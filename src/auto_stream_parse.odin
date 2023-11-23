package main

import "core:fmt"
import "core:strings"
import "core:slice"
import "core:mem"
import "core:os"
import "core:math"
import "core:intrinsics"
import "formats:spall_fmt"

as_get_next_buffer :: proc(trace: ^Trace, chunk: []u8, buffer_header: ^spall_fmt.Buffer_Header) -> BinaryState {
	p := &trace.parser

	if chunk_pos(p) + size_of(spall_fmt.Buffer_Header) > i64(len(chunk)) {
		return .PartialRead
	}

	data_start := chunk[chunk_pos(p):]
	tmp_header := (^spall_fmt.Buffer_Header)(raw_data(data_start))^
	buffer_header^ = tmp_header

	p.pos += size_of(spall_fmt.Buffer_Header)
	return .EventRead
}

pull_uval :: proc(buffer: []u8, size: int) -> u64 {
    switch size {
    case 1:
        return u64(intrinsics.unaligned_load((^u8)(raw_data(buffer))))
    case 2:
        return u64(intrinsics.unaligned_load((^u16)(raw_data(buffer))))
    case 4:
        return u64(intrinsics.unaligned_load((^u32)(raw_data(buffer))))
    case 8:
        return u64(intrinsics.unaligned_load((^u64)(raw_data(buffer))))
    }
    return 0
}

pull_ival :: proc(buffer: []u8, size: int) -> i64 {
    switch size {
    case 1:
        return i64(intrinsics.unaligned_load((^i8)(raw_data(buffer))))
    case 2:
        return i64(intrinsics.unaligned_load((^i16)(raw_data(buffer))))
    case 4:
        return i64(intrinsics.unaligned_load((^i32)(raw_data(buffer))))
    case 8:
        return i64(intrinsics.unaligned_load((^i64)(raw_data(buffer))))
    }
    return 0
}

as_parse_next_event :: proc(trace: ^Trace, chunk: []u8, process: ^Process, thread: ^Thread, current_time: ^i64, current_addr: ^u64, current_caller: ^u64) -> BinaryState {
	p := &trace.parser

	min_sz := i64(size_of(u16))
	if chunk_pos(p) + min_sz > i64(len(chunk)) {
		return .PartialRead
	}

	data_start := raw_data(chunk[chunk_pos(p):])
	type_byte := ((^u8)(data_start)^)
    type_tag := type_byte >> 6

    i : i64 = 1
    switch type_tag {
        case 1: // Begin
            dt_size     := i64(1 << ((0b00_11_00_00 & type_byte) >> 4))
            addr_size   := i64(1 << ((0b00_00_11_00 & type_byte) >> 2))
            caller_size := i64(1 <<  (0b00_00_00_11 & type_byte))
            event_sz := 1 + dt_size + addr_size + caller_size
            if chunk_pos(p) + event_sz > i64(len(chunk)) {
                return .PartialRead
            }

            dt       := pull_uval(chunk[chunk_pos(p)+i:], int(dt_size));     i += dt_size
            d_addr   := pull_ival(chunk[chunk_pos(p)+i:], int(addr_size));   i += addr_size
            d_caller := pull_ival(chunk[chunk_pos(p)+i:], int(caller_size)); i += caller_size

            current_time^ = current_time^ + i64(dt)
            current_addr^ = current_addr^ + u64(d_addr)
            //fmt.printf("addr: %x, delta: %d, size: %d\n", current_addr^, d_addr, addr_size)
            ev := Event{
                has_addr = true,
                id = current_addr^,
                duration = -1,
                timestamp = current_time^,
            }

            if thread.max_time > ev.timestamp {
                post_error(trace, 
                    "Woah, time-travel? You just had a begin event that started before a previous one; [pid: %d, tid: %d, addr: 0x%x, event: %v, event_count: %d]", 
                    0, thread.id, ev.id, ev, trace.event_count)
                return .Failure
            }

            process.min_time = min(process.min_time, ev.timestamp)
            thread.min_time  = min(thread.min_time, ev.timestamp)
            thread.max_time  = ev.timestamp

            trace.total_min_time = min(trace.total_min_time, ev.timestamp)
            trace.total_max_time = max(trace.total_max_time, ev.timestamp)

            if thread.current_depth >= len(thread.depths) {
                depth := Depth{
                    events = make([dynamic]Event),
                }
                append(&thread.depths, depth)
            }

            depth := &thread.depths[thread.current_depth]
            thread.current_depth += 1
            append_event(&depth.events, &ev)

            ev_idx := len(depth.events)-1
            stack_push_back(&thread.bande_q, ev_idx)
            trace.event_count += 1

            p.pos += event_sz
            return .EventRead
        case 2: // End
            dt_size := i64(1 << ((0b00_11_00_00 & type_byte) >> 4))
            event_sz := 1 + dt_size
            if chunk_pos(p) + event_sz > i64(len(chunk)) {
                return .PartialRead
            }

            dt := pull_uval(chunk[chunk_pos(p)+i:], int(dt_size)); i += dt_size
            //fmt.printf("E | dt: %d\n", dt)

            current_time^ = current_time^ + i64(dt)
            if thread.bande_q.len > 0 {
                jev_idx := stack_pop_back(&thread.bande_q)
                thread.current_depth -= 1

                depth := &thread.depths[thread.current_depth]
                jev := &depth.events[jev_idx]
                jev.duration = current_time^ - jev.timestamp
                jev.self_time = jev.duration - jev.self_time

                thread.max_time      = max(thread.max_time, jev.timestamp + jev.duration)
                trace.total_max_time = max(trace.total_max_time, jev.timestamp + jev.duration)

                if thread.bande_q.len > 0 {
                    parent_depth := &thread.depths[thread.current_depth - 1]
                    parent_ev_idx := stack_peek_back(&thread.bande_q)

                    pev := &parent_depth.events[parent_ev_idx]
                    pev.self_time += jev.duration
                }
            }
            
            p.pos += event_sz
            return .EventRead
        case:
            post_error(trace, "Invalid event type: %d in file!", data_start[0])
            return .Failure
    }

	return .PartialRead
}


as_parse :: proc(trace: ^Trace, fd: os.Handle, header_size: i64) -> bool {
	buffer_header := spall_fmt.Buffer_Header{}
	p := &trace.parser

	proc_idx := setup_pid(trace, 0)
	process := &trace.processes[proc_idx]

	chunk_buffer := make([]u8, 4 * 1024 * 1024)
	defer delete(chunk_buffer)

	read_size, err := os.read_at(fd, chunk_buffer, 0)
	if err != 0 {
		post_error(trace, "Unable to read file!")
		return false
	}

	last_read: i64 = 0
	full_chunk := chunk_buffer[:read_size]
	buffer_loop: for p.pos < trace.total_size {
		state := as_get_next_buffer(trace, full_chunk, &buffer_header)
		#partial switch state {
		case .PartialRead:
			if p.pos == last_read {
				fmt.printf("Invalid trailing data? dropping from [%d -> %d] (%d bytes)\n", p.pos, trace.total_size, trace.total_size - p.pos)
				break buffer_loop
			} else {
				last_read = p.pos
			}

			p.offset = p.pos

			rd_sz, ok := get_chunk(p, fd, chunk_buffer)
			if !ok {
				post_error(trace, "Failed to read file!")
				return false
			}

			full_chunk = chunk_buffer[:rd_sz]
			continue buffer_loop
		case .Failure:
			return false
		}

		thread_idx := setup_tid(trace, proc_idx, buffer_header.tid)
		thread := &process.threads[thread_idx]

		buffer_end := p.pos + i64(buffer_header.size)

        current_time   := i64(buffer_header.first_ts)
        current_addr   := u64(0)
        current_caller := u64(0)
        //fmt.printf("starting new buffer for tid %d at %d\n", buffer_header.tid, current_time)
		ev_loop: for p.pos < buffer_end {
			state := as_parse_next_event(trace, full_chunk, process, thread, &current_time, &current_addr, &current_caller)

			#partial switch state {
			case .PartialRead:
				if p.pos == last_read {
					fmt.printf("Invalid trailing data? dropping from [%d -> %d] (%d bytes)\n", p.pos, trace.total_size, trace.total_size - p.pos)
					break buffer_loop
				} else {
					last_read = p.pos
				}

				p.offset = p.pos

				rd_sz, ok := get_chunk(p, fd, chunk_buffer)
				if !ok {
					post_error(trace, "Failed to read file!")
					return false
				}

				full_chunk = chunk_buffer[:rd_sz]
				continue ev_loop
			case .Failure:
				return false
			}
		}
	}

	// cleanup unfinished events
	for process in &trace.processes {
		for thread in &process.threads {
			assert(thread.bande_q.len == thread.current_depth)
			for thread.current_depth > 0 {
				jev_idx := stack_pop_back(&thread.bande_q)
				thread.current_depth -= 1
				ev_depth := thread.current_depth

				depth := &thread.depths[ev_depth]
				jev := &depth.events[jev_idx]

				thread.max_time = max(thread.max_time, jev.timestamp)
				trace.total_max_time = max(trace.total_max_time, jev.timestamp)

				duration := bound_duration(jev, thread.max_time)
				jev.self_time = duration - jev.self_time
				jev.self_time = max(jev.self_time, 0)

				if thread.current_depth > 0 {
					parent_depth := &thread.depths[ev_depth - 1]
					parent_ev_idx := stack_peek_back(&thread.bande_q)

					pev := &parent_depth.events[parent_ev_idx]
					pev.self_time += duration
					pev.self_time = max(pev.self_time, 0)
				}
			}
		}
	}

	return true
}
