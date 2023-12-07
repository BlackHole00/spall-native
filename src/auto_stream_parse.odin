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

DtState :: struct {
	current_time:   i64,
	current_addr:   u64,
	current_caller: u64,
}

as_parse_next_event :: proc(trace: ^Trace, chunk: []u8, process: ^Process, thread: ^Thread, state: ^DtState) -> BinaryState {
	p := &trace.parser

	min_sz := i64(size_of(u16))
	if chunk_pos(p) + min_sz > i64(len(chunk)) {
		return .PartialRead
	}

    data_start := chunk[chunk_pos(p):]
    type_byte := ((^u8)(raw_data(data_start))^)
    type_tag := type_byte >> 6

    switch type_tag {
        case 0: // MicroBegin
            dt_size     := i64(1 << (((0b00_11_00_00 & type_byte) >> 4) & 63))
            addr_size   := i64(1 << (((0b00_00_11_00 & type_byte) >> 2) & 63))
            caller_size := i64(1 << ((0b00_00_00_11 & type_byte) & 63))
            event_sz := 1 + dt_size + addr_size + caller_size
            if chunk_pos(p) + event_sz > i64(len(chunk)) {
                return .PartialRead
            }

			i : i64 = 1
            dt       := pull_uval(chunk[chunk_pos(p)+i:], int(dt_size));     i += dt_size
            d_addr   := pull_uval(chunk[chunk_pos(p)+i:], int(addr_size));   i += addr_size
            d_caller := pull_uval(chunk[chunk_pos(p)+i:], int(caller_size)); i += caller_size

            state.current_time   += i64(dt)
            state.current_addr   ~= d_addr
            state.current_caller ~= d_caller

            id := state.current_addr
            caller := state.current_caller
            timestamp := state.current_time

            if thread.max_time > timestamp {
                post_error(trace, 
                    "Woah, time-travel? You just had a begin event that started before a previous one; [pid: %d, tid: %d, addr: 0x%x, event_count: %d]", 
                    0, thread.id, id, trace.event_count)
                return .Failure
            }
            thread.max_time  = timestamp

            if thread.current_depth >= len(thread.depths) {
                depth := Depth{
					nodes  = make([dynamic]LODInternal),
					leaves = make([dynamic]LODLeaf),
                    events = make([dynamic]u8),
                }
                non_zero_append(&thread.depths, depth)
            }

            depth := &thread.depths[thread.current_depth]
            thread.current_depth += 1

			add_event(depth, true, timestamp, id, caller)
            trace.event_count += 1

            p.pos += event_sz
            return .EventRead
        case 2: // Other Events
            type := spall_fmt.Auto_Event_Type((0b00_11_00_00 & type_byte) >> 4)
            #partial switch type {
            case .Begin:
                dt_size   := i64(1 << (((0b00_00_11_00 & type_byte) >> 2) & 63))
                name_size := i64(1 << (((0b00_00_00_10 & type_byte) >> 1) & 63))
                arg_size  := i64(1 << ((0b00_00_00_01 & type_byte) & 63))

                min_event_sz := 1 + dt_size + name_size + arg_size
                if chunk_pos(p) + min_event_sz > i64(len(chunk)) {
                    return .PartialRead
                }
                
                i : i64 = 1
                dt       := pull_uval(chunk[chunk_pos(p)+i:], int(dt_size));   i += dt_size
                name_len := pull_uval(chunk[chunk_pos(p)+i:], int(name_size)); i += name_size
                args_len := pull_uval(chunk[chunk_pos(p)+i:], int(arg_size));  i += arg_size

                event_tail := i64(name_len) + i64(args_len)
                if (chunk_pos(p) + min_event_sz + event_tail) > i64(len(chunk)) {
                    return .PartialRead
                }

                name_str := string(data_start[i:i+i64(name_len)]); i += i64(name_len)
                args_str := string(data_start[i:i+i64(args_len)]); i += i64(args_len)
                id   := in_get(&trace.intern, &trace.string_block, name_str)
                args := in_get(&trace.intern, &trace.string_block, args_str)

                state.current_time += i64(dt)
                timestamp := state.current_time

                if thread.max_time > timestamp {
                    post_error(trace, 
                        "Woah, time-travel? You just had a begin event that started before a previous one; [pid: %d, tid: %d, name: %s, event_count: %d]", 
                        0, thread.id, name_str, trace.event_count)
                    return .Failure
                }
                thread.max_time = timestamp

                if thread.current_depth >= len(thread.depths) {
                    depth := Depth{
						nodes  = make([dynamic]LODInternal),
						leaves = make([dynamic]LODLeaf),
						events = make([dynamic]u8),
                    }
                    non_zero_append(&thread.depths, depth)
                }

                depth := &thread.depths[thread.current_depth]
                thread.current_depth += 1
				add_event(depth, true, timestamp, id, args)

                trace.event_count += 1

                p.pos += i
                return .EventRead
            }
        case 1: // MicroEnd
            dt_size := i64(1 << (((0b00_11_00_00 & type_byte) >> 4) & 63))
            event_sz := 1 + dt_size
            if chunk_pos(p) + event_sz > i64(len(chunk)) {
                return .PartialRead
            }

			i : i64 = 1
            dt := pull_uval(chunk[chunk_pos(p)+i:], int(dt_size)); i += dt_size

            ts := state.current_time + i64(dt)
			if thread.current_depth > 0 {
                thread.current_depth -= 1
                depth := &thread.depths[thread.current_depth]
				duration := update_event(depth, ts)

				end_time := depth.last_ts + depth.last_duration
                thread.max_time = end_time

                if thread.current_depth > 0 {
                    parent_depth  := &thread.depths[thread.current_depth - 1]
					parent_depth.accum_selftime += duration
                }
            }
            
            state.current_time = ts
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

	chunk_buffer := make([]u8, 2 * 1024 * 1024)
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

        dt_state := DtState{
			current_time   = i64(buffer_header.first_ts),
			current_addr   = 0,
			current_caller = 0,
		}
		ev_loop: for p.pos < buffer_end {
			state := as_parse_next_event(trace, full_chunk, process, thread, &dt_state)

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
	/*
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
	*/

	event_mem : i64 = 0
	overhead_mem : i64 = 0
	for process in &trace.processes {
		for thread in &process.threads {
			for depth in thread.depths {
				event_mem += depth.event_cursor
				overhead_mem += size_of(Depth)
			}
			overhead_mem += size_of(Thread)
		}
		overhead_mem += size_of(Process)
	}
	fmt.printf("used %v MB for events!\n", f64(event_mem) / 1024 / 1024)
	fmt.printf("used %v MB for org overhead!\n", f64(overhead_mem) / 1024 / 1024)
	fmt.printf("Loaded %s events!\n", tens_fmt(trace.event_count))
	fmt.printf("Average Event Size: %v bytes\n", f64(event_mem) / f64(trace.event_count))

	if true { os.exit(0) }
	return true
}
