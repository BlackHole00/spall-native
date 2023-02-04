package main

import "core:fmt"
import "core:strings"
import "core:slice"
import "core:mem"
import "core:os"
import "core:strconv"
import "core:math"
import "formats:spall"

as_get_next_buffer :: proc(trace: ^Trace, chunk: []u8, buffer_header: ^spall.BufferHeader) -> BinaryState {
	p := &trace.parser

	if chunk_pos(p) + size_of(spall.BufferHeader) > i64(len(chunk)) {
		return .PartialRead
	}

	data_start := chunk[chunk_pos(p):]
	tmp_header := (^spall.BufferHeader)(raw_data(data_start))^
	buffer_header^ = tmp_header

	p.pos += size_of(spall.BufferHeader)
	return .EventRead
}

as_parse_next_event :: proc(trace: ^Trace, chunk: []u8, process: ^Process, thread: ^Thread) -> BinaryState {
	p := &trace.parser

	min_sz := i64(size_of(u64))
	if chunk_pos(p) + min_sz > i64(len(chunk)) {
		return .PartialRead
	}

	data_start := chunk[chunk_pos(p):]
	first_lump := (^u64)(raw_data(data_start))^
	type := spall.Auto_Event_Type(first_lump >> 56)
	#partial switch type {
	case .MicroBegin:
		event_sz := i64(size_of(spall.MicroBegin_Event))
		if chunk_pos(p) + event_sz > i64(len(chunk)) {
			return .PartialRead
		}

		event := (^spall.MicroBegin_Event)(raw_data(data_start))
		raw_time := (event.time_and_type << 8) >> 8

		name, ok := am_find(&trace.addr_map, event.address)
		if !ok {
			tmp_buf := [34]byte{}
			tmp_buf[0] = '0'
			tmp_buf[1] = 'x'
			name_str := strconv.append_uint(tmp_buf[2:], event.address, 16)
			name = in_get(&trace.intern, &trace.string_block, string(tmp_buf[:len(name_str)+2]))
		}

		timestamp := i64(math.ceil(f64(raw_time) * trace.stamp_scale))
		ev := Event{
			name = name,
			duration = -1,
			timestamp = timestamp,
		}

		if thread.max_time > ev.timestamp {
			post_error(trace, 
				"Woah, time-travel? You just had a begin event that started before a previous one; [pid: %d, tid: %d, name: %s, event: %v, event_count: %d]", 
				0, thread.id, in_getstr(&trace.string_block, ev.name), ev, trace.event_count)
			return .Failure
		}

		process.min_time = min(process.min_time, ev.timestamp)
		thread.min_time = min(thread.min_time, ev.timestamp)
		thread.max_time = ev.timestamp + ev.duration

		trace.total_min_time = min(trace.total_min_time, ev.timestamp)
		trace.total_max_time = max(trace.total_max_time, ev.timestamp + ev.duration)

		if int(thread.current_depth) >= len(thread.depths) {
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
	case .MicroEnd:
		event_sz := i64(size_of(spall.MicroEnd_Event))
		if chunk_pos(p) + event_sz > i64(len(chunk)) {
			return .PartialRead
		}

		event := (^spall.MicroEnd_Event)(raw_data(data_start))
		raw_time := (event.time_and_type << 8) >> 8

		timestamp := i64(math.ceil(f64(raw_time) * trace.stamp_scale))
		if thread.bande_q.len > 0 {
			jev_idx := stack_pop_back(&thread.bande_q)
			thread.current_depth -= 1

			depth := &thread.depths[thread.current_depth]
			jev := &depth.events[jev_idx]
			jev.duration = timestamp - jev.timestamp
			jev.self_time = jev.duration - jev.self_time
			thread.max_time = max(thread.max_time, jev.timestamp + jev.duration)
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


as_parse :: proc(trace: ^Trace, fd: os.Handle, chunk_buffer: []u8, read_size: i64) -> bool {
	buffer_header := spall.BufferHeader{}
	p := &trace.parser

	proc_idx := setup_pid(trace, 0)
	process := &trace.processes[proc_idx]

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
		ev_loop: for p.pos < buffer_end {
			state := as_parse_next_event(trace, full_chunk, process, thread)

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
			assert(u16(thread.bande_q.len) == thread.current_depth)
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
