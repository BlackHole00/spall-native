package main

import "core:fmt"
import "core:strings"
import "core:slice"
import "core:mem"
import "core:os"
import "core:math"
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

as_parse_next_event :: proc(trace: ^Trace, chunk: []u8, process: ^Process, thread: ^Thread, current_time: ^i64) -> BinaryState {
	p := &trace.parser

	min_sz := i64(size_of(u64))
	if chunk_pos(p) + min_sz > i64(len(chunk)) {
		return .PartialRead
	}

	data_start := raw_data(chunk[chunk_pos(p):])
	type := spall_fmt.Auto_Event_Type((^u8)(data_start)^)

    event_sz : i64
    ev : Event
    #partial switch type {
	case .MicroBegin_1:
		event_sz = i64(size_of(spall_fmt.MicroBegin_Event_1))
		if chunk_pos(p) + event_sz > i64(len(chunk)) {
			return .PartialRead
		}

		event := (^spall_fmt.MicroBegin_Event_1)(data_start)
        current_time^ = current_time^ + i64(u64(event.dt))
        //fmt.printf("B1 | dt: %d, time: %d\n", event.dt, current_time^)
		ev = Event{
			has_addr = true,
			id = event.address,
			duration = -1,
			timestamp = current_time^,
		}
	case .MicroBegin_2:
		event_sz = i64(size_of(spall_fmt.MicroBegin_Event_2))
		if chunk_pos(p) + event_sz > i64(len(chunk)) {
			return .PartialRead
		}

		event := (^spall_fmt.MicroBegin_Event_2)(data_start)
        current_time^ = current_time^ + i64(u64(event.dt))
        //fmt.printf("B2 | dt: %d, time: %d\n", event.dt, current_time^)
		ev = Event{
			has_addr = true,
			id = event.address,
			duration = -1,
			timestamp = current_time^,
		}
	case .MicroBegin_4:
		event_sz = i64(size_of(spall_fmt.MicroBegin_Event_4))
		if chunk_pos(p) + event_sz > i64(len(chunk)) {
			return .PartialRead
		}

		event := (^spall_fmt.MicroBegin_Event_4)(data_start)
        current_time^ = current_time^ + i64(u64(event.dt))
        //fmt.printf("B4 | dt: %d, time: %d\n", event.dt, current_time^)
		ev = Event{
			has_addr = true,
			id = event.address,
			duration = -1,
			timestamp = current_time^,
		}
	case .MicroBegin_8:
		event_sz = i64(size_of(spall_fmt.MicroBegin_Event_8))
		if chunk_pos(p) + event_sz > i64(len(chunk)) {
			return .PartialRead
		}

		event := (^spall_fmt.MicroBegin_Event_8)(data_start)
        current_time^ = current_time^ + i64(u64(event.dt))
        //fmt.printf("B8 | dt: %d, time: %d\n", event.dt, current_time^)
		ev = Event{
			has_addr = true,
			id = event.address,
			duration = -1,
			timestamp = current_time^,
		}
    case .MicroEnd_1:
		event_sz = i64(size_of(spall_fmt.MicroEnd_Event_1))
		if chunk_pos(p) + event_sz > i64(len(chunk)) {
			return .PartialRead
		}

		event := (^spall_fmt.MicroEnd_Event_1)(data_start)
        current_time^ = current_time^ + i64(u64(event.dt))
        //fmt.printf("E1 | dt: %d, time: %d\n", event.dt, current_time^)
    case .MicroEnd_2:
		event_sz = i64(size_of(spall_fmt.MicroEnd_Event_2))
		if chunk_pos(p) + event_sz > i64(len(chunk)) {
			return .PartialRead
		}

		event := (^spall_fmt.MicroEnd_Event_2)(data_start)
        current_time^ = current_time^ + i64(u64(event.dt))
        //fmt.printf("E2 | dt: %d, time: %d\n", event.dt, current_time^)
    case .MicroEnd_4:
		event_sz = i64(size_of(spall_fmt.MicroEnd_Event_4))
		if chunk_pos(p) + event_sz > i64(len(chunk)) {
			return .PartialRead
		}

		event := (^spall_fmt.MicroEnd_Event_4)(data_start)
        current_time^ = current_time^ + i64(u64(event.dt))
        //fmt.printf("E4 | dt: %d, time: %d\n", event.dt, current_time^)
    case .MicroEnd_8:
		event_sz = i64(size_of(spall_fmt.MicroEnd_Event_8))
		if chunk_pos(p) + event_sz > i64(len(chunk)) {
			return .PartialRead
		}

		event := (^spall_fmt.MicroEnd_Event_8)(data_start)
        current_time^ = current_time^ + i64(u64(event.dt))
        //fmt.printf("E8 | dt: %d, time: %d\n", event.dt, current_time^)
    }

	#partial switch type {
	case .MicroBegin_1: fallthrough
	case .MicroBegin_2: fallthrough
	case .MicroBegin_4: fallthrough
	case .MicroBegin_8:
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
	case .MicroEnd_1: fallthrough
	case .MicroEnd_2: fallthrough
	case .MicroEnd_4: fallthrough
	case .MicroEnd_8:
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
        current_time := i64(buffer_header.first_ts)
        //fmt.printf("starting new buffer for tid %d at %d\n", buffer_header.tid, current_time)
		ev_loop: for p.pos < buffer_end {
			state := as_parse_next_event(trace, full_chunk, process, thread, &current_time)

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
