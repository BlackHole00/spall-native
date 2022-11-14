package main

import "core:fmt"
import "core:strings"
import "core:slice"
import "core:mem"
import "core:os"
import "formats:spall"

BinaryState :: enum {
	PartialRead,
	EventRead,
	Failure,
}

get_next_event :: proc(trace: ^Trace, chunk: []u8, temp_ev: ^TempEvent) -> BinaryState {
	p := &trace.parser

	header_sz := i64(size_of(u64))
	if chunk_pos(p) + header_sz > i64(len(chunk)) {
		return .PartialRead
	}

	data_start := chunk[chunk_pos(p):]
	type := (^spall.Event_Type)(raw_data(data_start))^
	#partial switch type {
	case .Begin:
		event_sz := i64(size_of(spall.Begin_Event))
		if chunk_pos(p) + event_sz > i64(len(chunk)) {
			return .PartialRead
		}
		event := (^spall.Begin_Event)(raw_data(data_start))

		event_tail := i64(event.name_len) + i64(event.args_len)
		if (chunk_pos(p) + event_sz + event_tail) > i64(len(chunk)) {
			return .PartialRead
		}

		name := string(data_start[event_sz:event_sz+i64(event.name_len)])

		temp_ev.type = .Begin
		temp_ev.timestamp = event.time
		temp_ev.thread_id = event.tid
		temp_ev.process_id = event.pid
		temp_ev.name = in_get(&p.intern, &trace.string_block, name)

		p.pos += event_sz + event_tail
		return .EventRead
	case .End:
		event_sz := i64(size_of(spall.End_Event))
		if chunk_pos(p) + event_sz > i64(len(chunk)) {
			return .PartialRead
		}
		event := (^spall.End_Event)(raw_data(data_start))

		temp_ev.type = .End
		temp_ev.timestamp = event.time
		temp_ev.thread_id = event.tid
		temp_ev.process_id = event.pid
		
		p.pos += event_sz
		return .EventRead
	case:
		return .Failure
	}

	return .PartialRead
}

bin_push_event :: proc(trace: ^Trace, process_id, thread_id: u32, event: ^Event) -> (int, int, int) {
	p_idx := setup_pid(trace, process_id)
	t_idx := setup_tid(trace, p_idx, thread_id)

	p := &trace.processes[p_idx]
	p.min_time = min(p.min_time, event.timestamp)

	t := &p.threads[t_idx]
	t.min_time = min(t.min_time, event.timestamp)
	if t.max_time > event.timestamp {
		fmt.printf("Woah, time-travel? You just had a begin event that started before a previous one; [pid: %d, tid: %d, name: %s]\n", 
			process_id, thread_id, in_getstr(&trace.string_block, event.name))
		push_fatal(SpallError.InvalidFile)
	}
	t.max_time = event.timestamp + event.duration

	trace.total_min_time = min(trace.total_min_time, event.timestamp)
	trace.total_max_time = max(trace.total_max_time, event.timestamp + event.duration)

	if int(t.current_depth) >= len(t.depths) {
		depth := Depth{
			events = make([dynamic]Event)
		}
		append(&t.depths, depth)
	}

	depth := &t.depths[t.current_depth]
	t.current_depth += 1
	append(&depth.events, event^)

	return p_idx, t_idx, len(depth.events)-1
}

parse_binary :: proc(trace: ^Trace, fd: os.Handle, chunk_buffer: []u8, read_size: i64) {
	temp_ev := TempEvent{}
	ev := Event{}
	p := &trace.parser

	last_read: i64 = 0
	full_chunk := chunk_buffer[:read_size]
	load_loop: for p.pos < trace.total_size {
		mem.zero(&temp_ev, size_of(TempEvent))
		state := get_next_event(trace, full_chunk, &temp_ev)
		#partial switch state {
		case .PartialRead:
			if p.pos == last_read {
				fmt.printf("Invalid trailing data? dropping from [%d -> %d] (%d bytes)\n", p.pos, trace.total_size, trace.total_size - p.pos)
				break load_loop
			} else {
				last_read = p.pos
			}

			p.offset = p.pos

			rd_sz, ok := get_chunk(p, fd, chunk_buffer)
			if !ok {
				push_fatal(SpallError.FileFailure)
			}

			full_chunk = chunk_buffer[:rd_sz]
			continue
		case .Failure:
			push_fatal(SpallError.InvalidFile)
		}

		#partial switch temp_ev.type {
		case .Begin:
			ev.name = temp_ev.name
			ev.args = temp_ev.args
			ev.duration = -1
			ev.self_time = 0
			ev.timestamp = temp_ev.timestamp * trace.stamp_scale

			p_idx, t_idx, e_idx := bin_push_event(trace, temp_ev.process_id, temp_ev.thread_id, &ev)
			thread := &trace.processes[p_idx].threads[t_idx]
			stack_push_back(&thread.bande_q, EVData{idx = e_idx, depth = thread.current_depth - 1, self_time = 0})

			trace.event_count += 1
		case .End:
			p_idx, ok1 := vh_find(&trace.process_map, temp_ev.process_id)
			if !ok1 {
				continue
			}

			t_idx, ok2 := vh_find(&trace.processes[p_idx].thread_map, temp_ev.thread_id)
			if !ok2 {
				continue
			}

			thread := &trace.processes[p_idx].threads[t_idx]
			if thread.bande_q.len > 0 {
				jev_data := stack_pop_back(&thread.bande_q)
				thread.current_depth -= 1

				depth := &thread.depths[thread.current_depth]
				jev := &depth.events[jev_data.idx]
				jev.duration = (temp_ev.timestamp * trace.stamp_scale) - jev.timestamp
				jev.self_time = jev.duration - jev.self_time
				thread.max_time = max(thread.max_time, jev.timestamp + jev.duration)
				trace.total_max_time = max(trace.total_max_time, jev.timestamp + jev.duration)

				if thread.bande_q.len > 0 {
					parent_depth := &thread.depths[thread.current_depth - 1]
					parent_ev := stack_peek_back(&thread.bande_q)

					pev := &parent_depth.events[parent_ev.idx]

					pev.self_time += jev.duration
				}
			}
		}
	}

	// cleanup unfinished events
	for process in &trace.processes {
		for thread in &process.threads {
			for thread.bande_q.len > 0 {
				ev_data := stack_pop_back(&thread.bande_q)

				depth := &thread.depths[ev_data.depth]
				jev := &depth.events[ev_data.idx]

				thread.max_time = max(thread.max_time, jev.timestamp)
				trace.total_max_time = max(trace.total_max_time, jev.timestamp)

				duration := bound_duration(jev, thread.max_time)
				jev.self_time = duration - jev.self_time
				jev.self_time = max(jev.self_time, 0)

				if thread.bande_q.len > 0 {
					parent_depth := &thread.depths[ev_data.depth - 1]
					parent_ev := stack_peek_back(&thread.bande_q)

					pev := &parent_depth.events[parent_ev.idx]
					pev.self_time += duration
					pev.self_time = max(pev.self_time, 0)
				}
			}
		}
	}
}
