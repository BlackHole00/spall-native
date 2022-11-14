package main

import "core:os"
import "core:fmt"
import "core:slice"
import "core:time"
import "core:path/filepath"

import "formats:spall"

FileType :: enum {
	Json,
	SpallStream,
}

Parser :: struct {
	pos: i64,
	offset: i64,
	intern: INMap,
}
real_pos :: proc(p: ^Parser) -> i64 { return p.pos }
chunk_pos :: proc(p: ^Parser) -> i64 { return p.pos - p.offset }
init_parser :: proc() -> Parser {
	p := Parser{
		intern = in_init()
	}
	return p
}
free_parser :: proc(p: ^Parser) {
	in_free(&p.intern)
}
get_chunk :: proc(p: ^Parser, fd: os.Handle, chunk_buffer: []u8) -> (int, bool) {
	_, err := os.seek(fd, p.pos, os.SEEK_SET)
	if err != 0 {
		return 0, false
	}
	rd_sz, err2 := os.read(fd, chunk_buffer)
	if err2 != 0 {
		return 0, false
	}

	return rd_sz, true
}

setup_pid :: proc(trace: ^Trace, process_id: u32) -> int {
	p_idx, ok := vh_find(&trace.process_map, process_id)
	if !ok {
		append(&trace.processes, init_process(process_id))

		p_idx = len(trace.processes) - 1
		vh_insert(&trace.process_map, process_id, p_idx)
	}

	return p_idx
}

setup_tid :: proc(trace: ^Trace, p_idx: int, thread_id: u32) -> int {
	t_idx, ok := vh_find(&trace.processes[p_idx].thread_map, thread_id)
	if !ok {
		threads := &trace.processes[p_idx].threads
		thread_map := &trace.processes[p_idx].thread_map
		append(threads, init_thread(thread_id))

		t_idx = len(threads) - 1
		vh_insert(thread_map, thread_id, t_idx)
	}

	return t_idx
}

free_trace_temps :: proc(trace: ^Trace) {
	for process in &trace.processes {
		for thread in &process.threads {
			stack_free(&thread.bande_q)
		}
		vh_free(&process.thread_map)
	}
	vh_free(&trace.process_map)
	free_parser(&trace.parser)
}

free_trace :: proc(trace: ^Trace) {
	for process in &trace.processes {
		for thread in &process.threads {
			free_thread(&thread)
		}
		free_process(&process)
	}
	delete(trace.processes)
	delete(trace.string_block)
	delete(trace.file_name)
}

bound_duration :: proc(ev: $T, max_ts: f64) -> f64 {
	return ev.duration == -1 ? (max_ts - ev.timestamp) : ev.duration
}

find_idx :: proc(trace: ^Trace, events: []Event, val: f64) -> int {
	low := 0
	max := len(events)
	high := max - 1

	for low < high {
		mid := (low + high) / 2

		ev := events[mid]
		ev_start := ev.timestamp - trace.total_min_time
		ev_end := ev_start + ev.duration

		if (val >= ev_start && val <= ev_end) {
			return mid
		} else if ev_start < val && ev_end < val { 
			low = mid + 1
		} else { 
			high = mid - 1
		}
	}

	return low
}

gen_event_color :: proc(trace: ^Trace, events: []Event, thread_max: f64) -> (FVec3, f64) {
	total_weight : f64 = 0

	color := FVec3{}
	color_weights := [len(trace.color_choices)]f64{}
	for ev in events {
		idx := name_color_idx(trace, in_getstr(&trace.string_block, ev.name))

		duration := f64(bound_duration(ev, thread_max))
		if duration <= 0 {
			//fmt.printf("weird duration: %d, %#v\n", duration, ev)
			duration = 0.1
		}
		color_weights[idx] += duration
		total_weight += duration
	}

	weights_sum : f64 = 0
	for weight, idx in color_weights {
		color += trace.color_choices[idx] * f32(weight)
		weights_sum += weight
	}
	if weights_sum <= 0 {
		fmt.printf("Invalid weights sum! events: %d, %f, %f\n", len(events), weights_sum, total_weight)
		push_fatal(SpallError.Bug)
	}
	color /= f32(weights_sum)

	return color, total_weight
}

print_tree :: proc(tree: []ChunkNode, head: uint) {
	fmt.printf("mah tree!\n")
	// If we blow this, we're in space
	tree_stack := [128]uint{}
	stack_len := 0
	pad_buf := [?]u8{0..<64 = '\t',}

	tree_stack[0] = head; stack_len += 1
	for stack_len > 0 {
		stack_len -= 1

		tree_idx := tree_stack[stack_len]
		cur_node := tree[tree_idx]

		//padding := pad_buf[len(pad_buf) - stack_len:]
		fmt.printf("%d | %v\n", tree_idx, cur_node)

		if cur_node.child_count == 0 {
			continue
		}

		for i := (cur_node.child_count - 1); i >= 0; i -= 1 {
			tree_stack[stack_len] = cur_node.children[i]; stack_len += 1
		}
	}
	fmt.printf("ded!\n")
}

chunk_events :: proc(trace: ^Trace) {
	for proc_v, p_idx in &trace.processes {
		for tm, t_idx in &proc_v.threads {
			for depth, d_idx in &tm.depths {
				bucket_count := i_round_up(len(depth.events), BUCKET_SIZE) / BUCKET_SIZE

				// precompute element count for tree
				max_nodes := bucket_count
				{
					row_count := bucket_count
					parent_row_count := (row_count + (CHUNK_NARY_WIDTH - 1)) / CHUNK_NARY_WIDTH
					for row_count > 1 {
						tmp := (row_count + (CHUNK_NARY_WIDTH - 1)) / CHUNK_NARY_WIDTH
						max_nodes += tmp
						row_count = parent_row_count
						parent_row_count = tmp
					}
				}

				tm.depths[d_idx].tree = make([dynamic]ChunkNode, 0, max_nodes)
				tree := &tm.depths[d_idx].tree

				for i := 0; i < bucket_count; i += 1 {
					start_idx := i * BUCKET_SIZE
					end_idx := start_idx + min(len(depth.events) - start_idx, BUCKET_SIZE)
					scan_arr := depth.events[start_idx:end_idx]

					start_ev := scan_arr[0]
					end_ev := scan_arr[len(scan_arr)-1]

					node := ChunkNode{}
					node.start_time = start_ev.timestamp - trace.total_min_time
					node.end_time   = end_ev.timestamp + bound_duration(end_ev, tm.max_time) - trace.total_min_time
					node.start_idx  = uint(start_idx)
					node.end_idx    = uint(end_idx)
					node.arr_len = i8(len(scan_arr))

					avg_color, weight := gen_event_color(trace, scan_arr, tm.max_time)
					node.avg_color = avg_color
					node.weight = weight

					append(tree, node)
				}

				tree_start_idx := 0
				tree_end_idx := len(tree)

				row_count := len(tree)
				parent_row_count := (row_count + (CHUNK_NARY_WIDTH - 1)) / CHUNK_NARY_WIDTH
				for row_count > 1 {
					for i := 0; i < parent_row_count; i += 1 {
						start_idx := tree_start_idx + (i * CHUNK_NARY_WIDTH)
						end_idx := start_idx + min(tree_end_idx - start_idx, CHUNK_NARY_WIDTH)

						children := tree[start_idx:end_idx]

						start_node := children[0]
						end_node := children[len(children)-1]

						node := ChunkNode{}
						node.start_time = start_node.start_time
						node.end_time   = end_node.end_time
						node.start_idx  = start_node.start_idx
						node.end_idx    = end_node.end_idx

						avg_color := FVec3{}
						for j := 0; j < len(children); j += 1 {
							node.children[j] = uint(start_idx + j)
							avg_color += children[j].avg_color * f32(children[j].weight)
							node.weight += children[j].weight
						}
						node.child_count = i8(len(children))
						node.avg_color = avg_color / f32(node.weight)

						append(tree, node)
					}

					tree_start_idx = tree_end_idx
					tree_end_idx = len(tree)
					row_count = tree_end_idx - tree_start_idx
					parent_row_count = (row_count + (CHUNK_NARY_WIDTH - 1)) / CHUNK_NARY_WIDTH
				}

				depth.head = len(tree) - 1
			}
		}
	}
}

generate_selftimes :: proc(trace: ^Trace) {
	for proc_v, p_idx in &trace.processes {
		for tm, t_idx in &proc_v.threads {

			// skip the bottom rank, it's already set up correctly
			if len(tm.depths) == 1 {
				continue
			}

			for depth, d_idx in &tm.depths {
				// skip the last depth
				if d_idx == (len(tm.depths) - 1) {
					continue
				}

				for ev, e_idx in &depth.events {
					depth := tm.depths[d_idx+1]
					tree := depth.tree

					tree_stack := [128]uint{}
					stack_len := 0

					start_time := ev.timestamp - trace.total_min_time
					end_time := ev.timestamp + bound_duration(ev, tm.max_time) - trace.total_min_time

					child_time := 0.0
					tree_stack[0] = depth.head; stack_len += 1
					for stack_len > 0 {
						stack_len -= 1

						tree_idx := tree_stack[stack_len]
						cur_node := tree[tree_idx]

						if end_time < cur_node.start_time || start_time > cur_node.end_time {
							continue
						}

						if cur_node.start_time >= start_time && cur_node.end_time <= end_time {
							child_time += cur_node.weight
							continue
						}

						if cur_node.child_count == 0 {
							scan_arr := depth.events[cur_node.start_idx:cur_node.start_idx+uint(cur_node.arr_len)]
							weight := 0.0
							scan_loop: for scan_ev in scan_arr {
								scan_ev_start_time := scan_ev.timestamp - trace.total_min_time
								if scan_ev_start_time < start_time {
									continue
								}

								scan_ev_end_time := scan_ev.timestamp + bound_duration(scan_ev, tm.max_time) - trace.total_min_time
								if scan_ev_end_time > end_time {
									break scan_loop
								}

								weight += bound_duration(scan_ev, tm.max_time)
							}
							child_time += weight
							continue
						}

						for i := cur_node.child_count - 1; i >= 0; i -= 1 {
							tree_stack[stack_len] = cur_node.children[i]; stack_len += 1
						}
					}

					ev.self_time = bound_duration(ev, tm.max_time) - child_time
				}
			}
		}
	}
}

pid_sort_proc :: proc(a, b: Process) -> bool { return a.min_time < b.min_time }
tid_sort_proc :: proc(a, b: Thread) -> bool  { return a.min_time < b.min_time }
load_file :: proc(trace: ^Trace, file_name: string) {
	start_time := time.tick_now()

	trace_fd, err := os.open(file_name)
	if err != 0 {
		push_fatal(SpallError.InvalidFile)
	}
	defer os.close(trace_fd)

	chunk_buffer := make([]u8, 1 * 1024 * 1024)
	defer delete(chunk_buffer)

	trace^ = Trace{
		processes = make([dynamic]Process),
		selected_ranges = make([dynamic]Range),
		stats = make(map[string]Stats),
		process_map = vh_init(),
		total_max_time = 0,
		total_min_time = 0x7fefffffffffffff,
		event_count = 0,
		stamp_scale = 1,
		base_name = filepath.base(file_name),
		file_name = file_name,
		string_block = make([dynamic]u8),
		parser = init_parser(),
	}

	total_size, err2 := os.file_size(trace_fd)
	if err2 != 0 {
		push_fatal(SpallError.InvalidFile)
	}

	rd_sz, err3 := os.read(trace_fd, chunk_buffer)
	if err3 != 0 {
		push_fatal(SpallError.InvalidFile)
	}
	trace.total_size = total_size

	// parse header
	full_chunk := chunk_buffer[:rd_sz]

	header_sz := i64(size_of(spall.Header))
	if i64(len(full_chunk)) < header_sz {
		push_fatal(SpallError.InvalidFile)
	}

	file_type: FileType
	magic := (^u64)(raw_data(full_chunk))^
	if magic == spall.MAGIC {
		hdr := cast(^spall.Header)raw_data(full_chunk)
		if hdr.version != 1 {
			push_fatal(SpallError.InvalidFileVersion)
		}
		
		trace.stamp_scale = hdr.timestamp_unit

		p := &trace.parser
		p.pos += header_sz

		file_type = .SpallStream
	} else {
		file_type = .Json
	}

	#partial switch file_type {
	case .SpallStream:
		parse_binary(trace, trace_fd, chunk_buffer, i64(rd_sz))
	case .Json:
		parse_json(trace, trace_fd, chunk_buffer)
	}
	free_trace_temps(trace)

	#partial switch file_type {
	case .SpallStream:
		for process in &trace.processes {
			slice.sort_by(process.threads[:], tid_sort_proc)
		}
		slice.sort_by(trace.processes[:], pid_sort_proc)
	case .Json:
		json_process_events(trace)
	}

	duration := time.tick_since(start_time)
	fmt.printf("parse config -- %f ms\n", time.duration_milliseconds(duration))
	
	generate_color_choices(trace)

	start_time = time.tick_now()
	chunk_events(trace)
	duration = time.tick_since(start_time)
	fmt.printf("generate spatial partitions -- %f ms\n", time.duration_milliseconds(duration))

	if file_type == .Json {
		json_generate_selftimes(trace)
	}
}
