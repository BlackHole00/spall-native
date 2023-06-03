package main

import "core:os"
import "core:fmt"
import "core:slice"
import "core:bytes"
import "core:time"
import "core:runtime"
import "core:path/filepath"

import "formats:spall"

FileType :: enum {
	Json,
	ManualStream,
	AutoStream,
}

Parser :: struct {
	pos: i64,
	offset: i64,
}
real_pos :: proc(p: ^Parser) -> i64 { return p.pos }
chunk_pos :: proc(p: ^Parser) -> i64 { return p.pos - p.offset }
get_chunk :: proc(p: ^Parser, fd: os.Handle, chunk_buffer: []u8) -> (int, bool) {
	rd_sz, err2 := os.read_at(fd, chunk_buffer, p.pos)
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
	in_free(&trace.intern)
	am_free(&trace.addr_map)
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

bound_duration :: proc(ev: ^Event, max_ts: i64) -> i64 {
	dur := unpack_ns(ev.duration)
	ts := unpack_ns(ev.timestamp)
	return dur < 0 ? (max_ts - ts) : dur
}

find_idx :: proc(trace: ^Trace, events: []Event, val: i64) -> int {
	low := 0
	max := len(events)
	high := max - 1

	for low < high {
		mid := (low + high) / 2

		ev := events[mid]
		ts := unpack_ns(ev.timestamp)
		dur := unpack_ns(ev.duration)

		ev_start := ts - trace.total_min_time
		ev_end := ev_start + dur

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

append_event :: proc(events: ^[dynamic]Event, ev: ^Event, loc := #caller_location) {
	if cap(events) < len(events)+1 {
		cap := 2 * cap(events) + max(8, 1)
		_ = reserve(events, cap, loc)
	}

	a := (^runtime.Raw_Dynamic_Array)(events)
	data := ([^]Event)(a.data)
	data[a.len] = ev^
	a.len += 1

	return
}

gen_event_color :: proc(trace: ^Trace, _events: []Event, thread_max: i64) -> (FVec3, i64) {
	total_weight : i64 = 0

	events := _events

	color := FVec3{}
	color_weights := [len(trace.color_choices)]i64{}
	for ev in &events {
		idx := name_color_idx(trace, ev.name)

		duration := bound_duration(&ev, thread_max)
		if duration <= 0 {
			//fmt.printf("weird duration: %d, %#v\n", duration, ev)
			duration = 1
		}
		color_weights[idx] += duration
		total_weight += duration
	}

	weights_sum : i64 = 0
	for weight, idx in color_weights {
		color += trace.color_choices[idx] * f32(weight)
		weights_sum += weight
	}
	if weights_sum <= 0 {
		fmt.printf("Invalid weights sum! events: %d, %d, %d\n", len(events), weights_sum, total_weight)
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
		cur_node := &tree[tree_idx]

		//padding := pad_buf[len(pad_buf) - stack_len:]
		fmt.printf("%d | %v\n", tree_idx, cur_node)

		if cur_node.tree_child_count == 0 {
			continue
		}

		for i := (cur_node.tree_child_count - 1); i >= 0; i -= 1 {
			tree_stack[stack_len] = cur_node.tree_start_idx + uint(i); stack_len += 1
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
					start_ts := unpack_ns(start_ev.timestamp)
					end_ts := unpack_ns(end_ev.timestamp)

					node := ChunkNode{}
					node.start_time = start_ts - trace.total_min_time
					node.end_time   = end_ts + bound_duration(&end_ev, tm.max_time) - trace.total_min_time

					node.event_start_idx = uint(start_idx)
					node.event_arr_len  = i8(len(scan_arr))

					node.tree_start_idx = 0
					node.tree_child_count = 0

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

						child_count := end_idx - start_idx
						start_node := tree[start_idx]
						end_node := tree[start_idx+(child_count - 1)]

						node := ChunkNode{}
						node.start_time = start_node.start_time
						node.end_time   = end_node.end_time

						node.event_start_idx  = start_node.event_start_idx
						node.event_arr_len    = 0

						node.tree_start_idx   = uint(start_idx)
						node.tree_child_count = i8(child_count)

						avg_color := FVec3{}
						for j := start_idx; j < start_idx + child_count; j += 1 {
							avg_color += tree[j].avg_color * f32(tree[j].weight)
							node.weight += tree[j].weight
						}
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

					ts := unpack_ns(ev.timestamp)
					start_time := ts - trace.total_min_time
					end_time := ts + bound_duration(&ev, tm.max_time) - trace.total_min_time

					child_time : i64 = 0
					tree_stack[0] = depth.head; stack_len += 1
					for stack_len > 0 {
						stack_len -= 1

						tree_idx := tree_stack[stack_len]
						cur_node := &tree[tree_idx]

						if end_time < cur_node.start_time || start_time > cur_node.end_time {
							continue
						}

						if cur_node.start_time >= start_time && cur_node.end_time <= end_time {
							child_time += cur_node.weight
							continue
						}

						if cur_node.tree_child_count == 0 {
							scan_arr := depth.events[cur_node.event_start_idx:cur_node.event_start_idx+uint(cur_node.event_arr_len)]
							weight : i64 = 0
							scan_loop: for scan_ev in &scan_arr {
								scan_ts := unpack_ns(scan_ev.timestamp)
								scan_ev_start_time := scan_ts - trace.total_min_time
								if scan_ev_start_time < start_time {
									continue
								}

								scan_ev_end_time := scan_ts + bound_duration(&scan_ev, tm.max_time) - trace.total_min_time
								if scan_ev_end_time > end_time {
									break scan_loop
								}

								weight += bound_duration(&scan_ev, tm.max_time)
							}
							child_time += weight
							continue
						}

						for i := cur_node.tree_child_count - 1; i >= 0; i -= 1 {
							tree_stack[stack_len] = cur_node.tree_start_idx + uint(i); stack_len += 1
						}
					}

					ev.self_time = bound_duration(&ev, tm.max_time) - child_time
				}
			}
		}
	}
}

pid_sort_proc :: proc(a, b: Process) -> bool { return a.min_time < b.min_time }
tid_sort_proc :: proc(a, b: Thread) -> bool  { return a.min_time < b.min_time }

load_executable :: proc(trace: ^Trace, file_name: string) -> bool {
	fmt.printf("Loading symbols from %s\n", file_name)

	exec_buffer, ok := os.read_entire_file_from_filename(file_name)
	if !ok {
		post_error(trace, "Failed to load %s!", file_name)
		return false
	}
	defer delete(exec_buffer)

	if len(exec_buffer) < 4 {
		post_error(trace, "Invalid executable file!")
		return false
	}

	magic_chunk := (^u32)(raw_data(exec_buffer[:4]))^
	if bytes.equal(exec_buffer[:4], ELF_MAGIC) {
		ok := load_elf(trace, exec_buffer)
		if !ok {
			post_error(trace, "Failed to parse ELF!")
			return false
		}
	} else if magic_chunk == MACH_MAGIC_64 {
		ok := load_macho(trace, exec_buffer)
		if !ok {
			post_error(trace, "Failed to parse Mach-O!")
			return false
		}
	} else if bytes.equal(exec_buffer[:2], DOS_MAGIC) {
		ok := load_pe32(trace, exec_buffer)
		if !ok {
			post_error(trace, "Failed to parse PE32!")
			return false
		}
	} else {
		post_error(trace, "Unsupported executable type! %x", exec_buffer[:4])
		return false
	}

	fmt.printf("Loaded %d symbols!\n", len(trace.addr_map.entries))

	return true
}

load_file :: proc(trace: ^Trace, file_name: string) {
	start_time := time.tick_now()

	trace^ = Trace{
		processes = make([dynamic]Process),
		selected_ranges = make([dynamic]Range),
		stats = sm_init(),
		process_map = vh_init(),
		total_max_time = min(i64),
		total_min_time = max(i64),
		event_count = 0,
		stamp_scale = 1,
		base_name = filepath.base(file_name),
		file_name = file_name,
		string_block = make([dynamic]u8),
		intern = in_init(),
		addr_map = am_init(),
		parser = Parser{},
		error_message = "",
	}
	// deliberately setting the first elem to 0, to simplify string interactions
	append_elem(&trace.string_block, 0)
	append_elem(&trace.string_block, 0)

	trace_fd, err := os.open(file_name)
	if err != 0 {
		post_error(trace, "%s not found!", file_name)
		return
	}
	defer os.close(trace_fd)

	total_size, err2 := os.file_size(trace_fd)
	if err2 != 0 {
		post_error(trace, "unable to get file size!")
		return
	}
	if total_size == 0 {
		post_error(trace, "%s is empty!", file_name)
		return
	}
	trace.total_size = total_size
	fmt.printf("Loading %s, %f MB\n", trace.base_name, f64(trace.total_size) / 1024 / 1024)

	header_buffer := [0x4000]u8{}
	rd_sz, err3 := os.read_at(trace_fd, header_buffer[:], 0)
	if err3 != 0 {
		post_error(trace, "Unable to read %s!", file_name)
		return
	}

	magic, ok := slice_to_type(header_buffer[:], u64)
	if !ok {
		post_error(trace, "File %s too small to be valid!", file_name)
		return
	}

	header_size : i64 = 0
	file_type: FileType
	if magic == spall.MANUAL_MAGIC {
		hdr, ok := slice_to_type(header_buffer[:], spall.Manual_Header)
		if !ok {
			post_error(trace, "%s is invalid!", file_name)
			return
		}

		if hdr.version != 1 {
			post_error(trace, "Spall version %d for %s is invalid!", hdr.version, file_name)
			return
		}
		
		trace.stamp_scale = hdr.timestamp_unit
		header_size = size_of(spall.Manual_Header)

		file_type = .ManualStream
	} else if magic == spall.AUTO_MAGIC {
		hdr, ok := slice_to_type(header_buffer[:], spall.Auto_Header)
		if !ok {
			post_error(trace, "%s is invalid!", file_name)
			return
		}

		if hdr.version != 1 {
			post_error(trace, "Spall version %d for %s is invalid!", hdr.version, file_name)
			return
		}
		if total_size < i64(size_of(spall.Auto_Header)) + i64(hdr.program_path_len) {
			post_error(trace, "%s is invalid!", file_name)
			return
		}
		
		trace.stamp_scale = hdr.timestamp_unit
		trace.skew_address = hdr.known_address

		symbol_path := string(header_buffer[size_of(spall.Auto_Header):][:hdr.program_path_len])

		header_size = size_of(spall.Auto_Header) + i64(hdr.program_path_len)
		if !load_executable(trace, symbol_path) {
			return
		}

		file_type = .AutoStream
	} else {
		file_type = .Json
	}

	p := &trace.parser
	p.pos += i64(header_size)

	parsed_properly := false
	#partial switch file_type {
	case .ManualStream:
		parsed_properly = ms_parse(trace, trace_fd, header_size)
	case .AutoStream:
		parsed_properly = as_parse(trace, trace_fd, header_size)
	case .Json:
		parsed_properly = json_parse(trace, trace_fd)
	}
	free_trace_temps(trace)
	if !parsed_properly {
		error_temp := trace.error_storage
		error_str_len := len(trace.error_message)

		free_trace(trace)

		trace^ = Trace{}
		trace.error_storage = error_temp
		trace.error_message = string(trace.error_storage[:error_str_len])
		return
	}

	#partial switch file_type {
	case .ManualStream: fallthrough
	case .AutoStream:
		for process in &trace.processes {
			slice.sort_by(process.threads[:], tid_sort_proc)
		}
		slice.sort_by(trace.processes[:], pid_sort_proc)
	case .Json:
		json_process_events(trace)
	}
	fmt.printf("parse config -- %f ms\n", time.duration_milliseconds(time.tick_since(start_time)))
	
	generate_color_choices(trace)

	start_time = time.tick_now()
	chunk_events(trace)
	fmt.printf("generate spatial partitions -- %f ms\n", time.duration_milliseconds(time.tick_since(start_time)))

	start_time = time.tick_now()
	if file_type == .Json {
		json_generate_selftimes(trace)
	}
	fmt.printf("generate selftimes -- %f ms\n", time.duration_milliseconds(time.tick_since(start_time)))
}
