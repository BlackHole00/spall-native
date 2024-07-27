package main

import "base:runtime"

import "core:os"
import "core:fmt"
import "core:slice"
import "core:bytes"
import "core:time"
import "core:path/filepath"
import "core:mem"
import "core:strings"

import "formats:spall_fmt"

FileType :: enum {
	Invalid,
	Json,
	ManualStreamV1,
	ManualStreamV2,
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
		non_zero_append(&trace.processes, init_process(process_id))

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
		non_zero_append(threads, init_thread(thread_id))

		t_idx = len(threads) - 1
		vh_insert(thread_map, thread_id, t_idx)
	}

	return t_idx
}

free_trace_temps :: proc(trace: ^Trace) {
	for &process in trace.processes {
		for &thread in process.threads {
			stack_free(&thread.bande_q)
		}
		vh_free(&process.thread_map)
	}
	vh_free(&trace.process_map)
}

free_trace :: proc(trace: ^Trace) {
	for &process in trace.processes {
		for &thread in process.threads {
			free_thread(&thread)
		}
		free_process(&process)
	}
	delete(trace.processes)
	delete(trace.string_block)
	delete(trace.file_name)
	strings.intern_destroy(&trace.filename_map)
	delete(trace.line_info)

	delete(trace.stats.selected_ranges)
	sm_free(&trace.stats.stat_map)
	in_free(&trace.intern)
	am_free(&trace.addr_map)
}

bound_duration :: proc(ev: ^Event, max_ts: i64) -> i64 {
	return ev.duration < 0 ? (max_ts - ev.timestamp) : ev.duration
}

find_idx :: proc(trace: ^Trace, events: []Event, val: i64) -> int {
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

add_event :: proc(events: ^[dynamic]Event, loc := #caller_location) -> ^Event {
	if cap(events) < len(events)+1 {
		cap := 3 * cap(events) + max(8, 1)
		_ = non_zero_reserve(events, cap, loc)
	}

	a := (^runtime.Raw_Dynamic_Array)(events)
	data := ([^]Event)(a.data)
	ev := &data[a.len]
	a.len += 1

	return ev
}

append_event :: proc(events: ^[dynamic]Event, ev: ^Event, loc := #caller_location) {
	if cap(events) < len(events)+1 {
		cap := 2 * cap(events) + max(8, 1)
		_ = non_zero_reserve(events, cap, loc)
	}

	a := (^runtime.Raw_Dynamic_Array)(events)
	data := ([^]Event)(a.data)
	data[a.len] = ev^
	a.len += 1

	return
}

gen_event_color :: proc(trace: ^Trace, _events: []Event, thread_max: i64, node: ^ChunkNode) {
	total_weight : i64 = 0

	events := _events

	if len(events) == 1 {
		ev := &events[0]
		duration := bound_duration(ev, thread_max)
		idx := name_color_idx(ev.id)
		node.avg_color = trace.color_choices[idx]

		// if the event was started with no end, *right* as the trace quit, we'll get a duration of 0
		// make this 1 so it has *some* LOD contribution
		node.weight = max(duration, 1)
		return
	}

	color := FVec3{}
	color_weights := [COLOR_CHOICES]i64{}
	for &ev in events {
		idx := name_color_idx(ev.id)
		duration := bound_duration(&ev, thread_max)

		color_weights[idx] += duration
		total_weight += duration
	}

	weights_sum : i64 = 0
	for weight, idx in color_weights {
		color += trace.color_choices[idx] * f32(weight)
		weights_sum += weight
	}
	color /= f32(weights_sum)

	node.avg_color = color
	node.weight = total_weight
}

print_tree :: proc(depth: ^Depth) {
	fmt.printf("mah tree!\n")
	// If we blow this, we're in space
	tree_stack := [128]int{}
	stack_len := 0
	pad_buf := [?]u8{0..<64 = '\t',}

	tree_stack[0] = 0; stack_len += 1
	for stack_len > 0 {
		stack_len -= 1

		tree_idx := tree_stack[stack_len]
		cur_node := &depth.tree[tree_idx]

		fmt.printf("%d | start: %v, end: %v, weight: %v\n", tree_idx, cur_node.start_time, cur_node.end_time, cur_node.weight)

		if tree_idx > (len(depth.tree) - depth.leaf_count - 1) {
			continue
		}

		start_idx := (CHUNK_NARY_WIDTH * tree_idx) + 1
		end_idx := min(start_idx + CHUNK_NARY_WIDTH - 1, len(depth.tree) - 1)
		child_count := end_idx - start_idx
		for i := child_count; i >= 0; i -= 1 {
			tree_stack[stack_len] = start_idx + i; stack_len += 1
		}
	}
	fmt.printf("ded!\n")
}

chunk_events :: proc(trace: ^Trace) {
	lod_mem_usage := 0
	ev_mem_usage := 0

	// using an eytzinger LOD tree for each depth array
	for &proc_v, p_idx in trace.processes {
		for &tm, t_idx in proc_v.threads {
			for &depth, d_idx in tm.depths {
				leaf_count := i_round_up(len(depth.events), BUCKET_SIZE) / BUCKET_SIZE
				depth.leaf_count = leaf_count

				width := CHUNK_NARY_WIDTH - 1
				internal_node_count := i_round_up((leaf_count - 1), width) / width
				total_node_count := internal_node_count + leaf_count

				tm.depths[d_idx].tree = make([]ChunkNode, total_node_count)

				lod_mem_usage += size_of(ChunkNode) * total_node_count
				ev_mem_usage += size_of(Event) * len(depth.events)

				tree := tm.depths[d_idx].tree
				tree_start_idx := len(tree) - leaf_count

				cur_node := 0
				overhang_idx := 0
				prehang_rank := 0
				for ; cur_node < total_node_count; {
					overhang_idx = cur_node
					cur_node = (CHUNK_NARY_WIDTH * cur_node) + 1

					prehang_rank += 1
				}

				posthang_rank := 1
				tmp_idx := len(tree) - leaf_count
				for ; tmp_idx > 0; {
					tmp_idx = (tmp_idx - 1) / CHUNK_NARY_WIDTH
					posthang_rank += 1
				}

				_tmp := 1
				for _tmp < leaf_count {
					_tmp = _tmp * CHUNK_NARY_WIDTH
				}
				depth.full_leaves = _tmp

				overhang_len := len(tree) - overhang_idx
				if prehang_rank == posthang_rank {
					overhang_len = 0
				}
				depth.overhang_len = overhang_len

				for i := 0; i < overhang_len; i += 1 {
					start_idx := i * BUCKET_SIZE
					end_idx := start_idx + min(len(depth.events) - start_idx, BUCKET_SIZE)
					scan_arr := depth.events[start_idx:end_idx]

					start_ev := &scan_arr[0]
					end_ev := &scan_arr[len(scan_arr)-1]
					tree_idx := overhang_idx + i

					node := &tree[tree_idx]
					node.start_time = start_ev.timestamp - trace.total_min_time
					node.end_time   = end_ev.timestamp + bound_duration(end_ev, tm.max_time) - trace.total_min_time
					gen_event_color(trace, scan_arr, tm.max_time, node)

				}

				previous_len := leaf_count - overhang_len
				ev_offset := overhang_len * BUCKET_SIZE
				for i := 0; i < previous_len; i += 1 {
					start_idx := (i * BUCKET_SIZE) + ev_offset
					end_idx := start_idx + min(len(depth.events) - start_idx, BUCKET_SIZE)
					scan_arr := depth.events[start_idx:end_idx]

					start_ev := &scan_arr[0]
					end_ev := &scan_arr[len(scan_arr)-1]
					tree_idx := tree_start_idx + i

					node := &tree[tree_idx]
					node.start_time = start_ev.timestamp - trace.total_min_time
					node.end_time   = end_ev.timestamp + bound_duration(end_ev, tm.max_time) - trace.total_min_time
					gen_event_color(trace, scan_arr, tm.max_time, node)
				}

				avg_color := FVec3{}
				for i := tree_start_idx - 1; i >= 0; i -= 1 {
					node := &tree[i]

					start_idx := (CHUNK_NARY_WIDTH * i) + 1
					end_idx := min(start_idx + (CHUNK_NARY_WIDTH - 1), len(tree) - 1)

					node.start_time = tree[start_idx].start_time
					node.end_time   = tree[end_idx].end_time

					avg_color = {}
					for j := start_idx; j <= end_idx; j += 1 {
						avg_color += tree[j].avg_color * f32(tree[j].weight)
						node.weight += tree[j].weight
					}
					node.avg_color = avg_color / f32(node.weight)
				}
			}
		}
	}

	fmt.printf("LOD memory: %M | Event memory: %M\n", lod_mem_usage, ev_mem_usage)
}

get_left_child :: #force_inline proc(idx: int) -> int {
	return (CHUNK_NARY_WIDTH * idx) + 1
}
get_child_count :: proc(depth: ^Depth, idx: int) -> int {
	start_idx := get_left_child(idx)
	end_idx := min(start_idx + CHUNK_NARY_WIDTH - 1, len(depth.tree) - 1)
	child_count := end_idx - start_idx + 1

	return child_count
}

linearize_leaf :: proc(depth: ^Depth, idx: int, loc := #caller_location) -> int {
	overhang_start := len(depth.tree) - depth.overhang_len
	leaf_start := len(depth.tree) - depth.leaf_count

	ret := 0
	if depth.overhang_len == 0 {
		ret = idx - leaf_start
	} else if idx >= overhang_start {
		ret = idx - overhang_start
	} else {
		ret = (idx - leaf_start) + depth.overhang_len
	}
	return ret
}

// This *must* take a leaf idx
get_event_count :: proc(depth: ^Depth, idx: int) -> int {
	linear_idx := linearize_leaf(depth, idx)

	ret := BUCKET_SIZE
	// if we're the last index in the tree, determine the leftover
	if linear_idx == (depth.leaf_count - 1) {
		ret = len(depth.events) % BUCKET_SIZE


		// If we fall exactly in the bucket?
		if ret == 0 {
			ret = BUCKET_SIZE
		}
	}

	return ret
}
// This *must* take a leaf idx
get_event_start_idx :: proc(depth: ^Depth, idx: int) -> int {
	linear_idx := linearize_leaf(depth, idx)
	return linear_idx * BUCKET_SIZE
}

is_leaf :: proc(depth: ^Depth, idx: int) -> bool {
	ret := idx >= (len(depth.tree) - depth.leaf_count)
	return ret
}

get_left_leaf :: proc(depth: ^Depth, idx: int) -> int {
	tmp_idx := idx
	last_tmp := idx
	for tmp_idx < len(depth.tree) {
		last_tmp = tmp_idx
		tmp_idx = (CHUNK_NARY_WIDTH * tmp_idx) + 1
	}
	return last_tmp
}
get_right_leaf :: proc(depth: ^Depth, idx: int) -> int {
	if is_leaf(depth, idx) {
		return idx
	}

	full_internal_nodes := depth.full_leaves / (CHUNK_NARY_WIDTH - 1)
	full_tree_count := full_internal_nodes + depth.full_leaves

	internal_nodes := depth.leaf_count / (CHUNK_NARY_WIDTH - 1)
	total_tree_count := internal_nodes + depth.leaf_count

	prev_leaves := depth.full_leaves / CHUNK_NARY_WIDTH

	tmp_idx := idx
	last_tmp := idx
	for tmp_idx < len(depth.tree) {
		last_tmp = tmp_idx
		tmp_idx = (CHUNK_NARY_WIDTH * tmp_idx) + CHUNK_NARY_WIDTH
	}

	ret := last_tmp
	edge_case_count := total_tree_count + CHUNK_NARY_WIDTH - 1
	if edge_case_count >= full_tree_count {
		ret = len(depth.tree) - 1
	}
	return ret
}

get_event_range :: proc(depth: ^Depth, idx: int) -> (int, int) {
	left_idx := get_left_leaf(depth, idx)
	right_idx := get_right_leaf(depth, idx)
	event_start_idx := get_event_start_idx(depth, left_idx)
	event_count := get_event_count(depth, right_idx)

	linear_right_leaf := linearize_leaf(depth, right_idx)
	linear_left_leaf := linearize_leaf(depth, left_idx)
	leaf_count := linear_right_leaf - linear_left_leaf
	ev_count := (leaf_count * BUCKET_SIZE) + event_count

	start := event_start_idx
	end := event_start_idx + ev_count
	return start, end
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
		file_base := filepath.base(file_name)
		b := strings.builder_make(context.temp_allocator)
		strings.write_string(&b, file_name)
		strings.write_string(&b, ".dSYM/Contents/Resources/DWARF/")
		strings.write_string(&b, file_base)
		
		debug_file_name := strings.to_string(b)
		debug_buffer, ok2 := os.read_entire_file_from_filename(debug_file_name)
		if !ok2 {
			post_error(trace, "No debug info found!")
			return false
		}

		load_macho_debug(trace, debug_buffer)
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

	fmt.printf("Loaded %s symbols!\n", tens_fmt(u64(len(trace.addr_map.entries))))

	return true
}

init_trace_allocs :: proc(trace: ^Trace, file_name: string) {
	trace.processes    = make([dynamic]Process)
	trace.process_map  = vh_init()
	trace.string_block = make([dynamic]u8)
	trace.intern       = in_init()
	trace.addr_map     = am_init()

	trace.stats.selected_ranges = make([dynamic]Range)
	trace.stats.stat_map        = sm_init()

	trace.base_name = filepath.base(file_name)
	trace.file_name = file_name

	trace.line_info = make([dynamic]Line_Info)
	strings.intern_init(&trace.filename_map)

	// deliberately setting the first elem to 0, to simplify string interactions
	non_zero_append_elem(&trace.string_block, 0)
	non_zero_append_elem(&trace.string_block, 0)
}

init_trace :: proc(trace: ^Trace) {
	trace^ = Trace{
		total_max_time = min(i64),
		total_min_time = max(i64),

		event_count = 0,
		stamp_scale = 1,

		zoom_event = empty_event,
		stats = Stats{
			state           = .NoStats,
			just_started    = false,

			selected_func   = {},
			selected_event  = empty_event,
			pressed_event   = empty_event,
			released_event  = empty_event,
		},

		parser = Parser{},
		error_message = "",
	}
}

load_file :: proc(trace: ^Trace, file_name: string) {
	start_time := time.tick_now()

	init_trace(trace)
	init_trace_allocs(trace, file_name)

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
	fmt.printf("Loading %s, %M\n", trace.base_name, trace.total_size)

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
	if magic == spall_fmt.MANUAL_MAGIC {
		hdr, ok := slice_to_type(header_buffer[:], spall_fmt.Manual_Header)
		if !ok {
			post_error(trace, "%s is invalid!", file_name)
			return
		}

		if hdr.version != 1 && hdr.version != 2 {
			post_error(trace, "Spall version %d for %s is invalid!", hdr.version, file_name)
			return
		}
		
		trace.stamp_scale = hdr.timestamp_unit
		header_size = size_of(spall_fmt.Manual_Header)

		if hdr.version == 1 { 
			file_type = .ManualStreamV1 
			trace.stamp_scale *= 1000
		} else if hdr.version == 2 {
			file_type = .ManualStreamV2
		}

	} else if magic == spall_fmt.AUTO_MAGIC {
		hdr, ok := slice_to_type(header_buffer[:], spall_fmt.Auto_Header)
		if !ok {
			post_error(trace, "%s is invalid!", file_name)
			return
		}

        if hdr.version == 1 {
			post_error(trace, "Support for auto-tracing v1 has been dropped in this version, please grab the new header!")
			return
        }
		if hdr.version != 2 {
			post_error(trace, "Spall version %d for %s is invalid!", hdr.version, file_name)
			return
		}
		if total_size < i64(size_of(spall_fmt.Auto_Header)) + i64(hdr.program_path_len) {
			post_error(trace, "%s is invalid!", file_name)
			return
		}
		
		trace.stamp_scale = hdr.timestamp_unit
		trace.skew_address = hdr.known_address
		fmt.printf("runtime address of \"spall_auto_init\": 0x%08x\n", trace.skew_address)

		symbol_path := string(header_buffer[size_of(spall_fmt.Auto_Header):][:hdr.program_path_len])

		header_size = size_of(spall_fmt.Auto_Header) + i64(hdr.program_path_len)
		if !load_executable(trace, symbol_path) {
			return
		}

		file_type = .AutoStream
	} else {
		leading_char := header_buffer[0]
		if leading_char == ' '  || leading_char == '\n' ||
		   leading_char == '\r' || leading_char == '\t' ||
		   leading_char == '{'  || leading_char == '[' {
			file_type = .Json
		} else {
			file_type = .Invalid
			post_error(trace, "%s is an unsupported file type!", file_name)
		}
	}

	p := &trace.parser
	p.pos += i64(header_size)

	parsed_properly := false
	#partial switch file_type {
	case .ManualStreamV1:
		parsed_properly = ms_v1_parse(trace, trace_fd, header_size)
	case .ManualStreamV2:
		parsed_properly = ms_v2_parse(trace, trace_fd, header_size)
	case .AutoStream:
		parsed_properly = as_parse(trace, trace_fd, header_size)
	case .Json:
		parsed_properly = json_parse(trace, trace_fd)
	}

	if parsed_properly && (p.pos == i64(header_size) || trace.event_count == 0) {
		parsed_properly = false
		post_error(trace, "Trace is empty, did you remember to quit your threads and enable -finstrument-functions?")
	}

	free_trace_temps(trace)
	if !parsed_properly {
		error_temp := trace.error_storage
		error_str_len := len(trace.error_message)

		free_trace(trace)

		init_trace(trace)
		trace.error_storage = error_temp
		trace.error_message = string(trace.error_storage[:error_str_len])
		return
	}

	#partial switch file_type {
	case .ManualStreamV1: fallthrough
	case .ManualStreamV2: fallthrough
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

	if file_type == .Json {
		start_time = time.tick_now()

		json_generate_selftimes(trace)
		trace.stamp_scale = 1

		fmt.printf("generate selftimes -- %f ms\n", time.duration_milliseconds(time.tick_since(start_time)))
	}
}

ev_name :: proc(trace: ^Trace, ev: ^Event) -> string {
	if !ev.has_addr {
		return in_getstr(&trace.string_block, ev.id)
	}
	name_idx, ok := am_find(&trace.addr_map, ev.id)
	if !ok {
		tmp_buf := make([]byte, 18, context.temp_allocator)
		return u64_to_hexstr(tmp_buf, ev.id)
	}
	return in_getstr(&trace.string_block, name_idx)
}

get_line_info :: proc(trace: ^Trace, addr: u64) -> (string, u64, bool) {
	if len(trace.line_info) == 0 {
		return "", 0, false
	}

	line_info_start := trace.line_info[0].address
	line_info_end := trace.line_info[len(trace.line_info)-1].address

	// make sure address is within line-info bounds
	if line_info_start > addr || line_info_end < addr {
		return "", 0, false
	}

	low := 0
	max := len(trace.line_info)
	high := max - 1

	for low < high {
		mid := (low + high) / 2

		line_info := trace.line_info[mid]
		if addr == line_info.address {
			if line_info.line_num == 0 {
				return "", 0, false
			}

			return line_info.filename, line_info.line_num, true
		} else if addr > line_info.address { 
			low = mid + 1
		} else { 
			high = mid - 1
		}
	}

	line_info := trace.line_info[low]

	if addr == line_info.address {
		if line_info.line_num == 0 {
			return "", 0, false
		}

		return line_info.filename, line_info.line_num, true
	}

	//fmt.printf("Failed to match: 0x08%x\n", addr)
	return "", 0, false
}
