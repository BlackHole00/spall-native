package main

import "core:os"
import "core:fmt"
import "core:slice"
import "core:bytes"
import "core:time"
import "core:runtime"
import "core:path/filepath"
import "core:strings"

import "formats:spall_fmt"

FileType :: enum {
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
	strings.intern_destroy(&trace.filename_map)
	delete(trace.line_info)

	delete(trace.stats.selected_ranges)
	sm_free(&trace.stats.stat_map)
	in_free(&trace.intern)
	am_free(&trace.addr_map)
}

/*
bound_duration :: proc(ev: ^Event, max_ts: i64) -> i64 {
	return ev.duration < 0 ? (max_ts - ev.timestamp) : ev.duration
}
*/

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
		skew_size : u64 = 0
		ok := load_macho_symbols(trace, exec_buffer, &skew_size)
		if !ok {
			post_error(trace, "Failed to parse Mach-O!")
			return false
		}

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

		load_macho_debug(trace, debug_buffer, skew_size)
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
	append_elem(&trace.string_block, 0)
	append_elem(&trace.string_block, 0)
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
		}
		else if hdr.version == 2 { file_type = .ManualStreamV2 }

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

		symbol_path := string(header_buffer[size_of(spall_fmt.Auto_Header):][:hdr.program_path_len])

		header_size = size_of(spall_fmt.Auto_Header) + i64(hdr.program_path_len)
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
		/*
	case .ManualStreamV1:
		parsed_properly = ms_v1_parse(trace, trace_fd, header_size)
	case .ManualStreamV2:
		parsed_properly = ms_v2_parse(trace, trace_fd, header_size)
	case .Json:
		parsed_properly = json_parse(trace, trace_fd)
		*/
	case .AutoStream:
		parsed_properly = as_parse(trace, trace_fd, header_size)
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
		// json_process_events(trace)
	}
	fmt.printf("parse config -- %f ms\n", time.duration_milliseconds(time.tick_since(start_time)))
	
	generate_color_choices(trace)

	if file_type == .Json {
		start_time = time.tick_now()

		// json_generate_selftimes(trace)
		trace.stamp_scale = 1

		fmt.printf("generate selftimes -- %f ms\n", time.duration_milliseconds(time.tick_since(start_time)))
	}
}

/*
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
*/

get_line_info :: proc(trace: ^Trace, addr: u64) -> (string, u64, bool) {
	if len(trace.line_info) == 0 {
		return "", 0, false
	}

	// make sure address is within line-info bounds
	if trace.line_info[0].address > addr || trace.line_info[len(trace.line_info)-1].address < addr {
		return "", 0, false
	}

	low := 0
	max := len(trace.line_info)
	high := max - 1

	for low < high {
		mid := (low + high) / 2

		line_info := trace.line_info[mid]
		if addr == line_info.address {
			return line_info.filename, line_info.line_num, true
		} else if addr > line_info.address { 
			low = mid + 1
		} else { 
			high = mid - 1
		}
	}

	line_info := trace.line_info[low]
	if addr == line_info.address {
		return line_info.filename, line_info.line_num, true
	}

	return "", 0, false
}
