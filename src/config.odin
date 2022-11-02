package main

import "core:os"
import "core:fmt"
import "formats:spall"

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
}

load_file :: proc(filename: string) -> Trace {
	trace_fd, err := os.open(filename)
	if err != 0 {
		push_fatal(SpallError.InvalidFile)
	}
	defer os.close(trace_fd)

	chunk_buffer := make([]u8, 1 * 1024 * 1024)
	defer delete(chunk_buffer)

	trace := Trace{
		processes = make([dynamic]Process),
		process_map = vh_init(),
		total_max_time = 0,
		total_min_time = 0x7fefffffffffffff,
		event_count = 0,
		stamp_scale = 1,
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

	// parse header
	full_chunk := chunk_buffer[:rd_sz]

	header_sz := i64(size_of(spall.Header))
	if i64(len(full_chunk)) < header_sz {
		push_fatal(SpallError.InvalidFile)
	}

	magic := (^u64)(raw_data(full_chunk))^
	if magic == spall.MAGIC {
		hdr := cast(^spall.Header)raw_data(full_chunk)
		if hdr.version != 1 {
			push_fatal(SpallError.InvalidFileVersion)
		}
		
		trace.stamp_scale = hdr.timestamp_unit

		p := &trace.parser
		p.pos += header_sz
		parse_binary(&trace, trace_fd, chunk_buffer, i64(rd_sz), total_size)
	} else {
		push_fatal(SpallError.InvalidFile)
	}

	free_trace_temps(&trace)
	return trace
}
