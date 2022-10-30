package main

import "core:fmt"
import "core:strings"
import "core:slice"
import "formats:spall"

BinaryState :: enum {
	PartialRead,
	EventRead,
	Finished,
	Failed,
}

Parser :: struct {
	pos: i64,
	offset: i64,

	data: []u8,
	full_chunk: []u8,
	total_size: i64,

	intern: INMap,
}

real_pos :: #force_inline proc(p: ^Parser) -> i64 { return p.pos }
chunk_pos :: #force_inline proc(p: ^Parser) -> i64 { return p.pos - p.offset }

init_parser :: proc(size: i64) -> Parser {
	p := Parser{}
	p.pos    = 0
	p.offset = 0
	p.total_size = size
	p.intern = in_init()

	return p
}

get_next_event :: proc(p: ^Parser) -> (TempEvent, BinaryState) {
	p.data = p.full_chunk[chunk_pos(p):]

	if real_pos(p) >= p.total_size {
		return TempEvent{}, .Finished
	}

	header_sz := i64(size_of(u64))
	if chunk_pos(p) + header_sz > i64(len(p.data)) {
		return TempEvent{}, .PartialRead
	}

	type := (^spall.Event_Type)(raw_data(p.data))^
	switch type {
	case .Begin:
		event_sz := i64(size_of(spall.Begin_Event))
		if chunk_pos(p) + event_sz > i64(len(p.data)) {
			return TempEvent{}, .PartialRead
		}
		event := (^spall.Begin_Event)(raw_data(p.data))^

		event_tail := i64(event.name_len + event.args_len)
		if (chunk_pos(p) + event_sz + event_tail) > i64(len(p.data)) {
			return TempEvent{}, .PartialRead
		}

		name := string(p.data[event_sz:event_sz+i64(event.name_len)])
		str := in_get(&p.intern, name)

		ev := TempEvent{
			type = .Begin,
			timestamp = event.time,
			thread_id = event.tid,
			process_id = event.pid,
			name = str,
		}

		p.pos += event_sz + i64(event.name_len) + i64(event.args_len)
		return ev, .EventRead
	case .End:
		event_sz := i64(size_of(spall.End_Event))
		if chunk_pos(p) + event_sz > i64(len(p.data)) {
			return TempEvent{}, .PartialRead
		}
		event := (^spall.End_Event)(raw_data(p.data))^

		ev := TempEvent{
			type = .End,
			timestamp = event.time,
			thread_id = event.tid,
			process_id = event.pid,
		}
		
		p.pos += event_sz
		return ev, .EventRead
	case .StreamOver:          fallthrough;
	case .Custom_Data:         fallthrough;
	case .Instant:             fallthrough;
	case .Overwrite_Timestamp: fallthrough;

	case .Invalid: fallthrough;
	case:
		fmt.printf("Unknown/invalid chunk (%v)\n", type)
		push_fatal(SpallError.InvalidFile)
	}

	return TempEvent{}, .PartialRead
}
