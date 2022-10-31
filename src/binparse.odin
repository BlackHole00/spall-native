package main

import "core:fmt"
import "core:strings"
import "core:slice"
import "core:mem"
import "formats:spall"

BinaryState :: enum {
	PartialRead,
	EventRead,
	Failure,
}

Parser :: struct {
	pos: i64,
	offset: i64,
	intern: INMap,
}

real_pos :: #force_inline proc(p: ^Parser) -> i64 { return p.pos }
chunk_pos :: #force_inline proc(p: ^Parser) -> i64 { return p.pos - p.offset }

init_parser :: proc() -> Parser {
	p := Parser{}
	p.intern = in_init()
	return p
}

get_next_event :: #force_no_inline proc(p: ^Parser, chunk: []u8, temp_ev: ^TempEvent) -> BinaryState {
	header_sz := i64(size_of(u64))
	if chunk_pos(p) + header_sz > i64(len(chunk)) {
		return .PartialRead
	}

	type := (^spall.Event_Type)(raw_data(chunk))^
	#partial switch type {
	case .Begin:
		event_sz := i64(size_of(spall.Begin_Event))
		if chunk_pos(p) + event_sz > i64(len(chunk)) {
			return .PartialRead
		}
		event := (^spall.Begin_Event)(raw_data(chunk))

		event_tail := i64(event.name_len) + i64(event.args_len)
		if (chunk_pos(p) + event_sz + event_tail) > i64(len(chunk)) {
			return .PartialRead
		}

		//name := string(chunk[event_sz:event_sz+i64(event.name_len)])
		//str := in_get(&p.intern, name)

		temp_ev.type = .Begin
		temp_ev.timestamp = event.time
		temp_ev.thread_id = event.tid
		temp_ev.process_id = event.pid
		//temp_ev.name = str

		p.pos += event_sz + event_tail
		return .EventRead
	case .End:
		event_sz := i64(size_of(spall.End_Event))
		if chunk_pos(p) + event_sz > i64(len(chunk)) {
			return .PartialRead
		}
		event := (^spall.End_Event)(raw_data(chunk))

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
