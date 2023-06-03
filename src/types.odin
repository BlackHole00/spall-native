package main

import "core:fmt"

Vec2 :: [2]f64
FVec2 :: [2]f32

Vec3 :: [3]f64
FVec3 :: [3]f32

FVec4 :: [4]f32
BVec4 :: [4]u8

Rect :: struct {
	x: f64,
	y: f64,
	w: f64,
	h: f64,
}

UIState :: struct {
	width: f64,
	height: f64,
	side_pad: f64,
	rect_height: f64,
	top_line_gap: f64,
	topbars_height: f64,
	line_height: f64,

	flamegraph_header_height: f64,
	flamegraph_toptext_height: f64,
	info_pane_height:     f64,

	header_rect:          Rect,
	global_activity_rect: Rect,
	global_timebar_rect:  Rect,
	local_timebar_rect:   Rect,

	info_pane_rect:       Rect,
	tab_rect:             Rect,

	filter_pane_rect:      Rect,
	filter_pane_scroll_pos: f64,
	filter_pane_scroll_vel: f64,

	stats_pane_rect:      Rect,
	stats_pane_scroll_pos: f64,
	stats_pane_scroll_vel: f64,

	minimap_rect:         Rect,

	full_flamegraph_rect:   Rect,
	inner_flamegraph_rect:  Rect,
	padded_flamegraph_rect: Rect,

	render_one_more: bool,
	multiselecting: bool,
	resizing_pane: bool,
	filters_open: bool,
}

DrawRect :: struct #packed {
	pos: FVec4,
	color: BVec4,
	uv: FVec2,
}
TextRect :: struct {
	str: string,
	scale: FontSize,
	type: FontType,
	pos: FVec2,
	color: BVec4,
}
TextRectArr :: [dynamic]TextRect

FontSize :: enum u8 {
	PSize = 0,
	H1Size,
	H2Size,
	LastSize,
}
FontType :: enum u8 {
	DefaultFont = 0,
	MonoFont,
	IconFont,
	LastFont,
}

LRU_Key :: struct #packed {
	size: FontSize,
	type: FontType,
	str: string,
}

LRU_Text :: struct {
	handle: u32,
	width: i32,
	height: i32,
}

SpallError :: enum int {
	NoError = 0,
	OutOfMemory = 1,
	Bug = 2,
	InvalidFile = 3,
	InvalidFileVersion = 4,
	FileFailure = 5,
}

BinaryState :: enum {
	PartialRead,
	EventRead,
	Failure,
}

Camera :: struct {
	pan: Vec2,
	vel: Vec2,
	target_pan_x: f64,

	current_scale: f64,
	target_scale: f64,
}

EventID :: struct {
	pid: i64,
	tid: i64,
	did: i64,
	eid: i64,
}
Stats :: struct {
	total_time: i64,
	self_time: i64,
	avg_time: f64,
	min_time: i64,
	max_time: i64,
	count: u32,
	hist: [100]f64,
}
Range :: struct {
	pid: int,
	tid: int,
	did: int,

	start: int,
	end: int,
}
StatState :: enum {
	NoStats,
	Pass1,
	Pass2,
	Finished,
}
StatEntry :: struct {
	key: u32,
	val: Stats,
}
SortState :: enum {
	SelfTime,
	TotalTime,
	MinTime,
	MaxTime,
	AvgTime,
	Count,
}
StatOffset :: struct {
	range_idx: int,
	event_idx: int,
}

EventType :: enum {
	Unknown = 0,
	Instant,
	Complete,
	Begin,
	End,
	Metadata,
	Sample,
	Pad_Skip,
	MicroBegin,
	MicroEnd,
}
EventScope :: enum {
	Global,
	Process,
	Thread,
}
TempEvent :: struct {
	type: EventType,
	scope: EventScope,
	duration: i64,
	timestamp: i64,
	thread_id: u32,
	process_id: u32,
	name: u32,
	args: u32,
}
Instant :: struct #packed {
	name: u32,
	timestamp: i64,
}

Event :: struct #packed {
	timestamp: [6]u8,
	duration:  [6]u8,
	name: u32,
	args: u32,
	self_time: i64,
}

Trace :: struct {
	file_name: string,
	base_name: string,
	total_size: i64,
	parser: Parser,
	intern: INMap,
	string_block: [dynamic]u8,

	skew_address: u64,
	addr_map: AMMap,
	color_choices: [16]FVec3,

	processes: [dynamic]Process,
	process_map: ValHash,
	selected_ranges: [dynamic]Range,
	stats: StatMap,
	global_instants: [dynamic]Instant,
	stats_start_time: f64,
	stats_end_time: f64,

	total_max_time: i64,
	total_min_time: i64,
	event_count: u64,
	instant_count: u64,
	stamp_scale: f64,

	error_message: string,
	error_storage: [4096]u8,
}

BUCKET_SIZE :: 4
CHUNK_NARY_WIDTH :: 4
ChunkNode :: struct #packed {
	start_time: i64,
	end_time: i64,

	avg_color: FVec3,
	weight: i64,

	tree_start_idx: uint,
	event_start_idx: uint,

	tree_child_count: i8,
	event_arr_len: i8,
}
Depth :: struct {
	head: uint,
	tree: [dynamic]ChunkNode,
	events: [dynamic]Event,
}

Thread :: struct {
	min_time: i64,
	max_time: i64,
	current_depth: u16,

	id: u32,
	name: u32,

	in_stats: bool,

	events: [dynamic]Event,
	depths: [dynamic]Depth,
	instants: [dynamic]Instant,

	bande_q: Stack(int),
}

Process :: struct {
	min_time: i64,
	name: u32,

	id: u32,

	in_stats: bool,

	threads: [dynamic]Thread,
	instants: [dynamic]Instant,
	thread_map: ValHash,
}

init_process :: proc(process_id: u32) -> Process {
	return Process{
		min_time = max(i64), 
		id = process_id,
		in_stats = true,
		thread_map = vh_init(),
		threads = make([dynamic]Thread),
		instants = make([dynamic]Instant),
	}
}
free_process :: proc(process: ^Process) {
	delete(process.threads)
	delete(process.instants)
}

get_proc_name :: proc(trace: ^Trace, process: ^Process) -> string {
	if process.name > 0 {
		return fmt.tprintf("%s (PID %d)", in_getstr(&trace.string_block, process.name), process.id)
	} else {
		return fmt.tprintf("PID: %d", process.id)
	}
}

init_thread :: proc(thread_id: u32) -> Thread {
	t := Thread{
		min_time = max(i64), 
		id = thread_id,
		in_stats = true,
		events = make([dynamic]Event),
		depths = make([dynamic]Depth),
		instants = make([dynamic]Instant),
	}
	stack_init(&t.bande_q)
	return t
}
free_thread :: proc(thread: ^Thread) {
	for depth in thread.depths {
		delete(depth.events)
		delete(depth.tree)
	}
	delete(thread.events)
	delete(thread.depths)
	delete(thread.instants)
}

get_thread_name :: proc(trace: ^Trace, thread: ^Thread) -> string {
	if thread.name > 0 {
		return fmt.tprintf("%s (TID %d)", in_getstr(&trace.string_block, thread.name), thread.id)
	} else {
		return fmt.tprintf("TID: %d", thread.id)
	}
}

Stack :: struct($T: typeid) {
	arr: [dynamic]T,
	len: int,
}
stack_init :: proc(s: ^$Q/Stack($T), allocator := context.allocator) {
	s.arr = make([dynamic]T, 16, allocator)
	s.len = 0
}
stack_free :: proc(s: ^$Q/Stack($T)) {
	delete(s.arr)
}
stack_push_back :: proc(s: ^$Q/Stack($T), elem: T) #no_bounds_check {
	if s.len >= cap(s.arr) {
		new_capacity := max(uint(8), uint(len(s.arr))*2)
		resize(&s.arr, int(new_capacity))
	}
	s.arr[s.len] = elem
	s.len += 1
}
stack_pop_back :: proc(s: ^$Q/Stack($T)) -> T #no_bounds_check {
	s.len -= 1
	return s.arr[s.len]
}
stack_peek_back :: proc(s: ^$Q/Stack($T)) -> T #no_bounds_check { return s.arr[s.len - 1] }
stack_clear :: proc(s: ^$Q/Stack($T)) { s.len = 0 }

print_stack :: proc(s: ^$Q/Stack($T)) {
	fmt.printf("Stack{{\n")
	for i:= 0; i < s.len; i += 1 {
		fmt.printf("%#v\n", s.arr[i])
	}
	fmt.printf("}}\n")
}

unpack_ns :: proc(packed: [6]u8) -> i64 {
	ret : u64 = 0
	ret |= u64(packed[0]) << 56
	ret |= u64(packed[1]) << 48
	ret |= u64(packed[2]) << 40
	ret |= u64(packed[3]) << 32
	ret |= u64(packed[4]) << 24
    ret |= u64(packed[5]) << 16

	return i64(ret)
}

pack_ns :: proc(val: i64) -> [6]u8 {
	tmp := transmute([8]u8)val
	return [6]u8{tmp[7], tmp[6], tmp[5], tmp[4], tmp[3], tmp[2]}
}
