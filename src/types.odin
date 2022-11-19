package main

Vec2 :: [2]f64
FVec2 :: [2]f32

Vec3 :: [3]f64
FVec3 :: [3]f32

FVec4 :: [4]f32
BVec4 :: [4]u8

Rect :: struct {
	pos: Vec2,
	size: Vec2,
}
rect :: #force_inline proc(x, y, w, h: f64) -> Rect {
	return Rect{Vec2{x, y}, Vec2{w, h}}
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
	total_time: f64,
	self_time: f64,
	avg_time: f64,
	min_time: f64,
	max_time: f64,
	count: u32,
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
	Started,
	Finished,
}
SortState :: enum {
	SelfTime,
	TotalTime,
	MinTime,
	MaxTime,
	AvgTime,
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
}
EventScope :: enum {
	Global,
	Process,
	Thread,
}
TempEvent :: struct {
	type: EventType,
	scope: EventScope,
	duration: f64,
	timestamp: f64,
	thread_id: u32,
	process_id: u32,
	name: INStr,
	args: INStr,
}
Instant :: struct #packed {
	name: INStr,
	timestamp: f64,
}
Event :: struct #packed {
	name: INStr,
	args: INStr,
	timestamp: f64,
	duration: f64,
	self_time: f64,
}

Trace :: struct {
	file_name: string,
	base_name: string,
	total_size: i64,
	parser: Parser,
	string_block: [dynamic]u8,
	color_choices: [16]FVec3,

	processes: [dynamic]Process,
	process_map: ValHash,
	selected_ranges: [dynamic]Range,
	stats: StatMap,
	global_instants: [dynamic]Instant,

	total_max_time: f64,
	total_min_time: f64,
	event_count: u64,
	instant_count: u64,
	stamp_scale: f64,
}

BUCKET_SIZE :: 4
CHUNK_NARY_WIDTH :: 4
ChunkNode :: struct #packed {
	start_time: f64,
	end_time: f64,

	avg_color: FVec3,
	weight: f64,

	start_idx: uint,
	end_idx: uint,
	children: [CHUNK_NARY_WIDTH]uint,

	child_count: i8,
	arr_len: i8,
}
Depth :: struct {
	head: uint,
	tree: [dynamic]ChunkNode,
	events: [dynamic]Event,
}

EVData :: struct {
	idx: int,
	depth: u16,
	self_time: f64,
}

Thread :: struct {
	min_time: f64,
	max_time: f64,
	current_depth: u16,

	thread_id: u32,
	name: INStr,

	events: [dynamic]Event,
	depths: [dynamic]Depth,
	instants: [dynamic]Instant,

	bande_q: Stack(EVData),
}

Process :: struct {
	min_time: f64,
	name: INStr,

	process_id: u32,
	threads: [dynamic]Thread,
	instants: [dynamic]Instant,
	thread_map: ValHash,
}

init_process :: proc(process_id: u32) -> Process {
	return Process{
		min_time = 0x7fefffffffffffff, 
		process_id = process_id,
		thread_map = vh_init(),
		threads = make([dynamic]Thread),
		instants = make([dynamic]Instant),
	}
}
free_process :: proc(process: ^Process) {
	delete(process.threads)
	delete(process.instants)
}

init_thread :: proc(thread_id: u32) -> Thread {
	t := Thread{
		min_time = 0x7fefffffffffffff, 
		thread_id = thread_id,
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
