package main

Vec2 :: [2]f64
Vec3 :: [3]f64
FVec3 :: [3]f32
FVec4 :: [4]f32
Rect :: struct {
	pos: Vec2,
	size: Vec2,
}
rect :: #force_inline proc(x, y, w, h: f64) -> Rect {
	return Rect{Vec2{x, y}, Vec2{w, h}}
}


SpallError :: enum int {
	NoError = 0,
	OutOfMemory = 1,
	Bug = 2,
	InvalidFile = 3,
	InvalidFileVersion = 4,
	FileFailure = 5,
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
Event :: struct #packed {
	name: INStr,
	args: INStr,
	timestamp: f64,
	duration: f64,
	self_time: f64,
}
Instant :: struct #packed {
	name: INStr,
	timestamp: f64,
}

Trace :: struct {
	string_block: [dynamic]u8,
	processes: [dynamic]Process,
	process_map: ValHash,
	total_max_time: f64,
	total_min_time: f64,
	event_count: u64,
	stamp_scale: f64,
	parser: Parser,
}

BUCKET_SIZE :: 8
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
	bs_events: [dynamic]Event,
	events: []Event,
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

	bande_q: Stack(int),
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
		threads = make([dynamic]Thread),
		thread_map = vh_init(context.temp_allocator),
		instants = make([dynamic]Instant),
	}
}

init_thread :: proc(thread_id: u32) -> Thread {
	t := Thread{
		min_time = 0x7fefffffffffffff, 
		thread_id = thread_id,
		events = make([dynamic]Event),
		depths = make([dynamic]Depth),
		instants = make([dynamic]Instant),
	}
	stack_init(&t.bande_q, context.temp_allocator)
	return t
}

Stack :: struct($T: typeid) {
	arr: [dynamic]T,
	len: int,
}
stack_init :: proc(s: ^$Q/Stack($T), allocator := context.allocator) {
	s.arr = make([dynamic]T, 16, allocator)
	s.len = 0
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
