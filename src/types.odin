package main

import "core:fmt"
import "core:strings"
import "core:time"
import "core:container/lru"

Vec2 :: [2]f64
FVec2 :: [2]f32

Vec3 :: [3]f64
FVec3 :: [3]f32

FVec4 :: [4]f32
BVec4 :: [4]u8

IRect :: struct {//[4]i32
	x: i32,
	y: i32,
	w: i32,
	h: i32,
}

Rect :: struct {
	x: f64,
	y: f64,
	w: f64,
	h: f64,
}

TextboxState :: struct {
	focus: bool,
	cursor: int,
	b: strings.Builder,

	prev: ^TextboxState,
	next: ^TextboxState,
}

TextboxKind :: enum u8 {
	ProgramInput,
	PathInput,
	CmdArgsInput,
}

init_textbox_state :: proc() -> TextboxState {
	return TextboxState{
		focus = false,
		cursor = 0,
		b = strings.builder_make(),
	}
}

UIMode :: enum {
	MainMenu,
	SampleRunning,
	TraceLoading,
	TraceView,
}

UIState :: struct {
	width: f64,
	height: f64,
	side_pad: f64,
	rect_height: f64,
	top_line_gap: f64,
	topbars_height: f64,
	line_height: f64,
	grip_delta: f64,

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

	loading_config: bool,
	post_loading: bool,

	ui_mode: UIMode,

	textboxes: map[TextboxKind]TextboxState,
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

Font_LRU_Key :: struct #packed {
	size: FontSize,
	type: FontType,
	str: string,
}

Font_LRU_Text :: struct {
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

empty_event := EventID{-1, -1, -1, -1}
event_cmp :: proc(ev1, ev2: EventID) -> bool {
	return (
	   ev1.pid == ev2.pid &&
	   ev1.tid == ev2.tid &&
	   ev1.did == ev2.did &&
	   ev1.eid == ev2.eid
	)
}

FunctionStats :: struct {
	total_time: i64,
	self_time: i64,
	avg_time: f64,
	min_time: i64,
	max_time: i64,
	count: u32,
	hist: [100]u32,
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
	id: u64,
	args: u64,
}
Instant :: struct #packed {
	id: u64,
	timestamp: i64,
}
Event :: struct #packed {
	has_addr: b8,
	id: u64,
	args: u64,
	timestamp: i64,
	duration: i64,
	self_time: i64,
}

Stats :: struct {
	selected_ranges: [dynamic]Range,
	stat_map:        StatMap,
	state:           StatState,

	start_time:      f64,
	end_time:        f64,
	total_time:      i64,

	cur_offset:      StatOffset,
	just_started:    bool,

	selected_func:   StatKey,
	selected_event:  EventID,
	pressed_event:   EventID,
	released_event:  EventID,
}

Function :: struct {
	name: u64,
	low_pc: u64,
	high_pc: u64,
}

Line_Info :: struct {
	address:  u64,
	line_num: u64,
	filename: string,
}

CU_File_Entry :: struct {
	cu_idx: u64,
	file_idx: u64,
}

Scope :: struct {
	func_idx: u64,

	low_pc: u64,
	high_pc: u64,

	children: [dynamic]Scope,
}

Func_Bucket :: struct {
	source_path: string,
	base_address: u64,
	uuid: [16]u8,

	functions: [dynamic]Function,
	line_info: [dynamic]Line_Info,
	scopes: Scope,

	scopes_built: bool,

	unwind_info: []ARM_Compact_Unwind_Op,
}

COLOR_CHOICES :: 64
Trace :: struct {
	file_name: string,
	base_name: string,
	total_size: i64,
	parser: Parser,
	intern: INMap,
	string_block: [dynamic]string,

	skew_size:                   u64,
	filename_map:     strings.Intern,
	func_buckets: [dynamic]Func_Bucket,

	color_choices: [COLOR_CHOICES]FVec3,

	processes: [dynamic]Process,
	process_map: ValHash,
	global_instants: [dynamic]Instant,

	total_max_time: i64,
	total_min_time: i64,
	event_count: u64,
	instant_count: u64,
	stamp_scale: f64,

	stats: Stats,
	zoom_event: EventID,

	load_kickoff: time.Tick,
	requested_stop: bool,
	error_message: string,
	error_storage: [4096]u8,

	func_lookup_cache: lru.Cache(u64, u64),

	unnamed_count: int,
}

BUCKET_SIZE :: 32
CHUNK_NARY_WIDTH :: 4
WEIGHT_COUNT :: 2
WeightIdx :: struct {
	idx: u8,
	weight: i64,
}
ChunkNode :: struct #packed {
	start_time: i64,
	end_time: i64,

	total_weight: i64,
	p: [WEIGHT_COUNT]WeightIdx,
}
Depth :: struct {
	tree: []ChunkNode,
	events: [dynamic]Event,
	leaf_count:   int,
	overhang_len: int,
	full_leaves: int,
}

Thread :: struct {
	min_time: i64,
	max_time: i64,
	current_depth: int,

	id: u32,
	name: u64,

	in_stats: bool,

	events: [dynamic]Event,
	depths: [dynamic]Depth,
	instants: [dynamic]Instant,

	bande_q: Stack(int),
	zero_patchup: i64,
	//last_dt: i64,
}

Process :: struct {
	min_time: i64,
	name: u64,

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
		zero_patchup = -1,
		//last_dt = -1,
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
		new_capacity := max(8, len(s.arr)*2)
		non_zero_resize(&s.arr, new_capacity)
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
