package main

SpallError :: enum int {
	NoError = 0,
	OutOfMemory = 1,
	Bug = 2,
	InvalidFile = 3,
	InvalidFileVersion = 4,
}

EventType :: enum u8 {
	Unknown = 0,
	Instant,
	Complete,
	Begin,
	End,
	Metadata,
	Sample,
}
EventScope :: enum u8 {
	Global,
	Process,
	Thread,
}
TempEvent :: struct {
	type: EventType,
	scope: EventScope,
	name: INStr,
	args: INStr,
	duration: f64,
	timestamp: f64,
	thread_id: u32,
	process_id: u32,
}
