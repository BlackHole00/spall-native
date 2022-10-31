package main

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
