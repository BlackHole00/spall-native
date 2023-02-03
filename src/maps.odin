package main

import "core:fmt"
import "core:hash"
import "core:runtime"
import "core:strings"
import "core:slice"

VH_LOAD_FACTOR :: 0.75
// u32 -> u32 map
PTEntry :: struct {
	key: u32,
	val: int,
}
ValHash :: struct {
	entries: [dynamic]PTEntry,
	hashes:  [dynamic]int,
	resize_threshold: i64,
}

vh_init :: proc(allocator := context.allocator) -> ValHash {
	v := ValHash{}
	v.entries = make([dynamic]PTEntry, 0, allocator)
	v.hashes = make([dynamic]int, 32, allocator) // must be a power of two
	for i in 0..<len(v.hashes) {
		v.hashes[i] = -1
	}
	v.resize_threshold = i64(f64(len(v.hashes)) * VH_LOAD_FACTOR)
	return v
}

vh_free :: proc(v: ^ValHash) {
	delete(v.entries)
	delete(v.hashes)
}

// this is a fibhash.. Replace me if I'm dumb
vh_hash :: proc "contextless" (key: u32) -> u32 {
	return key * 2654435769
}

vh_find :: proc (v: ^ValHash, key: u32) -> (int, bool) {
	hv := u64(vh_hash(key)) & u64(len(v.hashes) - 1)
	for i: u64 = 0; i < u64(len(v.hashes)); i += 1 {
		idx := (hv + i) & u64(len(v.hashes) - 1)

		e_idx := v.hashes[idx]
		if e_idx == -1 {
			return -1, false
		}

		if v.entries[e_idx].key == key {
			return v.entries[e_idx].val, true
		}
	}

	push_fatal(SpallError.Bug)
}

vh_grow :: proc(v: ^ValHash) {
	resize(&v.hashes, len(v.hashes) * 2)
	for i in 0..<len(v.hashes) {
		v.hashes[i] = -1
	}

	v.resize_threshold = i64(f64(len(v.hashes)) * VH_LOAD_FACTOR)
	for entry, idx in v.entries {
		vh_reinsert(v, entry, idx)
	}
}

vh_reinsert :: proc "contextless" (v: ^ValHash, entry: PTEntry, v_idx: int) {
	hv := u64(vh_hash(entry.key)) & u64(len(v.hashes) - 1)
	for i: u64 = 0; i < u64(len(v.hashes)); i += 1 {
		idx := (hv + i) & u64(len(v.hashes) - 1)

		e_idx := v.hashes[idx]
		if e_idx == -1 {
			v.hashes[idx] = v_idx
			return
		}
	}
}

vh_insert :: proc(v: ^ValHash, key: u32, val: int) {
	if i64(len(v.entries)) >= v.resize_threshold {
		vh_grow(v)
	}

	hv := u64(vh_hash(key)) & u64(len(v.hashes) - 1)
	for i: u64 = 0; i < u64(len(v.hashes)); i += 1 {
		idx := (hv + i) & u64(len(v.hashes) - 1)

		e_idx := v.hashes[idx]
		if e_idx == -1 {
			v.hashes[idx] = len(v.entries)
			append(&v.entries, PTEntry{key, val})
			return
		} else if v.entries[e_idx].key == key {
			v.entries[e_idx] = PTEntry{key, val}
			return
		}
	}

	push_fatal(SpallError.Bug)
}

INMAP_LOAD_FACTOR :: 0.75

// String interning
INMap :: struct {
	entries: [dynamic]u32,
	hashes:  [dynamic]int,
	resize_threshold: i64,
	len_minus_one: u32,
}

in_init :: proc(allocator := context.allocator) -> INMap {
	v := INMap{
		entries = make([dynamic]u32, 0, allocator),
		hashes = make([dynamic]int, 32, allocator), // must be a power of two
	}
	for i in 0..<len(v.hashes) {
		v.hashes[i] = -1
	}
	v.resize_threshold = i64(f64(len(v.hashes)) * INMAP_LOAD_FACTOR) 
	return v
}
in_free :: proc(v: ^INMap) {
	delete(v.entries)
	delete(v.hashes)
}

in_hash :: proc (key: string) -> u32 {
	k := transmute([]u8)key
	return #force_inline hash.murmur32(k)
}

in_reinsert :: proc (v: ^INMap, strings: ^[dynamic]u8, entry: u32, v_idx: int) {
	hv := u64(in_hash(in_getstr(strings, entry))) & u64(len(v.hashes) - 1)
	for i: u64 = 0; i < u64(len(v.hashes)); i += 1 {
		idx := (u64(hv) + i) & u64(len(v.hashes) - 1)

		e_idx := v.hashes[idx]
		if e_idx == -1 {
			v.hashes[idx] = v_idx
			return
		}
	}
}

in_grow :: proc(v: ^INMap, strings: ^[dynamic]u8) {
	resize(&v.hashes, len(v.hashes) * 2)
	for i in 0..<len(v.hashes) {
		v.hashes[i] = -1
	}

	v.resize_threshold = i64(f64(len(v.hashes)) * INMAP_LOAD_FACTOR) 
	for entry, idx in v.entries {
		in_reinsert(v, strings, entry, idx)
	}
}

in_get :: proc(v: ^INMap, strings: ^[dynamic]u8, key: string) -> u32 {
	if i64(len(v.entries)) >= v.resize_threshold {
		in_grow(v, strings)
	}

	hv := u64(in_hash(key)) & u64(len(v.hashes) - 1)
	for i: u64 = 0; i < u64(len(v.hashes)); i += 1 {
		idx := (u64(hv) + i) & u64(len(v.hashes) - 1)

		e_idx := v.hashes[idx]
		if e_idx == -1 {
			v.hashes[idx] = len(v.entries)

			str_start := u32(len(strings))
			in_str := str_start
			key_len := u16(len(key))
			key_len_bytes := (([^]u8)(&key_len)[:2])
			append_elem(strings, key_len_bytes[0])
			append_elem(strings, key_len_bytes[1])
			append_elem_string(strings, key)
			append(&v.entries, in_str)

			return in_str
		} else if in_getstr(strings, v.entries[e_idx]) == key {
			return v.entries[e_idx]
		}
	}

	push_fatal(SpallError.Bug)
}

in_getstr :: #force_inline proc(v: ^[dynamic]u8, s: u32) -> string {
	str_len := u32((^u16)(raw_data(v[s:]))^)
	str_start := s+size_of(u16)
	return string(v[str_start:str_start+str_len])
}

KM_CAP :: 32

// Key mashing
KeyMap :: struct {
	keys:   [KM_CAP]string,
	types: [KM_CAP]FieldType,
	hashes: [KM_CAP]int,
	len: int,
}

km_init :: proc() -> KeyMap {
	v := KeyMap{}
	for i in 0..<len(v.hashes) {
		v.hashes[i] = -1
	}
	return v
}

// lol, fibhash win
km_hash :: proc "contextless" (key: string) -> u32 {
	return u32(key[0]) * 2654435769 
}

// expects that we only get static strings
km_insert :: proc(v: ^KeyMap, key: string, type: FieldType) {
	hv := km_hash(key) & (KM_CAP - 1)
	for i: u32 = 0; i < KM_CAP; i += 1 {
		idx := (hv + i) & (KM_CAP - 1)

		e_idx := v.hashes[idx]
		if e_idx == -1 {
			v.hashes[idx] = v.len
			v.keys[v.len] = key
			v.types[v.len] = type
			v.len += 1
			return
		} else if v.keys[e_idx] == key {
			return
		}
	}

	push_fatal(SpallError.Bug)
}

km_find :: proc (v: ^KeyMap, key: string) -> (FieldType, bool) {
	hv := km_hash(key) & (KM_CAP - 1)

	for i: u32 = 0; i < KM_CAP; i += 1 {
		idx := (hv + i) & (KM_CAP - 1)

		e_idx := v.hashes[idx]
		if e_idx == -1 {
			return .Invalid, false
		}

		if v.keys[e_idx] == key {
			return v.types[e_idx], true
		}
	}

	return .Invalid, false
}

// Tracking for Stats
SMMAP_LOAD_FACTOR :: 0.75
StatMap :: struct {
	entries: [dynamic]StatEntry,
	hashes:  [dynamic]int,
	resize_threshold: i64,
}
sm_init :: proc(allocator := context.allocator) -> StatMap {
	v := StatMap{}
	v.entries = make([dynamic]StatEntry, 0, allocator)
	v.hashes = make([dynamic]int, 32, allocator) // must be a power of two
	for i in 0..<len(v.hashes) {
		v.hashes[i] = -1
	}
	return v
}
sm_hash :: proc(start: u32) -> u32 {
	return start * 2654435769
}
sm_reinsert :: proc(v: ^StatMap, entry: StatEntry, v_idx: int) {
	hv := sm_hash(u32(entry.key)) & u32(len(v.hashes) - 1)
	for i: u32 = 0; i < u32(len(v.hashes)); i += 1 {
		idx := (hv + i) & u32(len(v.hashes) - 1)

		e_idx := v.hashes[idx]
		if e_idx == -1 {
			v.hashes[idx] = v_idx
			return
		}
	}

	push_fatal(SpallError.Bug)
}

sm_grow :: proc(v: ^StatMap) {
	resize(&v.hashes, len(v.hashes) * 2)
	for i in 0..<len(v.hashes) {
		v.hashes[i] = -1
	}

	v.resize_threshold = i64(f64(len(v.hashes)) * SMMAP_LOAD_FACTOR) 
	for entry, idx in v.entries {
		sm_reinsert(v, entry, idx)
	}
}

sm_get :: proc(v: ^StatMap, key: u32) -> (^Stats, bool) {
	hv := sm_hash(u32(key)) & u32(len(v.hashes) - 1)

	for i: u32 = 0; i < u32(len(v.hashes)); i += 1 {
		idx := (hv + i) & u32(len(v.hashes) - 1)

		e_idx := v.hashes[idx]
		if e_idx == -1 {
			return nil, false
		}

		entry_key := v.entries[e_idx].key
		if entry_key == key {
			return &v.entries[e_idx].val, true
		}
	}

	push_fatal(SpallError.Bug)
}
sm_insert :: proc(v: ^StatMap, key: u32, val: Stats) -> ^Stats {
	if i64(len(v.entries)) >= v.resize_threshold {
		sm_grow(v)
	}

	hv := sm_hash(key) & u32(len(v.hashes) - 1)
	for i: u32 = 0; i < u32(len(v.hashes)); i += 1 {
		idx := (hv + i) & u32(len(v.hashes) - 1)

		e_idx := v.hashes[idx]
		if e_idx == -1 {
			e_idx = len(v.entries)
			v.hashes[idx] = e_idx
			append(&v.entries, StatEntry{key, val})
			return &v.entries[e_idx].val
		} else if v.entries[e_idx].key == key {
			v.entries[e_idx] = StatEntry{key, val}
			return &v.entries[e_idx].val
		}
	}

	push_fatal(SpallError.Bug)
}
sm_sort :: proc(v: ^StatMap, less: proc(i, j: StatEntry) -> bool) {
	slice.sort_by(v.entries[:], less)
	for i in 0..<len(v.hashes) {
		v.hashes[i] = -1
	}

	for entry, idx in v.entries {
		sm_reinsert(v, entry, idx)
	}
}
sm_clear :: proc(v: ^StatMap)  {
	resize(&v.entries, 0)
	resize(&v.hashes, 32)
	for i in 0..<len(v.hashes) {
		v.hashes[i] = -1
	}
	v.resize_threshold = i64(f64(len(v.hashes)) * SMMAP_LOAD_FACTOR) 
}

// Address Map hashtable
AM_LOAD_FACTOR :: 0.70
// u64 -> u32 map
AMEntry :: struct {
	key: u64,
	val: u32,
}
AMMap :: struct {
	entries: [dynamic]AMEntry,
	hashes:  [dynamic]int,
	resize_threshold: i64,
}

am_init :: proc(allocator := context.allocator) -> AMMap {
	v := AMMap{}
	v.entries = make([dynamic]AMEntry, 0, allocator)
	v.hashes = make([dynamic]int, 32, allocator) // must be a power of two
	for i in 0..<len(v.hashes) {
		v.hashes[i] = -1
	}
	v.resize_threshold = i64(f64(len(v.hashes)) * AM_LOAD_FACTOR)
	return v
}

am_free :: proc(v: ^AMMap) {
	delete(v.entries)
	delete(v.hashes)
}

// this is a fibhash.. Replace me if I'm dumb
am_hash :: proc(key: u64) -> u32 {
	return u32(key) * 2654435769
}

am_find :: proc (v: ^AMMap, key: u64) -> (u32, bool) {
	hv := u64(am_hash(key)) & u64(len(v.hashes) - 1)
	for i: u64 = 0; i < u64(len(v.hashes)); i += 1 {
		idx := (hv + i) & u64(len(v.hashes) - 1)

		e_idx := v.hashes[idx]
		if e_idx == -1 {
			return 0, false
		}

		if v.entries[e_idx].key == key {
			return v.entries[e_idx].val, true
		}
	}

	push_fatal(SpallError.Bug)
}

am_grow :: proc(v: ^AMMap) {
	resize(&v.hashes, len(v.hashes) * 2)
	for i in 0..<len(v.hashes) {
		v.hashes[i] = -1
	}

	v.resize_threshold = i64(f64(len(v.hashes)) * AM_LOAD_FACTOR)
	for entry, idx in v.entries {
		am_reinsert(v, entry, idx)
	}
}

am_reinsert :: proc(v: ^AMMap, entry: AMEntry, v_idx: int) {
	hv := u64(am_hash(entry.key)) & u64(len(v.hashes) - 1)
	for i: u64 = 0; i < u64(len(v.hashes)); i += 1 {
		idx := (hv + i) & u64(len(v.hashes) - 1)

		e_idx := v.hashes[idx]
		if e_idx == -1 {
			v.hashes[idx] = v_idx
			return
		}
	}
}

am_insert :: proc(v: ^AMMap, key: u64, val: u32) {
	if i64(len(v.entries)) >= v.resize_threshold {
		am_grow(v)
	}

	hv := u64(am_hash(key)) & u64(len(v.hashes) - 1)
	for i: u64 = 0; i < u64(len(v.hashes)); i += 1 {
		idx := (hv + i) & u64(len(v.hashes) - 1)

		e_idx := v.hashes[idx]
		if e_idx == -1 {
			v.hashes[idx] = len(v.entries)
			append(&v.entries, AMEntry{key, val})
			return
		} else if v.entries[e_idx].key == key {
			v.entries[e_idx] = AMEntry{key, val}
			return
		}
	}

	push_fatal(SpallError.Bug)
}
