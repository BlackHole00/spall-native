package main

import "core:fmt"
import "core:hash"
import "core:runtime"
import "core:strings"

INMAP_LOAD_FACTOR :: 0.75

INStr :: struct #packed {
	start: int,
	len: u16,
}

// String interning
INMap :: struct {
	entries: [dynamic]INStr,
	hashes:  [dynamic]int,
	resize_threshold: i64,
	len_minus_one: u32,
}

in_init :: proc(allocator := context.allocator) -> INMap {
	v := INMap{
		entries = make([dynamic]INStr, 0, allocator),
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

in_hash :: proc (key: string) -> u32 #no_bounds_check {
	k := transmute([]u8)key
	return #force_inline hash.murmur32(k)
}

in_reinsert :: proc (v: ^INMap, strings: ^[dynamic]u8, entry: INStr, v_idx: int) {
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

in_get :: proc(v: ^INMap, strings: ^[dynamic]u8, key: string) -> INStr {
	if i64(len(v.entries)) >= v.resize_threshold {
		in_grow(v, strings)
	}

	hv := u64(in_hash(key)) & u64(len(v.hashes) - 1)
	for i: u64 = 0; i < u64(len(v.hashes)); i += 1 {
		idx := (u64(hv) + i) & u64(len(v.hashes) - 1)

		e_idx := v.hashes[idx]
		if e_idx == -1 {
			v.hashes[idx] = len(v.entries)

			str_start := len(strings)
			in_str := INStr{str_start, u16(len(key))}
			append_elem_string(strings, key)
			append(&v.entries, in_str)

			return in_str
		} else if in_getstr(strings, v.entries[e_idx]) == key {
			return v.entries[e_idx]
		}
	}

	push_fatal(SpallError.Bug)
}

in_getstr :: #force_inline proc(v: ^[dynamic]u8, s: INStr) -> string {
	return string(v[s.start:s.start+int(s.len)])
}

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
