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
	v := INMap{}
	v.entries = make([dynamic]INStr, 0, allocator)
	v.hashes = make([dynamic]int, 32, allocator) // must be a power of two
	for i in 0..<len(v.hashes) {
		v.hashes[i] = -1
	}
	v.resize_threshold = i64(f64(len(v.hashes)) * INMAP_LOAD_FACTOR) 
	v.len_minus_one = u32(len(v.hashes) - 1)
	return v
}

in_hash :: proc (key: string) -> u32 #no_bounds_check {
	k := transmute([]u8)key
	return #force_inline hash.murmur32(k)
}


in_reinsert :: proc (v: ^INMap, entry: INStr, v_idx: int) {
	hv := in_hash(in_getstr(entry)) & v.len_minus_one
	for i: u32 = 0; i < u32(len(v.hashes)); i += 1 {
		idx := (hv + i) & v.len_minus_one

		e_idx := v.hashes[idx]
		if e_idx == -1 {
			v.hashes[idx] = v_idx
			return
		}
	}
}

in_grow :: proc(v: ^INMap) {
	resize(&v.hashes, len(v.hashes) * 2)
	for i in 0..<len(v.hashes) {
		v.hashes[i] = -1
	}

	v.resize_threshold = i64(f64(len(v.hashes)) * INMAP_LOAD_FACTOR) 
	v.len_minus_one = u32(len(v.hashes) - 1)
	for entry, idx in v.entries {
		in_reinsert(v, entry, idx)
	}
}

in_get :: proc(v: ^INMap, key: string) -> INStr {
	if i64(len(v.entries)) >= v.resize_threshold {
		in_grow(v)
	}

	hv := in_hash(key) & v.len_minus_one
	for i: u32 = 0; i < u32(len(v.hashes)); i += 1 {
		idx := (hv + i) & v.len_minus_one

		e_idx := v.hashes[idx]
		if e_idx == -1 {
			v.hashes[idx] = len(v.entries)

			str_start := len(string_block)
			in_str := INStr{str_start, u16(len(key))}
			append_elem_string(&string_block, key)
			append(&v.entries, in_str)

			return in_str
		} else if in_getstr(v.entries[e_idx]) == key {
			return v.entries[e_idx]
		}
	}

	push_fatal(SpallError.Bug)
}

in_getstr :: #force_inline proc(v: INStr) -> string {
	return string(string_block[v.start:v.start+int(v.len)])
}
