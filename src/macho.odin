package main

import "base:intrinsics"

import "core:fmt"
import "core:strings"
import "core:slice"
import "core:path/filepath"

MACH_FAT_MAGIC :: 0xcafebebe
MACH_FAT_CIGAM :: 0xbebafeca
MACH_MAGIC_64  :: 0xfeedfacf

MACH_CPU_ABI_64      :: 0x1000000
MACH_CPU_TYPE_I386   :: 7
MACH_CPU_TYPE_X86_64 :: MACH_CPU_TYPE_I386 | MACH_CPU_ABI_64
MACH_CPU_TYPE_ARM    :: 12
MACH_CPU_TYPE_ARM64  :: MACH_CPU_TYPE_ARM | MACH_CPU_ABI_64

Mach_Cmd :: enum u32 {
	Symtab              = 0x2,
	DySymtab            = 0xB,
	Load_Dylib          = 0xC,
	ID_Dylib            = 0xD,
	Load_Dylinker       = 0xE,
	Sub_Framework       = 0x12,
	Sub_Client          = 0x14,
	Segment_64          = 0x19,
	UUID                = 0x1B,
	Code_Signature      = 0x1D,
	Function_Starts     = 0x26,
	Data_In_Code        = 0x29,
	Build_Version       = 0x32,
	Source_Version      = 0x2A,
	Load_Weak_Dylib     = 0x80000018,
	ReExport_Dylib      = 0x8000001f,
	Load_Upward_Dylib   = 0x80000023,
	Main                = 0x80000028,
	DYLD_Info_Only      = 0x80000022,
	DYLD_Exports_Trie   = 0x80000033,
	DYLD_Chained_Fixups = 0x80000034,
}

MACH_FILETYPE_EXEC   :: 2
MACH_FILETYPE_DYLIB  :: 6
MACH_FILETYPE_DYLD   :: 7
MACH_FILETYPE_DSYM   :: 10
MACH_DYLIB_IN_CACHE  :: 0x80000000
Mach_Header_64 :: struct #packed {
	magic:       u32,
	cpu_type:    u32,
	cpu_subtype: u32,
	file_type:   u32,
	cmd_count:   u32,
	cmd_size:    u32,
	flags:       u32,
	reserved:    u32,
}

Mach_Fat_Header :: struct #packed {
	magic:          u32,
	fat_arch_count: u32,
}
Mach_Fat_Arch_Header :: struct #packed {
	cpu_type:    u32,
	cpu_subtype: u32,
	offset:      u32,
	size:        u32,
	align:       u32,
}

Mach_Load_Command :: struct #packed {
	type: Mach_Cmd,
	size: u32,
}

Mach_Segment_64_Command :: struct #packed {
	type:                Mach_Cmd,
	size:                u32,
	name:             [16]u8,
	address:             u64,
	mem_size:            u64,
	file_offset:         u64,
	file_size:           u64,
	max_protection:      i32,
	init_protection:     i32,
	section_count:       u32,
	flags:               u32,
}

Mach_Section :: struct #packed {
	name:         [16]u8,
	segment_name: [16]u8,
	address:         u64,
	size:            u64,
	offset:          u32,
	align:           u32,
	reloc_offset:    u32,
	reloc_count:     u32,
	flags:           u32,
	_rsv1:           u32,
	_rsv2:           u32,
	_rsv3:           u32,
}

Mach_Symtab_Command :: struct #packed {
	type:                Mach_Cmd,
	size:                u32,
	symbol_table_offset: u32,
	symbol_count:        u32,
	string_table_offset: u32,
	string_table_size:   u32,
}

Mach_UUID_Command :: struct #packed {
	type:    Mach_Cmd,
	size:    u32,
	uuid: [16]u8,
}

Mach_Linkedit_Data_Command :: struct #packed {
	type:      Mach_Cmd,
	size:      u32,
	file_off:  u32,
	file_size: u32,
}

Mach_Symbol_Entry_64 :: struct #packed {
	string_table_idx: u32,
	type: u8,
	section_count: u8,
	description: u16,
	value: u64,
}

Mach_Unwind_Info_Header :: struct #packed {
	version:               u32,
	global_opcodes_offset: u32,
	global_opcodes_len:    u32,
	personalities_offset:  u32,
	personalities_len:     u32,
	pages_offset:          u32,
	pages_len:             u32,
}

Mach_Page_Entry :: struct #packed {
	first_addr: u32,
	subpage_offset: u32,
	lsda_index_offset: u32,
}

Mach_Subpage_Kind :: enum u32 {
	Regular = 2,
	Compressed = 3,
}

Mach_Regular_Subpage :: struct #packed {
	kind: Mach_Subpage_Kind,
	entries_offset: u16,
	entries_len: u16,
}

Mach_Compressed_Subpage :: struct #packed {
	kind: Mach_Subpage_Kind,
	entries_offset: u16,
	entries_len: u16,

	local_opcodes_offset: u16,
	local_opcodes_len: u16,
}

Mach_Regular_Entry :: struct #packed {
	inst_addr: u32,
	opcode: u32,
}

Mach_LSDA_Entry :: struct #packed {
	inst_addr: u32,
	lsda_addr: u32,
}

Mach_x86_Unwind_Op :: enum {
	None = 0,
	Framed = 1,
	StackIndirect = 2,
	StackImmediate = 3,
	DWARF = 4,
}

Mach_ARM_Unwind_Op :: enum {
	None = 0,
	Frameless = 2,
	DWARF = 3,
	Framed = 4,
}

fmt_macho_debug_id :: proc(uuid: [16]u8) -> string {
	return fmt.tprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		uuid[0], uuid[1], uuid[2], uuid[3], uuid[4],
		uuid[5], uuid[6], uuid[7], uuid[8], uuid[9],
		uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15],
	)
}

guess_debug_path :: proc(file_path: string) -> string {
	file_base := filepath.base(file_path)
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, file_path)
	strings.write_string(&b, ".dSYM/Contents/Resources/DWARF/")
	strings.write_string(&b, file_base)
	
	return strings.to_string(b)
}

patch_symbol_ends :: proc(trace: ^Trace, bucket: ^Func_Bucket, text_seg_end: u64) {
	slice.sort_by(bucket.functions[:], fast_func_order)

	for &function, idx in bucket.functions {
		if idx == 0 {
			continue
		}

		prev_func := &bucket.functions[idx - 1]
		prev_high_addr := function.low_pc - 1
		prev_func.high_pc = prev_high_addr
		bucket.scopes.high_pc = max(bucket.scopes.high_pc, prev_high_addr)

		str := in_getstr(&trace.string_block, prev_func.name)
		//fmt.printf("0x%08x -> 0x%08x | %s\n", prev_func.low_pc, prev_func.high_pc, str)
	}

	if len(bucket.functions) > 0 {
		last_func := &bucket.functions[len(bucket.functions)-1]
		high_addr := text_seg_end
		last_func.high_pc = high_addr
		bucket.scopes.high_pc = max(bucket.scopes.high_pc, high_addr)
	}
}

load_macho_symbols :: proc(trace: ^Trace, bucket: ^Func_Bucket, symbol_table: []Mach_Symbol_Entry_64, string_table: []u8, text_segment_offset: u64, text_seg_start: u64, text_seg_end: u64, scratch_buffer: []u8) -> bool {
	for symbol in symbol_table {
		symbol_name := string(cstring(raw_data(string_table[symbol.string_table_idx:])))

		if symbol_name == "" || symbol.value == 0 {
			continue
		}

		sym_addr := bucket.base_address + symbol.value - text_segment_offset
		if !val_in_range(sym_addr, text_seg_start, text_seg_end) {
			continue
		}

		bucket.scopes.low_pc = min(bucket.scopes.low_pc, sym_addr)
		demangled_name, ok := demangle_symbol(symbol_name, scratch_buffer)
		if !ok {
			return false
		}

		sym_idx := in_get(&trace.intern, &trace.string_block, demangled_name)
		non_zero_append(&bucket.functions, Function{name = sym_idx, low_pc = sym_addr, high_pc = sym_addr})
	}

	patch_symbol_ends(trace, bucket, text_seg_end)
	return true
}

load_macho :: proc(trace: ^Trace, _exec_buffer: []u8, bucket: ^Func_Bucket) -> bool {
	exec_buffer := _exec_buffer
	if len(exec_buffer) < size_of(Mach_Header_64) {
		return false
	}

	read_idx := 0
	magic := slice_to_type(exec_buffer, u32) or_return
	if magic == MACH_FAT_CIGAM {
		header := slice_to_type(exec_buffer[read_idx:], Mach_Fat_Header) or_return
		read_idx += size_of(header)

		header.fat_arch_count = intrinsics.byte_swap(header.fat_arch_count)

		for i := 0; i < int(header.fat_arch_count); i += 1 {
			arch_header := slice_to_type(exec_buffer[read_idx:], Mach_Fat_Arch_Header) or_return
			read_idx += size_of(arch_header)

			arch_header.cpu_type = intrinsics.byte_swap(arch_header.cpu_type)
			arch_header.cpu_subtype = intrinsics.byte_swap(arch_header.cpu_subtype)
			arch_header.offset = intrinsics.byte_swap(arch_header.offset)
			arch_header.size = intrinsics.byte_swap(arch_header.size)
			arch_header.align = intrinsics.byte_swap(arch_header.align)

			if arch_header.cpu_type == MACH_CPU_TYPE_X86_64 || arch_header.cpu_type == MACH_CPU_TYPE_ARM64 {
				exec_buffer = exec_buffer[arch_header.offset:]
				read_idx = 0
				break
			}
		}
	}

	header := slice_to_type(exec_buffer[read_idx:], Mach_Header_64) or_return
	if !(header.file_type == MACH_FILETYPE_EXEC || header.file_type == MACH_FILETYPE_DYLIB) {
		return false
	}
	if header.magic != MACH_MAGIC_64 {
		fmt.printf("we don't handle big endian mach files\n")
		return false
	}
	read_idx += size_of(header)

	symtab_header := Mach_Symtab_Command{}
	text_segment_offset : u64 = max(u64)

	for read_idx < len(exec_buffer) {
		current_buffer := exec_buffer[read_idx:]
		cmd := slice_to_type(current_buffer, Mach_Load_Command) or_return
		if cmd.size == 0 {
			return false
		}

		if cmd.type == .Segment_64 {
			segment_header := slice_to_type(current_buffer, Mach_Segment_64_Command) or_return
			segment_name := strings.string_from_null_terminated_ptr(raw_data(segment_header.name[:]), 16)
			if segment_name == "__TEXT" {
				text_segment_offset = segment_header.address
			}
		}

		if cmd.type == .Symtab {
			symtab_header = slice_to_type(current_buffer, Mach_Symtab_Command) or_return
			break
		}

		read_idx += int(cmd.size)
	}
	if read_idx >= len(exec_buffer) {
		return false
	}
	if text_segment_offset == max(u64) {
		return false
	}

	symbol_table_size := symtab_header.symbol_count * size_of(Mach_Symbol_Entry_64)
	if len(exec_buffer) < int(symtab_header.symbol_table_offset + symbol_table_size) ||
	   len(exec_buffer) < int(symtab_header.string_table_offset + symtab_header.string_table_size) {
		return false
	}

	tmp_buffer := make([]u8, 1024*1024, context.temp_allocator)
	symbol_table := transmute([]Mach_Symbol_Entry_64)exec_buffer[symtab_header.symbol_table_offset:][:symbol_table_size]
	string_table := exec_buffer[symtab_header.string_table_offset:][:symtab_header.string_table_size]
	return true //load_macho_symbols(trace, bucket, symbol_table, string_table, text_segment_offset, tmp_buffer)
}

load_macho_debug :: proc(trace: ^Trace, exec_buffer: []u8, bucket: ^Func_Bucket) -> bool {
	if len(exec_buffer) < size_of(Mach_Header_64) {
		return false
	}

	header := slice_to_type(exec_buffer, Mach_Header_64) or_return
	if header.file_type != MACH_FILETYPE_DSYM {
		return false
	}

	sections := Sections{}

	text_segment_offset : u64 = 0
	read_idx := size_of(Mach_Header_64)
	for read_idx < len(exec_buffer) {
		current_buffer := exec_buffer[read_idx:]
		cmd := slice_to_type(exec_buffer[read_idx:], Mach_Load_Command) or_return
		if cmd.size == 0 {
			return false
		}

		if cmd.type == .Segment_64 {
			segment_header := slice_to_type(exec_buffer[read_idx:], Mach_Segment_64_Command) or_return
			segment_name := strings.string_from_null_terminated_ptr(raw_data(segment_header.name[:]), 16)
			if segment_name == "__TEXT" {
				text_segment_offset = segment_header.address
			}

			if segment_name == "__DWARF" {

				sub_idx := read_idx + size_of(Mach_Segment_64_Command)
				end_idx := read_idx + int(cmd.size)
				for sub_idx < end_idx {
					section := slice_to_type(exec_buffer[sub_idx:], Mach_Section) or_return
					section_name := strings.string_from_null_terminated_ptr(raw_data(section.name[:]), 16)

					switch section_name {
					case "__debug_line":
						sections.line        = create_subbuffer(exec_buffer, u64(section.offset), section.size) or_return
					case "__debug_str":
						sections.debug_str   = create_subbuffer(exec_buffer, u64(section.offset), section.size) or_return
					case "__debug_str_offs":
						sections.str_offsets = create_subbuffer(exec_buffer, u64(section.offset), section.size) or_return
					case "__debug_line_str":
						sections.line_str    = create_subbuffer(exec_buffer, u64(section.offset), section.size) or_return
					case "__debug_info":
						sections.info        = create_subbuffer(exec_buffer, u64(section.offset), section.size) or_return
					case "__debug_abbrev":
						sections.abbrev      = create_subbuffer(exec_buffer, u64(section.offset), section.size) or_return
					case "__debug_addr":
						sections.addr        = create_subbuffer(exec_buffer, u64(section.offset), section.size) or_return
					case "__debug_ranges":
						sections.ranges      = create_subbuffer(exec_buffer, u64(section.offset), section.size) or_return
					case "__debug_rnglists":
						sections.rnglists    = create_subbuffer(exec_buffer, u64(section.offset), section.size) or_return
					case "__unwind_info":
						sections.unwind_info = create_subbuffer(exec_buffer, u64(section.offset), section.size) or_return
					}

					sub_idx += size_of(Mach_Section)
				}
				break
			}
		}

		read_idx += int(cmd.size)
	}
	if read_idx >= len(exec_buffer) {
		return false
	}
	if text_segment_offset == 0 {
		return false
	}

	if !load_dwarf(trace, &sections, bucket, text_segment_offset) {
		fmt.printf("DWARF parsing failed!\n")
	}

	return true
}
