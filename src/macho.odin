package main

import "base:intrinsics"

import "core:fmt"
import "core:strings"
import "core:path/filepath"

MACH_FAT_MAGIC :: 0xcafebebe
MACH_FAT_CIGAM :: 0xbebafeca
MACH_MAGIC_64  :: 0xfeedfacf

MACH_CPU_ABI_64      :: 0x1000000
MACH_CPU_TYPE_I386   :: 7
MACH_CPU_TYPE_X86_64 :: MACH_CPU_TYPE_I386 | MACH_CPU_ABI_64
MACH_CPU_TYPE_ARM    :: 12
MACH_CPU_TYPE_ARM64  :: MACH_CPU_TYPE_ARM | MACH_CPU_ABI_64
MACH_CMD_SYMTAB      :: 0x2
MACH_CMD_SEGMENT_64  :: 0x19
MACH_CMD_UUID        :: 0x1B
MACH_FILETYPE_EXEC   :: 2
MACH_FILETYPE_DYLIB  :: 6
MACH_FILETYPE_DSYM   :: 10
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
	type: u32,
	size: u32,
}

Mach_Segment_64_Command :: struct #packed {
	type:                u32,
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
	type:                u32,
	size:                u32,
	symbol_table_offset: u32,
	symbol_count:        u32,
	string_table_offset: u32,
	string_table_size:   u32,
}

Mach_UUID_Command :: struct #packed {
	type:    u32,
	size:    u32,
	uuid: [16]u8,
}

Mach_Symbol_Entry_64 :: struct #packed {
	string_table_idx: u32,
	type: u8,
	section_count: u8,
	description: u16,
	value: u64,
}

fmt_macho_debug_id :: proc(uuid: [16]u8) -> string {
	return fmt.tprintf("%X%X%X%X-%X%X-%X%X-%X%X-%X%X%X%X%X%X",
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

load_macho_symbols :: proc(trace: ^Trace, _exec_buffer: []u8, bucket: ^Func_Bucket) -> bool {
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

		if cmd.type == MACH_CMD_SEGMENT_64 {
			segment_header := slice_to_type(current_buffer, Mach_Segment_64_Command) or_return
			segment_name := strings.string_from_null_terminated_ptr(raw_data(segment_header.name[:]), 16)
			if segment_name == "__TEXT" {
				text_segment_offset = segment_header.address
			}
		}

		if cmd.type == MACH_CMD_SYMTAB {
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
	symbol_table_bytes := exec_buffer[symtab_header.symbol_table_offset:]
	string_table_bytes := exec_buffer[symtab_header.string_table_offset:]
	for i := 0; i < int(symtab_header.symbol_count); i += 1 {
		symbol_buffer := exec_buffer[int(symtab_header.symbol_table_offset)+(i * size_of(Mach_Symbol_Entry_64)):]
		symbol := slice_to_type(symbol_buffer, Mach_Symbol_Entry_64) or_return
		symbol_name := string(cstring(raw_data(string_table_bytes[symbol.string_table_idx:])))

		if symbol_name == "" || symbol.value == 0 {
			continue
		}

		demangled_name, ok2 := demangle_symbol(symbol_name, tmp_buffer)
		if !ok2 {
			return false
		}
/*
		sym_idx := in_get(&trace.intern, &trace.string_block, demangled_name)
		sym_addr := bucket.base_address + symbol.value - text_segment_offset
		if len(bucket.functions) > 1 {
			prev_func := &bucket.functions[len(bucket.functions) - 1]
			prev_func.high_pc = sym_addr - 1
			str := in_getstr(&trace.string_block, prev_func.name)
			//fmt.printf("0x%08x - 0x%08x | %s\n", prev_func.low_pc, prev_func.high_pc, str)
		}
		non_zero_append(&bucket.functions, Function{name = sym_idx, low_pc = sym_addr, high_pc = sym_addr})
*/
	}

	return true
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

		if cmd.type == MACH_CMD_SEGMENT_64 {
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
