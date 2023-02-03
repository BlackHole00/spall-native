package main

import "core:fmt"
import "core:os"
import "core:bytes"

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

MACH_CMD_SYMTAB :: 2
Mach_Load_Command :: struct #packed {
	type: u32,
	size: u32,
}

Mach_Symtab_Command :: struct #packed {
	type:                u32,
	size:                u32,
	symbol_table_offset: u32,
	symbol_count:        u32,
	string_table_offset: u32,
	string_table_size:   u32,
}

Mach_Symbol_Entry_64 :: struct #packed {
	string_table_idx: u32,
	type: u8,
	section_count: u8,
	description: u16,
	value: u64,
}

ELF_Header_64 :: struct #packed {
	magic:        [16]u8,
	type:            u16,
	machine:         u16,
	version:         u32,
	entry:           u64,
	program_header_offset:  u64,
	section_header_offset:  u64,
	flags:           u32,
	elf_header_size:             u16,
	program_header_entry_size:   u16,
	program_header_count:        u16,
	section_header_entry_size:   u16,
	section_header_count:        u16,
	section_header_strtable_idx: u16,
}

ELF_Section_Header_64 :: struct #packed {
	name:       u32,
	type:       u32,
	flags:      u64,
	addr:       u64,
	offset:     u64,
	size:       u64,
	link:       u32,
	info:       u32,
	addr_align: u64,
	entry_size: u64,
}

STT_FUNC :: 2
ELF_Sym_64 :: struct #packed {
	name:            u32,
	info:             u8,
	other:            u8,
	section_hdr_idx: u16,
	value:           u64,
	size:            u64,
}

ELF_MAGIC     := []u8{ 0x7f, 'E', 'L', 'F' }
MACH_MAGIC_64 :: 0xfeedfacf
PE32_MAGIC    := []u8{ 0x5a, 0x4d }

load_executable :: proc(trace: ^Trace, file_name: string) -> bool {
	fmt.printf("Loading symbols from %s\n", file_name)

	exec_buffer, ok := os.read_entire_file_from_filename(file_name)
	if !ok {
		post_error(trace, "Failed to load %s!", file_name)
		return false
	}
	if len(exec_buffer) < 4 {
		post_error(trace, "Invalid executable file!")
		return false
	}

	magic_chunk := (^u32)(raw_data(exec_buffer[:4]))^
	if bytes.equal(exec_buffer[:4], ELF_MAGIC) {
		ok := load_elf(trace, exec_buffer)
		if !ok {
			post_error(trace, "Failed to parse ELF!")
			return false
		}
	} else if magic_chunk == MACH_MAGIC_64 {
		ok := load_macho(trace, exec_buffer)
		if !ok {
			post_error(trace, "Failed to parse Mach-O!")
			return false
		}
	} else if bytes.equal(exec_buffer[:2], PE32_MAGIC) {
		ok := load_pe32(trace, exec_buffer)
		if !ok {
			post_error(trace, "Failed to parse PE32!")
			return false
		}
	} else {
		post_error(trace, "Unsupported executable type! %x %x", exec_buffer[:4], MACH_MAGIC_64)
		return false
	}

	fmt.printf("Loaded %d symbols!\n", len(trace.addr_map.entries))

	return true
}

load_macho :: proc(trace: ^Trace, exec_buffer: []u8) -> bool {
	if len(exec_buffer) < size_of(Mach_Header_64) {
		return false
	}

	header := (^Mach_Header_64)(raw_data(exec_buffer[:size_of(Mach_Header_64)]))
	if header.file_type != 2 {
		return false
	}

	symtab_header := Mach_Symtab_Command{}

	read_idx := size_of(Mach_Header_64)
	for read_idx < len(exec_buffer) {
		current_buffer := exec_buffer[read_idx:]
		cmd := (^Mach_Load_Command)(raw_data(current_buffer[:size_of(Mach_Load_Command)]))
		if cmd.size == 0 {
			return false
		}

		if cmd.type == MACH_CMD_SYMTAB {
			symtab_header = (^Mach_Symtab_Command)(raw_data(current_buffer[:size_of(Mach_Symtab_Command)]))^
			break
		} 

		read_idx += int(cmd.size)
	}
	if read_idx >= len(exec_buffer) {
		return false
	}
	
	symbol_table_size := symtab_header.symbol_count * size_of(Mach_Symbol_Entry_64)
	if len(exec_buffer) < int(symtab_header.symbol_table_offset + symbol_table_size) ||
	   len(exec_buffer) < int(symtab_header.string_table_offset + symtab_header.string_table_size) {
		return false
	}

	skew_size : u64 = 0
	symbol_table_bytes := exec_buffer[symtab_header.symbol_table_offset:]
	string_table_bytes := exec_buffer[symtab_header.string_table_offset:]
	for i := 0; i < int(symtab_header.symbol_count); i += 1 {
		symbol_buffer := exec_buffer[int(symtab_header.symbol_table_offset)+(i * size_of(Mach_Symbol_Entry_64)):]
		symbol := (^Mach_Symbol_Entry_64)(raw_data(symbol_buffer[:size_of(Mach_Symbol_Entry_64)]))
		symbol_name := string(transmute(cstring)raw_data(string_table_bytes[symbol.string_table_idx:]))

		if symbol_name == "_spall_auto_init" {
			skew_size = trace.skew_address - u64(symbol.value)
			break
		}
	}

	for i := 0; i < int(symtab_header.symbol_count); i += 1 {
		symbol_buffer := exec_buffer[int(symtab_header.symbol_table_offset)+(i * size_of(Mach_Symbol_Entry_64)):]
		symbol := (^Mach_Symbol_Entry_64)(raw_data(symbol_buffer[:size_of(Mach_Symbol_Entry_64)]))
		symbol_name := string(transmute(cstring)raw_data(string_table_bytes[symbol.string_table_idx:]))

		if symbol.value != 0 {
			interned_symbol := in_get(&trace.intern, &trace.string_block, symbol_name)

			symbol_addr := symbol.value + skew_size
			am_insert(&trace.addr_map, symbol_addr, interned_symbol)
		}
	}

	return true
}

load_elf :: proc(trace: ^Trace, exec_buffer: []u8) -> bool {
	if len(exec_buffer) < size_of(ELF_Header_64) {
		return false
	}

	elf_header := (^ELF_Header_64)(raw_data(exec_buffer[:size_of(ELF_Header_64)]))
	section_header := (^ELF_Section_Header_64)(raw_data(exec_buffer[elf_header.section_header_offset:elf_header.section_header_offset+size_of(ELF_Section_Header_64)]))

	strtable_offset := elf_header.section_header_offset + (size_of(ELF_Section_Header_64) * u64(elf_header.section_header_strtable_idx))
	section_strtable_header := (^ELF_Section_Header_64)(raw_data(exec_buffer[strtable_offset:strtable_offset+size_of(ELF_Section_Header_64)]))
	strtable := exec_buffer[section_strtable_header.offset:]

	symbol_table_idx : u64 = 0
	symbol_table_str_idx : u64 = 0
	i : u64 = 0
	for ; i < u64(elf_header.section_header_count); i += 1 {
		section_offset := elf_header.section_header_offset + (size_of(ELF_Section_Header_64) * i)
		cur_hdr := (^ELF_Section_Header_64)(raw_data(exec_buffer[section_offset:section_offset+size_of(ELF_Section_Header_64)]))

		section_name := string(transmute(cstring)raw_data(strtable[cur_hdr.name:]))
		if section_name == ".symtab" {
			symbol_table_idx = i
			symbol_table_str_idx = u64(cur_hdr.link)
			break
		}
	}
	if i == u64(elf_header.section_header_count) {
		return false
	}

	symbol_table_offset := elf_header.section_header_offset + (size_of(ELF_Section_Header_64) * u64(symbol_table_idx))
	symbol_table_str_offset := elf_header.section_header_offset + (size_of(ELF_Section_Header_64) * u64(symbol_table_str_idx))
	symbol_table := (^ELF_Section_Header_64)(raw_data(exec_buffer[symbol_table_offset:symbol_table_offset+size_of(ELF_Section_Header_64)]))
	symbol_str_table := (^ELF_Section_Header_64)(raw_data(exec_buffer[symbol_table_str_offset:symbol_table_str_offset+size_of(ELF_Section_Header_64)]))

	skew_size : u64 = 0
	for i = 0; i < symbol_table.size; i += symbol_table.entry_size {
		symbol_offset := symbol_table.offset + i
		symbol := (^ELF_Sym_64)(raw_data(exec_buffer[symbol_offset:symbol_offset+size_of(ELF_Sym_64)]))

        type := u8(symbol.info & 0xf)
		symbol_name := string(transmute(cstring)raw_data(exec_buffer[symbol_str_table.offset+u64(symbol.name):]))
        if type != STT_FUNC || symbol.value == 0 {
            continue;
        }

		if symbol_name == "spall_auto_init" {
			skew_size = trace.skew_address - u64(symbol.value)
			fmt.printf("Found address to skew! %x, %x\n", symbol.value, skew_size)
			break
		}
	}

	for i = 0; i < symbol_table.size; i += symbol_table.entry_size {
		symbol_offset := symbol_table.offset + i
		symbol := (^ELF_Sym_64)(raw_data(exec_buffer[symbol_offset:symbol_offset+size_of(ELF_Sym_64)]))

        type := u8(symbol.info & 0xf)
        if type != STT_FUNC || symbol.value == 0 {
            continue;
        }

		symbol_name := string(transmute(cstring)raw_data(exec_buffer[symbol_str_table.offset+u64(symbol.name):]))
		interned_symbol := in_get(&trace.intern, &trace.string_block, symbol_name)

		symbol_addr := symbol.value + skew_size
		am_insert(&trace.addr_map, symbol_addr, interned_symbol)
	}

	return true
}

load_pe32 :: proc(trace: ^Trace, exec_buffer: []u8) -> bool {
	return false
}
