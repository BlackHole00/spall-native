package main

import "core:os"
import "core:fmt"
import "core:strings"
import "core:slice"

Dw_Form :: enum {
	addr           = 0x01,
	block2         = 0x03,
	block4         = 0x04,
	data2          = 0x05,
	data4          = 0x06,
	data8          = 0x07,
	str            = 0x08,
	block          = 0x09,
	block1         = 0x0a,
	data1          = 0x0b,
	flag           = 0x0c,
	sdata          = 0x0d,
	strp           = 0x0e,
	udata          = 0x0f,
	ref_addr       = 0x10,
	ref1           = 0x11,
	ref2           = 0x12,
	ref4           = 0x13,
	ref8           = 0x14,
	ref_udata      = 0x15,
	indirect       = 0x16,
	sec_offset     = 0x17,
	exprloc        = 0x18,
	flag_present   = 0x19,

	strx           = 0x1a,
	ref_sup4       = 0x1c,
	strp_sup       = 0x1d,
	data16         = 0x1e,
	line_strp      = 0x1f,
	ref_sig8       = 0x20,
	implicit_const = 0x21,
	loclistx       = 0x22,
	rnglistx       = 0x23,
	ref_sup8       = 0x24,
	strx1          = 0x25,
	strx2          = 0x26,
	strx3          = 0x27,
	strx4          = 0x28,
	addrx1         = 0x29,
	addrx2         = 0x2a,
	addrx3         = 0x2b,
	addrx4         = 0x2c,
}

Dw_LNCT :: enum u8 {
	path            = 1,
	directory_index = 2,
	timestamp       = 3,
	size            = 4,
	md5             = 5,
}

Dw_LNS :: enum u8 {
	extended           = 0x0,
	copy               = 0x1,
	advance_pc         = 0x2,
	advance_line       = 0x3,
	set_file           = 0x4,
	set_column         = 0x5,
	negate_stmt        = 0x6,
	set_basic_block    = 0x7,
	const_add_pc       = 0x8,
	fixed_advance_pc   = 0x9,
	set_prologue_end   = 0xa,
	set_epilogue_begin = 0xb,
}

Dw_Line :: enum u8 {
	end_sequence      = 0x1,
	set_address       = 0x2,
	set_discriminator = 0x4,
}

DWARF32_V5_Line_Header :: struct #packed {
	address_size:           u8,
	segment_selector_size:  u8,
	header_length:         u32,
	min_inst_length:        u8,
	max_ops_per_inst:       u8,
	default_is_stmt:        u8,
	line_base:              i8,
	line_range:             u8,
	opcode_base:            u8,
}

DWARF32_V4_Line_Header :: struct #packed {
	header_length:   u32,
	min_inst_length:  u8,
	max_ops_per_inst: u8,
	default_is_stmt:  u8,
	line_base:        i8,
	line_range:       u8,
	opcode_base:      u8,
}

DWARF32_V3_Line_Header :: struct #packed {
	header_length:   u32,
	min_inst_length:  u8,
	default_is_stmt:  u8,
	line_base:        i8,
	line_range:       u8,
	opcode_base:      u8,
}

DWARF_Line_Header :: struct {
	header_length:        u32,
	address_size:          u8,
	segment_selector_size: u8,
	min_inst_length:       u8,
	max_ops_per_inst:      u8,
	default_is_stmt:       u8,
	line_base:             i8,
	line_range:            u8,
	opcode_base:           u8,
}

LineFmtEntry :: struct {
	content: Dw_LNCT,
	form: Dw_Form,
}

File_Unit :: struct {
	name:    string,
	dir_idx:    int,
}

Line_Machine :: struct {
	address:         u64,
	op_idx:          u32,
	file_idx:        u32,
	line_num:        u32,
	col_num:         u32,
	is_stmt:        bool,
	basic_block:    bool,
	end_sequence:   bool,
	prologue_end:   bool,
	epilogue_end:   bool,
	epilogue_begin: bool,
	isa:             u32,
	discriminator:   u32,
}

Line_Table :: struct {
	op_buffer:       []u8,
	default_is_stmt: bool,
	line_base:         i8,
	line_range:        u8,
	opcode_base:       u8,

	lines: []Line_Machine,
}

Line_Info :: struct {
	address:  u64,
	is_func_frame_start: bool,
	is_func_frame_end:   bool,
	line_num: u32,
	col_num:  u32,
	file_idx: u32,
}

CU_Unit :: struct {
	dir_table:    [dynamic]string,
	file_table:   [dynamic]File_Unit,
	line_info:    [dynamic]Line_Info,
	line_table:   Line_Table,
}

DWARF_Context :: struct {
	bits_64: bool,
	version: int,
}

parse_line_header :: proc(ctx: ^DWARF_Context, blob: []u8) -> (DWARF_Line_Header, int, bool) {
	common_hdr := DWARF_Line_Header{}
	switch ctx.version {
		case 5:
			hdr, ok := slice_to_type(blob, DWARF32_V5_Line_Header)
			if !ok {
				return {}, 0, false
			}

			common_hdr.header_length         = hdr.header_length
			common_hdr.address_size          = hdr.address_size
			common_hdr.segment_selector_size = hdr.segment_selector_size
			common_hdr.min_inst_length       = hdr.min_inst_length
			common_hdr.max_ops_per_inst      = hdr.max_ops_per_inst
			common_hdr.default_is_stmt       = hdr.default_is_stmt
			common_hdr.line_base             = hdr.line_base
			common_hdr.line_range            = hdr.line_range
			common_hdr.opcode_base           = hdr.opcode_base

			return common_hdr, size_of(hdr), true
		case 4:
			hdr, ok := slice_to_type(blob, DWARF32_V4_Line_Header)
			if !ok {
				return {}, 0, false
			}

			common_hdr.header_length         = hdr.header_length
			common_hdr.address_size          = 4
			common_hdr.segment_selector_size = 0
			common_hdr.min_inst_length       = hdr.min_inst_length
			common_hdr.max_ops_per_inst      = hdr.max_ops_per_inst
			common_hdr.default_is_stmt       = hdr.default_is_stmt
			common_hdr.line_base             = hdr.line_base
			common_hdr.line_range            = hdr.line_range
			common_hdr.opcode_base           = hdr.opcode_base

			return common_hdr, size_of(hdr), true
		case 3:
			hdr, ok := slice_to_type(blob, DWARF32_V3_Line_Header)
			if !ok {
				return {}, 0, false
			}

			common_hdr.header_length         = hdr.header_length
			common_hdr.address_size          = 4
			common_hdr.segment_selector_size = 0
			common_hdr.min_inst_length       = hdr.min_inst_length
			common_hdr.max_ops_per_inst      = 0
			common_hdr.default_is_stmt       = hdr.default_is_stmt
			common_hdr.line_base             = hdr.line_base
			common_hdr.line_range            = hdr.line_range
			common_hdr.opcode_base           = hdr.opcode_base

			return common_hdr, size_of(hdr), true
		case:
			return {}, 0, false
	}
}

read_uleb :: proc(buffer: []u8) -> (u64, int, bool) {
	val    : u64 = 0
	offset := 0
	size   := 1

	for i := 0; i < 8; i += 1 {
		b := buffer[i]

		val = val | u64(b & 0x7F) << u64(offset * 7)
		offset += 1

		if b < 128 {
			return val, size, true
		}

		size += 1
	}

	return 0, 0, false
}

read_ileb :: proc(buffer: []u8) -> (i64, int, bool) {
	val    : i64 = 0
	offset := 0
	size   := 1

	for i := 0; i < 8; i += 1 {
		b := buffer[i]

		val = val | i64(b & 0x7F) << u64(offset * 7)
		offset += 1

		if b < 128 {
			if (b & 0x40) == 0x40 {
				val |= max(i64) << u64(offset * 7)
			}

			return val, size, true
		}

		size += 1
	}

	return 0, 0, false
}

load_dwarf :: proc(trace: ^Trace, line_buffer, line_str_buffer, abbrev_buffer, info_buffer: []u8) -> bool {
	cu_list := make([dynamic]CU_Unit)

	pass := 1
	version : u16 = 0
	for i := 0; i < len(line_buffer); pass += 1 {
		fmt.printf("pass %v\n", pass)

		cu_start := i

		unit_length := slice_to_type(line_buffer[i:], u32) or_return
		if unit_length == 0xFFFF_FFFF { 
			fmt.printf("Only supporting DWARF32 for now!\n")
			return false 
		}
		i += size_of(unit_length)

		if unit_length == 0 { continue }

		version = slice_to_type(line_buffer[i:], u16) or_return
		if !(version == 3 || version == 4 || version == 5) {
			fmt.printf("Only supports DWARF 3, 4 and 5, got %d\n", version)
			return false
		}
		i += size_of(version)

		ctx := DWARF_Context{}
		ctx.bits_64 = false
		ctx.version = int(version)
		line_hdr, size := parse_line_header(&ctx, line_buffer[i:]) or_return
		i += size

		fmt.printf("parsing DWARF %v\n", version)
		fmt.printf("line header: %#v\n", line_hdr)

		if line_hdr.opcode_base != 13 {
			fmt.printf("Unable to support custom line table ops!\n")
			return false
		}

		// this is fun
		opcode_table_len := line_hdr.opcode_base - 1
		i += int(opcode_table_len)

		dir_table  := make([dynamic]string)
		file_table := make([dynamic]File_Unit)
		line_info  := make([dynamic]Line_Info)
		lt  := Line_Table{}

		if version == 5 {
			dir_entry_fmt_count := slice_to_type(line_buffer[i:], u8) or_return
			i += size_of(dir_entry_fmt_count)

			fmt_parse := [255]LineFmtEntry{}
			fmt_parse_len := 0
			for j := 0; j < int(dir_entry_fmt_count); j += 1 {
				content_type, size1 := read_uleb(line_buffer[i:]) or_return
				i += size1

				content_code := Dw_LNCT(content_type)

				form_type, size2 := read_uleb(line_buffer[i:]) or_return
				i += size2

				form_code := Dw_Form(form_type)

				fmt_parse[fmt_parse_len] = LineFmtEntry{content_code, form_code}
				fmt_parse_len += 1
			}

			dir_name_count, size2 := read_uleb(line_buffer[i:]) or_return
			i += size2

			for j := 0; j < int(dir_name_count); j += 1 {
				for k := 0; k < fmt_parse_len; k += 1 {

					def_block := fmt_parse[k]
					#partial switch def_block.content {
						case .path: {
							if def_block.form != .line_strp {
								fmt.printf("Unhandled line parser type! %v\n", def_block.form)
								return false
							}

							str_idx := slice_to_type(line_buffer[i:], u32) or_return

							cstr_dir_name := cstring(raw_data(line_str_buffer[str_idx:]))
							dir_name := strings.clone_from_cstring(cstr_dir_name)
							append(&dir_table, dir_name)

							i += size_of(u32)
						} case: {
							fmt.printf("Unhandled line parser type! %v\n", def_block.content)
							return false
						}
					}
				}
			}

			file_entry_fmt_count := slice_to_type(line_buffer[i:], u8) or_return
			i += size_of(file_entry_fmt_count)

			fmt_parse = {}
			fmt_parse_len = 0
			for j := 0; j < int(file_entry_fmt_count); j += 1 {
				content_type, size1 := read_uleb(line_buffer[i:]) or_return
				i += size1

				content_code := Dw_LNCT(content_type)

				form_type, size2 := read_uleb(line_buffer[i:]) or_return
				i += size2

				form_code := Dw_Form(form_type)

				fmt_parse[fmt_parse_len] = LineFmtEntry{content_code, form_code}
				fmt_parse_len += 1
			}

			file_name_count, size3 := read_uleb(line_buffer[i:]) or_return
			i += size3

			for j := 0; j < int(file_name_count); j += 1 {
				file := File_Unit{}
				for k := 0; k < fmt_parse_len; k += 1 {
					def_block := fmt_parse[k]
					#partial switch def_block.content {
						case .path: {
							if def_block.form != .line_strp {
								fmt.printf("Unhandled line parser type! %v\n", def_block.form)
								return false
							}

							str_idx := slice_to_type(line_buffer[i:], u32) or_return

							cstr_file_name := cstring(raw_data(line_str_buffer[str_idx:]))
							file.name = strings.clone_from_cstring(cstr_file_name)

							i += size_of(u32)
						} case .directory_index: {
							#partial switch def_block.form {
								case .data1: {
									dir_idx := slice_to_type(line_buffer[i:], u8) or_return
									file.dir_idx = int(dir_idx)
									i += size_of(u8)
								} case .data2: {
									dir_idx := slice_to_type(line_buffer[i:], u16) or_return
									file.dir_idx = int(dir_idx)
									i += size_of(u16)
								} case .udata: {
									dir_idx, size := read_uleb(line_buffer[i:]) or_return
									file.dir_idx = int(dir_idx)
									i += size
								} case: {
									fmt.printf("Invalid directory index size! %v\n", def_block.form)
									return false
								}
							}
						} case: {
							fmt.printf("Unhandled line parser type! %v\n", def_block.content)
							return false
						}
					}
				}

				append(&file_table, file)
			}

			full_cu_size := unit_length + size_of(unit_length)
			hdr_size := i - cu_start
			rem_size := int(full_cu_size) - hdr_size

			lt = Line_Table{
				op_buffer   = line_buffer[i:i+rem_size],
				opcode_base = line_hdr.opcode_base,
				line_base   = line_hdr.line_base,
				line_range  = line_hdr.line_range,
			}
			i += rem_size

		} else { // For DWARF 4, 3, 2, etc.
			append(&dir_table, ".")

			for {
				cstr_dir_name := cstring(raw_data(line_buffer[i:]))

				i += len(cstr_dir_name) + 1
				if len(cstr_dir_name) == 0 {
					break
				}

				dir_name := strings.clone_from_cstring(cstr_dir_name)
				append(&dir_table, dir_name)
			}

			for {
				cstr_file_name := cstring(raw_data(line_buffer[i:]))

				i += len(cstr_file_name) + 1
				if len(cstr_file_name) == 0 {
					break
				}

				dir_idx, size := read_uleb(line_buffer[i:]) or_return
				i += size

				last_modified, size2 := read_uleb(line_buffer[i:]) or_return
				i += size2

				file_size, size3 := read_uleb(line_buffer[i:]) or_return
				i += size3

				file_name := strings.clone_from_cstring(cstr_file_name)
				append(&file_table, File_Unit{name = file_name, dir_idx = int(dir_idx)})
			}

			full_cu_size := unit_length + size_of(unit_length)
			hdr_size := i - cu_start
			rem_size := int(full_cu_size) - hdr_size

			lt = Line_Table{
				op_buffer   = line_buffer[i:i+rem_size],
				opcode_base = line_hdr.opcode_base,
				line_base   = line_hdr.line_base,
				line_range  = line_hdr.line_range,
			}
			i += rem_size
		}

		append(&cu_list, CU_Unit{dir_table, file_table, line_info, lt})
	}

	for cu in &cu_list {
		line_table := &cu.line_table

		lm_state := Line_Machine{}
		lm_state.file_idx = 1
		lm_state.line_num = 1
		lm_state.is_stmt = line_table.default_is_stmt

		lines := make([dynamic]Line_Machine)
		for i := 0; i < len(line_table.op_buffer); {
			op_byte := line_table.op_buffer[i]
			i += 1

			if op_byte >= line_table.opcode_base {
				real_op := op_byte - line_table.opcode_base
				line_inc := int(line_table.line_base + i8(real_op % line_table.line_range))
				addr_inc := int(real_op / line_table.line_range)

				lm_state.line_num = u32(int(lm_state.line_num) + line_inc)
				lm_state.address  = u64(int(lm_state.address) + addr_inc)

				append(&lines, lm_state)

				lm_state.discriminator  = 0
				lm_state.basic_block    = false
				lm_state.prologue_end   = false
				lm_state.epilogue_begin = false

				continue
			}

			op := Dw_LNS(op_byte)
			if op == .extended {
				i += 1
				tmp := line_table.op_buffer[i]
				real_op := Dw_Line(tmp)
				i += 1

				#partial switch real_op {
					case .end_sequence: {
						lm_state.end_sequence = true
						append(&lines, lm_state)
					} case .set_address: {
						address := slice_to_type(line_table.op_buffer[i:], u64)
						lm_state.address = address
						lm_state.op_idx = 0
						i += size_of(address)
					} case .set_discriminator: {
						discr, size := read_uleb(line_table.op_buffer[i:]) or_return
						lm_state.discriminator = u32(discr)
						i += size_of(size)
					} case: {
						return false
					}
				}

				continue
			}

			#partial switch op {
				case .copy: {
					append(&lines, lm_state)

					lm_state.discriminator  = 0
					lm_state.basic_block    = false
					lm_state.prologue_end   = false
					lm_state.epilogue_begin = false
				} case .advance_pc: {
					addr_inc, size := read_uleb(line_table.op_buffer[i:]) or_return
					lm_state.address = lm_state.address + u64(addr_inc)
					i += size
				} case .advance_line: {
					line_inc, size := read_ileb(line_table.op_buffer[i:]) or_return
					lm_state.line_num = u32(int(lm_state.line_num) + int(line_inc))
					i += size
				} case .set_file: {
					file_idx, size := read_uleb(line_table.op_buffer[i:]) or_return
					lm_state.file_idx = u32(file_idx)
					i += size
				} case .set_column: {
					col_num, size := read_uleb(line_table.op_buffer[i:]) or_return
					lm_state.col_num = u32(col_num)
					i += size
				} case .negate_stmt: {
					lm_state.is_stmt = !lm_state.is_stmt
				} case .set_basic_block: {
					lm_state.basic_block = true
				} case .const_add_pc: {
					addr_inc := (255 - line_table.opcode_base) / line_table.line_range
					lm_state.address += u64(addr_inc)
				} case .fixed_advance_pc: {
					advance := slice_to_type(line_table.op_buffer[i:], u16)
					lm_state.address += u64(advance)
					i += size_of(advance)
				} case .set_epilogue_begin: {
					lm_state.epilogue_begin = true
				} case .set_prologue_end: {
					lm_state.prologue_end = true
				} case: {
					fmt.printf("Unsupported op %v\n", op)
					return false
				}
			}

			line_table.lines = lines[:]
		}
	}

	for cu in &cu_list {
		for line in &cu.line_table.lines {
			li := Line_Info{}
			li.address = line.address
			li.is_func_frame_start = line.prologue_end
			li.is_func_frame_end   = line.epilogue_begin
			li.line_num            = line.line_num
			li.col_num             = line.col_num
			li.file_idx            = line.file_idx
			append(&cu.line_info, li)
		}

		line_order :: proc(a, b: Line_Info) -> bool {
			return a.address < b.address
		}
		slice.sort_by(cu.line_info[:], line_order)

		for line in cu.line_info {
			fmt.printf("0x%x -- %s:%d\n", line.address, cu.file_table[line.file_idx].name, line.line_num)
		}
	}

	fmt.printf("success?\n")
	return false
}

