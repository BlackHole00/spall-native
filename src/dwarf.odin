package main

import "core:os"
import "core:fmt"

DWARF32_V5_Line_Header :: struct #packed {
	address_size:          u8,
	segment_selector_size: u8,
	min_inst_length:       u8,
	max_ops_per_inst:      u8,
	default_is_stmt:       u8,
	line_base:             i8,
	line_range:            u8,
	opcode_base:           u8,
}

DWARF32_V4_Line_Header :: struct #packed {
	min_inst_length:  u8,
	max_ops_per_inst: u8,
	default_is_stmt:  u8,
	line_base:        i8,
	line_range:       u8,
	opcode_base:      u8,
}

DWARF32_V3_Line_Header :: struct #packed {
	min_inst_length:  u8,
	default_is_stmt:  u8,
	line_base:        i8,
	line_range:       u8,
	opcode_base:      u8,
}

DWARF_Line_Header :: struct {
	address_size:          u8,
	segment_selector_size: u8,
	min_inst_length:       u8,
	max_ops_per_inst:      u8,
	default_is_stmt:       u8,
	line_base:             i8,
	line_range:            u8,
	opcode_base:           u8,
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

load_dwarf :: proc(trace: ^Trace, line_section: []u8) -> bool {
	if true do return true
	for i := 0; i < len(line_section); {
		unit_length := slice_to_type(line_section[i:], u32) or_return
		if unit_length == 0xFFFF_FFFF { return false }
		i += size_of(unit_length)

		if unit_length == 0 { continue }

		version := slice_to_type(line_section[i:], u16) or_return
		i += size_of(version)

		ctx := DWARF_Context{}
		ctx.bits_64 = false
		ctx.version = int(version)
		line_hdr, size := parse_line_header(&ctx, line_section[i:]) or_return
		i += size

		fmt.printf("version: %v\n", ctx.version)
		fmt.printf("%#v\n", line_hdr)
		if true { return false }
	}

	return false
}

