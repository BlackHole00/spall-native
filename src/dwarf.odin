package main

import "core:os"
import "core:fmt"
import "core:strings"
import "core:slice"
import "core:encoding/varint"

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
	addrx          = 0x1b,
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

Dw_Unit_Type :: enum u8 {
	none          = 0x0,
	compile       = 0x01,
	type          = 0x02,
	partial       = 0x03,
	skeleton      = 0x04,
	split_compile = 0x05,
	split_type    = 0x06,
	lo_user       = 0x80,
	hi_user       = 0xFF,
}

Dw_At :: enum {
	sibling            = 0x01,
	location           = 0x02,
	name               = 0x03,
	ordering           = 0x09,
	byte_size          = 0x0b,
	bit_offset         = 0x0c,
	bit_size           = 0x0d,
	stmt_list          = 0x10,
	low_pc             = 0x11,
	high_pc            = 0x12,
	language           = 0x13,
	discr              = 0x15,
	discr_value        = 0x16,
	visibility         = 0x17,
	imprt              = 0x18,
	string_length      = 0x19,
	common_ref         = 0x1a,
	comp_dir           = 0x1b,
	const_val          = 0x1c,
	containing_type    = 0x1d,
	default_type       = 0x1e,
	inline              = 0x20,
	is_optional        = 0x21,
	lower_bound        = 0x22,
	producer           = 0x25,
	prototyped         = 0x27,
	return_addr        = 0x2a,
	start_scope        = 0x2c,
	bit_stride         = 0x2e,
	upper_bound        = 0x2f,
	abstract_origin    = 0x31,
	accessibility      = 0x32,
	address_class      = 0x33,
	artificial         = 0x34,
	base_types         = 0x35,
	calling_convention = 0x36,
	count              = 0x37,
	data_mem_location  = 0x38,
	decl_column        = 0x39,
	decl_file          = 0x3a,
	decl_line          = 0x3b,
	declaration        = 0x3c,
	discr_list         = 0x3d,
	encoding           = 0x3e,
	external           = 0x3f,
	frame_base         = 0x40,
	friend             = 0x41,
	identifier_case    = 0x42,
	macro_info         = 0x43,
	namelist_item      = 0x44,
	priority           = 0x45,
	segment            = 0x46,
	specification      = 0x47,
	static_link        = 0x48,
	type               = 0x49,
	use_location       = 0x4a,
	variable_parameter = 0x4b,
	virtuality         = 0x4c,
	vtable_elem_loc    = 0x4d,
	allocated          = 0x4e,
	associated         = 0x4f,
	data_location      = 0x50,
	byte_stride        = 0x51,
	entry_pc           = 0x52,
	use_UTF8           = 0x53,
	extension          = 0x54,
	ranges             = 0x55,
	trampoline         = 0x56,
	call_column        = 0x57,
	call_file          = 0x58,
	call_line          = 0x59,
	description        = 0x5a,
	binary_scale       = 0x5b,
	decimal_scale      = 0x5c,
	small              = 0x5d,
	decimal_sign       = 0x5e,
	digit_count        = 0x5f,
	picture_string     = 0x60,
	mutable            = 0x61,
	threads_scaled     = 0x62,
	explicit           = 0x63,
	object_pointer     = 0x64,
	endianity          = 0x65,
	main_subprogram    = 0x6a,
	data_bit_offset    = 0x6b,
	const_expr         = 0x6c,
	enum_class         = 0x6d,
	linkage_name       = 0x6e,

	// DWARF 5
	string_length_bit_size  = 0x6f,
	string_length_byte_size = 0x70,
	rank               = 0x71,
	str_offsets_base   = 0x72,
	addr_base          = 0x73,
	rnglists_base      = 0x74,

	dwo_name           = 0x76,
	reference          = 0x77,
	rvalue_reference   = 0x78,
	macros             = 0x79,

	call_all_calls        = 0x7a,
	call_all_source_calls = 0x7b,
	call_all_tail_calls   = 0x7c,
	call_return_pc        = 0x7d,
	call_value            = 0x7e,
	call_origin           = 0x7f,
	call_parameter        = 0x80,
	call_pc               = 0x81,
	call_tail_call        = 0x82,
	call_target           = 0x83,
	call_target_clobbered = 0x84,
	call_data_location    = 0x85,
	call_data_value       = 0x86,

	noreturn           = 0x87,
	alignment          = 0x88,

	export_symbols     = 0x89,
	deleted            = 0x8a,
	defaulted          = 0x8b,
	loclists_base      = 0x8c,

	// GNU extensions
	GNU_template_name  = 0x2110,
	GNU_pubnames       = 0x2134,

	GNU_discriminator  = 0x2136,
	GNU_locviews       = 0x2137,
	GNU_entry_view     = 0x2138,
}

Dw_Tag :: enum {
	array_type         = 0x01,
	class_type         = 0x02,
	entry_point        = 0x03,
	enum_type          = 0x04,
	formal_parameter   = 0x05,
	imported_decl      = 0x08,
	label              = 0x0a,
	lexical_block      = 0x0b,
	member             = 0x0d,
	pointer_type       = 0x0f,
	ref_type           = 0x10,
	compile_unit       = 0x11,
	string_type        = 0x12,
	struct_type        = 0x13,
	subroutine_type    = 0x15,
	typedef            = 0x16,
	union_type         = 0x17,
	unspec_params      = 0x18,
	variant            = 0x19,
	common_block       = 0x1a,
	common_incl        = 0x1b,
	inheritance        = 0x1c,
	inlined_subroutine = 0x1d,
	module             = 0x1e,
	ptr_to_member_type = 0x1f,
	set_type           = 0x20,
	subrange_type      = 0x21,
	with_stmt          = 0x22,
	access_decl        = 0x23,
	base_type          = 0x24,
	catch_block        = 0x25,
	const_type         = 0x26,
	constant           = 0x27,
	enumerator         = 0x28,
	file_type          = 0x29,
	friend             = 0x2a,
	subprogram         = 0x2e,
	upper_bound        = 0x2f,
	template_value_parameter = 0x30,
	variable           = 0x34,
	volatile_type      = 0x35,
	dwarf_procedure    = 0x36,
	restrict_type      = 0x37,
	decl_column        = 0x39,
	imported_module    = 0x3a,
	unspecified_type   = 0x3b,
	rvalue_reference_type = 0x42,
	static_link        = 0x48,
	type               = 0x49,
	program            = 0xff,

	// GNU extensions
	GNU_template_parameter_parameter = 0x4106,
	GNU_template_parameter_pack      = 0x4107,
	GNU_formal_parameter_pack        = 0x4108,
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
	default_is_stmt:       bool,
	line_base:             i8,
	line_range:            u8,
	opcode_base:           u8,
}

DWARF32_V3_CU_Header :: struct #packed {
	abbrev_offset: u32,
	address_size: u8,
}

DWARF32_V4_CU_Header :: struct #packed {
	abbrev_offset: u32,
	address_size: u8,
}

DWARF32_V5_CU_Header :: struct #packed {
	unit_type: Dw_Unit_Type,
	address_size: u8,
	abbrev_offset: u32,
}

DWARF_CU_Header :: struct {
	unit_type: Dw_Unit_Type,
	address_size: u8,
	abbrev_offset: u32,
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
	op_idx:          u64,
	file_idx:        u64,
	line_num:        u64,
	col_num:         u64,
	is_stmt:        bool,
	basic_block:    bool,
	end_sequence:   bool,
	prologue_end:   bool,
	epilogue_end:   bool,
	epilogue_begin: bool,
	isa:             u64,
	discriminator:   u64,
}

Line_Table :: struct {
	op_buffer:       []u8,
	default_is_stmt: bool,
	line_base:         i8,
	line_range:        u8,
	opcode_base:       u8,

	lines: [dynamic]Line_Machine,
}

CU_Unit :: struct {
	dir_table:    [dynamic]string,
	file_table:   [dynamic]File_Unit,
	line_table:   Line_Table,
}

DWARF_Context :: struct {
	bits_64: bool,
	version: int,
}

Attr_Data :: union {
	[]u8,
	i64,
	u64,
	u32,
	u16,
	u8,
	string,
	cstring,
	bool,
}

Attr_Entry :: struct {
	form: Dw_Form,
	data: Attr_Data,
}

Abbrev_Unit :: struct {
	id: u64,
	offset: u64,
	type: Dw_Tag,

	has_children: bool,
	attrs_buf: []u8,
}

Sections :: struct {
	debug_str:   []u8,
	str_offsets: []u8,
	line:        []u8,
	line_str:    []u8,
	addr:        []u8,
	abbrev:      []u8,
	info:        []u8,
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
			common_hdr.default_is_stmt       = hdr.default_is_stmt == 1
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
			common_hdr.default_is_stmt       = hdr.default_is_stmt == 1
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
			common_hdr.default_is_stmt       = hdr.default_is_stmt == 1
			common_hdr.line_base             = hdr.line_base
			common_hdr.line_range            = hdr.line_range
			common_hdr.opcode_base           = hdr.opcode_base

			return common_hdr, size_of(hdr), true
		case:
			return {}, 0, false
	}
}

parse_cu_header :: proc(ctx: ^DWARF_Context, blob: []u8) -> (DWARF_CU_Header, int, bool) {
	common_hdr := DWARF_CU_Header{}
	switch ctx.version {
		case 5:
			hdr, ok := slice_to_type(blob, DWARF32_V5_CU_Header)
			if !ok {
				return {}, 0, false
			}

			common_hdr.unit_type = Dw_Unit_Type(hdr.unit_type)
			common_hdr.address_size = hdr.address_size
			common_hdr.abbrev_offset = hdr.abbrev_offset

			if common_hdr.unit_type != .compile {
				fmt.printf("Extra CU types not handled yet!\n")
				return {}, 0, false
			}

			return common_hdr, size_of(hdr), true
		case 4:
			hdr, ok := slice_to_type(blob, DWARF32_V4_CU_Header)
			if !ok {
				return {}, 0, false
			}

			common_hdr.address_size = hdr.address_size
			common_hdr.abbrev_offset = hdr.abbrev_offset

			return common_hdr, size_of(hdr), true
		case 3:
			hdr, ok := slice_to_type(blob, DWARF32_V3_CU_Header)
			if !ok {
				return {}, 0, false
			}

			common_hdr.address_size = hdr.address_size
			common_hdr.abbrev_offset = hdr.abbrev_offset

			return common_hdr, size_of(hdr), true
		case:
			return {}, 0, false
	}
}

parse_attr_data :: proc(form: Dw_Form, data, abbrev_buffer, str_buffer, str_offsets_buffer, line_str_buffer: []u8) -> (entry: Attr_Data, size: int, ok: bool) {
	#partial switch form {
	case Dw_Form.str:
		str := cstring(raw_data(data))

		return Attr_Data(str), len(str)+1, true
	case Dw_Form.strp:
		str_off := slice_to_type(data, u32) or_return
		str := cstring(raw_data(str_buffer[str_off:]))

		return Attr_Data(str), size_of(str_off), true
	case Dw_Form.line_strp:
		str_off := slice_to_type(data, u32) or_return
		str := cstring(raw_data(line_str_buffer[str_off:]))

		return Attr_Data(str), size_of(str_off), true
	case Dw_Form.strx1:
		str_off_idx := slice_to_type(data, u8) or_return
		str_off_off := str_off_idx * size_of(u32)
		str_off := slice_to_type(str_offsets_buffer[str_off_off:], u32) or_return
		str := cstring(raw_data(str_buffer[str_off:]))

		return Attr_Data(str), size_of(str_off_off), true
	case Dw_Form.strx2:
		str_off_idx := slice_to_type(data, u16) or_return
		str_off_off := str_off_idx * size_of(u32)
		str_off := slice_to_type(str_offsets_buffer[str_off_off:], u32) or_return
		str := cstring(raw_data(str_buffer[str_off:]))

		return Attr_Data(str), size_of(str_off_off), true
	case Dw_Form.loclistx:
		val, leb_size := read_uleb(data) or_return

		return Attr_Data(val), leb_size, true
	case Dw_Form.rnglistx:
		val, leb_size := read_uleb(data) or_return

		return Attr_Data(val), leb_size, true
	case Dw_Form.addrx:
		val, leb_size := read_uleb(data) or_return

		return Attr_Data(val), leb_size, true
	case Dw_Form.sec_offset:
		val := slice_to_type(data, u32) or_return

		return Attr_Data(val), size_of(val), true
	case Dw_Form.flag_present:
		return Attr_Data(bool(true)), 0, true
	case Dw_Form.addr:
		addr := slice_to_type(data, u64) or_return

		return Attr_Data(addr), size_of(addr), true
	case Dw_Form.ref_addr:
		addr := slice_to_type(data, u32) or_return
		return Attr_Data(addr), size_of(addr), true
	case Dw_Form.block1:
		length := slice_to_type(data, u8) or_return
		block := data[size_of(length):int(length)]

		return Attr_Data(block), size_of(length) + int(length), true
	case Dw_Form.block2:
		length := slice_to_type(data, u16) or_return
		block := data[size_of(length):int(length)]

		return Attr_Data(block), size_of(length) + int(length), true
	case Dw_Form.block4:
		length := slice_to_type(data, u32) or_return
		block := data[size_of(length):int(length)]

		return Attr_Data(block), size_of(length) + int(length), true
	case Dw_Form.data1:
		val := slice_to_type(data, u8) or_return

		return Attr_Data(val), size_of(val), true
	case Dw_Form.data2:
		val := slice_to_type(data, u16) or_return

		return Attr_Data(val), size_of(val), true
	case Dw_Form.data4:
		val := slice_to_type(data, u32) or_return

		return Attr_Data(val), size_of(val), true
	case Dw_Form.data8:
		val := slice_to_type(data, u64) or_return

		return Attr_Data(val), size_of(val), true
	case Dw_Form.udata:
		val, leb_size := read_uleb(data) or_return

		return Attr_Data(val), leb_size, true
	case Dw_Form.sdata:
		val, leb_size := read_ileb(data) or_return

		return Attr_Data(val), leb_size, true
	case Dw_Form.ref4:
		val := slice_to_type(data, u32) or_return

		return Attr_Data(val), size_of(val), true
	case Dw_Form.ref_udata:
		val, leb_size := read_uleb(data) or_return

		return Attr_Data(val), leb_size, true
	case Dw_Form.exprloc:
		expr_length, leb_size := read_uleb(data) or_return
		expr := data[leb_size:leb_size+int(expr_length)]

		return Attr_Data(expr), int(expr_length) + leb_size, true
	case Dw_Form.implicit_const:
		constval, leb_size := read_ileb(abbrev_buffer) or_return
		return Attr_Data(constval), leb_size, true
	case: panic("TODO Can't handle (%x) %s yet!\n", u64(form), form)
	}

	return
}

cleanup_au_offsets :: proc(au_off_map: ^map[int][dynamic]Abbrev_Unit) {
	for k, v in au_off_map {
		delete(v)
	}
	delete(au_off_map^)
}

cleanup_cu_list :: proc(cu_list: ^[dynamic]CU_Unit) {
	for cu in cu_list {
		delete(cu.dir_table)
		delete(cu.file_table)
		delete(cu.line_table.lines)
	}
}

load_dwarf :: proc(trace: ^Trace, sections: ^Sections, skew_size: u64) -> bool {
	debug_str_offsets := []u8{}
	if len(sections.str_offsets) > 0 {
		fmt.printf("DWARF: parsing debug_str_offset\n")
		i := 0

		unit_length, ok := slice_to_type(sections.str_offsets[i:], u32)
		if !ok {
			panic("%s\n", #location())
		}

		if unit_length == 0xFFFF_FFFF { 
			fmt.printf("Only supporting DWARF32 for now!\n")
			return false 
		}
		i += size_of(unit_length)

		version, ok2 := slice_to_type(sections.str_offsets[i:], u16)
		if !ok2 {
			panic("%s\n", #location())
		}
		if !(version == 5) {
			fmt.printf("Only supports DWARF 5, got %d!", version)
			return false
		}
		i += size_of(version)
		i += size_of(u16) // padding

		debug_str_offsets = sections.str_offsets[i:]
	}


	cu_list := make([dynamic]CU_Unit)
	defer cleanup_cu_list(&cu_list)

	version : u16 = 0
	fmt.printf("DWARF: parsing debug_line\n")
	for i := 0; i < len(sections.line); {
		cu_start := i

		unit_length, ok := slice_to_type(sections.line[i:], u32)
		if !ok {
			panic("%s\n", #location())
		}
		if unit_length == 0xFFFF_FFFF { 
			fmt.printf("Only supporting DWARF32 for now!\n")
			return false 
		}
		i += size_of(unit_length)

		if unit_length == 0 { continue }

		version, ok = slice_to_type(sections.line[i:], u16)
		if !ok {
			panic("%s\n", #location())
		}
		if !(version == 3 || version == 4 || version == 5) {
			fmt.printf("Only supports DWARF 3, 4 and 5, got %d\n", version)
			return false
		}
		i += size_of(version)

		ctx := DWARF_Context{}
		ctx.bits_64 = false
		ctx.version = int(version)
		line_hdr, size, ok3 := parse_line_header(&ctx, sections.line[i:])
		if !ok3 {
			panic("%s\n", #location())
		}
		i += size

		if line_hdr.opcode_base != 13 {
			fmt.printf("Unable to support custom line table ops!\n")
			return false
		}

		non_zero_append(&cu_list, CU_Unit{
			dir_table = make([dynamic]string),
			file_table = make([dynamic]File_Unit),
			line_table = Line_Table{
				lines = make([dynamic]Line_Machine),
			},
		})
		cu := &cu_list[len(cu_list) - 1]

		// this is fun
		opcode_table_len := line_hdr.opcode_base - 1
		i += int(opcode_table_len)

		if version == 5 {
			dir_entry_fmt_count, ok := slice_to_type(sections.line[i:], u8)
			if !ok {
				panic("%s\n", #location())
			}
			i += size_of(dir_entry_fmt_count)

			fmt_parse := [255]LineFmtEntry{}
			fmt_parse_len := 0
			for j := 0; j < int(dir_entry_fmt_count); j += 1 {
				content_type, size1, ok := read_uleb(sections.line[i:])
				if !ok {
					panic("%s\n", #location())
				}
				i += size1

				content_code := Dw_LNCT(content_type)

				form_type, size2, ok2 := read_uleb(sections.line[i:])
				if !ok2 {
					panic("%s\n", #location())
				}
				i += size2

				form_code := Dw_Form(form_type)

				fmt_parse[fmt_parse_len] = LineFmtEntry{content_code, form_code}
				fmt_parse_len += 1
			}

			dir_name_count, size2, ok2 := read_uleb(sections.line[i:])
			if !ok2 {
				panic("%s\n", #location())
			}
			i += size2

			for j := 0; j < int(dir_name_count); j += 1 {
				for k := 0; k < fmt_parse_len; k += 1 {

					def_block := fmt_parse[k]
					#partial switch def_block.content {
						case .path: {
							if def_block.form != .line_strp {
								fmt.printf("Unhandled path form! %v\n", def_block.form)
								return false
							}

							str_idx, ok := slice_to_type(sections.line[i:], u32)
							if !ok {
								panic("%s\n", #location())
							}

							cstr_dir_name := cstring(raw_data(sections.line_str[str_idx:]))
							non_zero_append(&cu.dir_table, string(cstr_dir_name))

							i += size_of(u32)
						} case: {
							fmt.printf("Unhandled line parser type! %v\n", def_block.content)
							return false
						}
					}
				}
			}

			file_entry_fmt_count, ok3 := slice_to_type(sections.line[i:], u8)
			if !ok3 {
				panic("%s\n", #location())
			}
			i += size_of(file_entry_fmt_count)

			fmt_parse = {}
			fmt_parse_len = 0
			for j := 0; j < int(file_entry_fmt_count); j += 1 {
				content_type, size, ok := read_uleb(sections.line[i:])
				if !ok {
					panic("%s\n", #location())
				}
				i += size

				content_code := Dw_LNCT(content_type)

				form_type, size2, ok2 := read_uleb(sections.line[i:])
				if !ok2 {
					panic("%s\n", #location())
				}
				i += size2

				form_code := Dw_Form(form_type)

				fmt_parse[fmt_parse_len] = LineFmtEntry{content_code, form_code}
				fmt_parse_len += 1
			}

			file_name_count, size3, ok4 := read_uleb(sections.line[i:])
			if !ok4 {
				panic("%s\n", #location())
			}
			i += size3

			for j := 0; j < int(file_name_count); j += 1 {
				file := File_Unit{}
				for k := 0; k < fmt_parse_len; k += 1 {
					def_block := fmt_parse[k]
					#partial switch def_block.content {
						case .path: {
							if def_block.form != .line_strp {
								fmt.printf("Unhandled path form! %v\n", def_block.form)
								return false
							}

							str_idx, ok := slice_to_type(sections.line[i:], u32)
							if !ok {
								panic("%s\n", #location())
							}

							cstr_file_name := cstring(raw_data(sections.line_str[str_idx:]))
							file.name = string(cstr_file_name)

							i += size_of(u32)
						} case .directory_index: {
							#partial switch def_block.form {
								case .data1: {
									dir_idx, ok := slice_to_type(sections.line[i:], u8)
									if !ok {
										panic("%s\n", #location())
									}
									file.dir_idx = int(dir_idx)
									i += size_of(u8)
								} case .data2: {
									dir_idx, ok := slice_to_type(sections.line[i:], u16)
									if !ok {
										panic("%s\n", #location())
									}
									file.dir_idx = int(dir_idx)
									i += size_of(u16)
								} case .udata: {
									dir_idx, size, ok := read_uleb(sections.line[i:])
									if !ok {
										panic("%s\n", #location())
									}
									file.dir_idx = int(dir_idx)
									i += size
								} case: {
									fmt.printf("Invalid directory index size! %v\n", def_block.form)
									return false
								}
							}
						} case .md5: {
							md5, ok := slice_to_type(sections.line[i:], [16]u8)
							if !ok {
								panic("%s\n", #location())
							}

							i += size_of(md5)
						} case: {
							fmt.printf("Unhandled line parser type! %v\n", def_block.content)
							return false
						}
					}
				}

				non_zero_append(&cu.file_table, file)
			}

			full_cu_size := unit_length + size_of(unit_length)
			hdr_size := i - cu_start
			rem_size := int(full_cu_size) - hdr_size

			cu.line_table = Line_Table{
				op_buffer   = sections.line[i:i+rem_size],
				opcode_base = line_hdr.opcode_base,
				line_base   = line_hdr.line_base,
				line_range  = line_hdr.line_range,
				default_is_stmt = line_hdr.default_is_stmt,
			}
			i += rem_size

		} else { // For DWARF 4, 3, 2, etc.
			non_zero_append(&cu.dir_table, ".")
			non_zero_append(&cu.file_table, File_Unit{})

			for {
				cstr_dir_name := cstring(raw_data(sections.line[i:]))

				i += len(cstr_dir_name) + 1
				if len(cstr_dir_name) == 0 {
					break
				}

				non_zero_append(&cu.dir_table, string(cstr_dir_name))
			}

			for {
				cstr_file_name := cstring(raw_data(sections.line[i:]))

				i += len(cstr_file_name) + 1
				if len(cstr_file_name) == 0 {
					break
				}

				dir_idx, size, ok := read_uleb(sections.line[i:])
				if !ok {
					panic("%s\n", #location())
				}
				i += size

				last_modified, size2, ok2 := read_uleb(sections.line[i:])
				if !ok2 {
					panic("%s\n", #location())
				}
				i += size2

				file_size, size3, ok3 := read_uleb(sections.line[i:])
				if !ok3 {
					panic("%s\n", #location())
				}
				i += size3

				non_zero_append(&cu.file_table, File_Unit{name = string(cstr_file_name), dir_idx = int(dir_idx)})
			}

			full_cu_size := unit_length + size_of(unit_length)
			hdr_size := i - cu_start
			rem_size := int(full_cu_size) - hdr_size

			cu.line_table = Line_Table{
				op_buffer   = sections.line[i:i+rem_size],
				opcode_base = line_hdr.opcode_base,
				line_base   = line_hdr.line_base,
				line_range  = line_hdr.line_range,
				default_is_stmt = line_hdr.default_is_stmt,
			}
			i += rem_size
		}
	}

	fmt.printf("DWARF: processing line info tables\n")
	for cu, idx in &cu_list {
		line_table := &cu.line_table

		lm_state := Line_Machine{}
		lm_state.file_idx = 1
		lm_state.line_num = 1
		lm_state.is_stmt = line_table.default_is_stmt

		for i := 0; i < len(line_table.op_buffer); {
			op_byte := line_table.op_buffer[i]
			i += 1

			if op_byte >= line_table.opcode_base {
				real_op := op_byte - line_table.opcode_base
				line_inc := int(line_table.line_base + i8(real_op % line_table.line_range))
				addr_inc := int(real_op / line_table.line_range)

				lm_state.line_num = u64(int(lm_state.line_num) + line_inc)
				lm_state.address  = u64(int(lm_state.address) + addr_inc)

				non_zero_append(&line_table.lines, lm_state)

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
						non_zero_append(&line_table.lines, lm_state)

						lm_state = Line_Machine{
							file_idx = 1,
							line_num = 1,
							is_stmt = line_table.default_is_stmt,
						}
					} case .set_address: {
						address := slice_to_type(line_table.op_buffer[i:], u64)
						lm_state.address = address
						lm_state.op_idx = 0
						i += size_of(address)
					} case .set_discriminator: {
						discr, size, ok := read_uleb(line_table.op_buffer[i:])
						if !ok {
							panic("%s\n", #location())
						}
						lm_state.discriminator = discr
						i += size
					} case: {
						fmt.printf("Got unhandled op! (%x) %v\n", tmp, real_op)
						return false
					}
				}
			} else {
				#partial switch op {
					case .copy: {
						non_zero_append(&line_table.lines, lm_state)

						lm_state.discriminator  = 0
						lm_state.basic_block    = false
						lm_state.prologue_end   = false
						lm_state.epilogue_begin = false
					} case .advance_pc: {
						addr_inc, size, ok := read_uleb(line_table.op_buffer[i:])
						if !ok {
							panic("%s\n", #location())
						}
						lm_state.address = lm_state.address + u64(addr_inc)
						i += size
					} case .advance_line: {
						line_inc, size, ok := read_ileb(line_table.op_buffer[i:])
						if !ok {
							panic("%s\n", #location())
						}
						lm_state.line_num = u64(int(lm_state.line_num) + int(line_inc))
						i += size
					} case .set_file: {
						file_idx, size, ok := read_uleb(line_table.op_buffer[i:])
						if !ok {
							panic("%s\n", #location())
						}
						lm_state.file_idx = file_idx
						i += size
					} case .set_column: {
						col_num, size, ok := read_uleb(line_table.op_buffer[i:])
						if !ok {
							panic("%s\n", #location())
						}
						lm_state.col_num = col_num
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
						lm_state.op_idx = 0
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
			}
		}
	}

	cu_file_map := make(map[CU_File_Entry]string)
	defer delete(cu_file_map)

	fmt.printf("DWARF: generating filenames\n")
	b := strings.builder_make(context.temp_allocator)
	for cu, c_idx in &cu_list {
		base_dir := cu.dir_table[0]
		for file, f_idx in cu.file_table {
			dir_name := cu.dir_table[file.dir_idx]

			strings.builder_reset(&b)
			if dir_name[0] != '/' {
				strings.write_string(&b, base_dir)
				strings.write_rune(&b, '/')
			}

			strings.write_string(&b, dir_name)
			strings.write_rune(&b, '/')
			strings.write_string(&b, file.name)
			file_name := strings.to_string(b)

			interned_name, err := strings.intern_get(&trace.filename_map, file_name)
			if err != nil {
				return false
			}

			cu_file_map[CU_File_Entry{u64(c_idx), u64(f_idx)}] = interned_name
		}
	}

	fmt.printf("DWARF: sorting lines\n")
	for cu, c_idx in &cu_list {
		for line in &cu.line_table.lines {
			name, ok := cu_file_map[CU_File_Entry{u64(c_idx), line.file_idx}]
			if !ok {
				name = ""
			}
			non_zero_append(&trace.line_info, Line_Info{line.address + skew_size, line.line_num, name})
		}

	}
	line_order :: proc(a, b: Line_Info) -> bool {
		return a.address < b.address
	}
	slice.sort_by(trace.line_info[:], line_order)

	// chunk through all abbreviations
	cu_start := 0

	au_offset_map := make(map[int][dynamic]Abbrev_Unit)
	defer cleanup_au_offsets(&au_offset_map)

	au_offset_map[0] = make([dynamic]Abbrev_Unit)
	abbrevs := &au_offset_map[cu_start]

	fmt.printf("DWARF: parsing debug_abbrev\n")
	for i := 0; i < len(sections.abbrev); {
		abbrev_code, size, ok := read_uleb(sections.abbrev[i:])
		if !ok {
			panic("%s\n", #location())
		}
		i += size

		// got a NULL abbrev
		if abbrev_code == 0 {
			cu_start = i

			au_offset_map[cu_start] = make([dynamic]Abbrev_Unit)
			abbrevs = &au_offset_map[cu_start]
			continue
		}

		entry := Abbrev_Unit{}
		entry.id = abbrev_code

		entry_type, size2, ok2 := read_uleb(sections.abbrev[i:])
		if !ok2 {
			panic("%s\n", #location())
		}
		i += size2

		entry.type = Dw_Tag(entry_type)
		entry.has_children = sections.abbrev[i] > 0
		i += 1

		// get the size of attributes list for an abbrev
		attrs_start := i
		for i < len(sections.abbrev) {
			attr_name, size, ok := read_uleb(sections.abbrev[i:])
			if !ok {
				panic("%s\n", #location())
			}
			i += size

			attr_form, size2, ok2 := read_uleb(sections.abbrev[i:])
			if !ok2 {
				panic("%s\n", #location())
			}
			i += size2

			// 0, 0 means we've hit the end of the list of attributes
			if attr_name == 0 && attr_form == 0 {
				break
			}

			// implicit const is stored in the attribute. Oh boy.
			if Dw_Form(attr_form) == .implicit_const {
				_, size, ok := read_ileb(sections.abbrev[i:])
				if !ok {
					panic("%s\n", #location())
				}
				i += size
			}
		}

		entry.attrs_buf = sections.abbrev[attrs_start:i]
		non_zero_append(abbrevs, entry)
	}

	MAX_BLOCK_STACK :: 30
	cu_start_offset  := 0

	// Process the CUs using the abbrev data
	fmt.printf("DWARF: parsing debug_info\n")
	for i := 0; i < len(sections.info); {
		unit_length, ok := slice_to_type(sections.info[i:], u32)
		if !ok {
			panic("%s\n", #location())
		}
		if unit_length == 0xFFFF_FFFF { 
			fmt.printf("Only supporting DWARF32 for now!\n")
			return false 
		}
		i += size_of(unit_length)

		version, ok2 := slice_to_type(sections.info[i:], u16)
		if !ok2 {
			panic("%s\n", #location())
		}
		if !(version == 3 || version == 4 || version == 5) {
			fmt.printf("Only supports DWARF 3, 4 and 5, got %d\n", version)
			return false
		}
		i += size_of(version)

		ctx := DWARF_Context{}
		ctx.bits_64 = false
		ctx.version = int(version)

		cu_hdr, size, ok3 := parse_cu_header(&ctx, sections.info[i:])
		if !ok3 {
			panic("%s\n", #location())
		}
		i += size

		if cu_hdr.address_size != 8 {
			fmt.printf("Doesn't support address size other than 8! %v\n", cu_hdr.address_size)
			return false
		}

		//fmt.printf("0x%x, %v, %v\n", unit_length, version, cu_hdr)

		child_level := 1
		first_entry := true

		abbrevs := &au_offset_map[int(cu_hdr.abbrev_offset)]
		for first_entry || child_level > 1 {
			first_entry = false

			abbrev_id, size, ok := read_uleb(sections.info[i:])
			if !ok {
				panic("%s\n", #location())
			}
			i += size

			if abbrev_id == 0 {
				child_level -= 1
				continue
			}

			abbrev_idx := abbrev_id - 1
			if abbrev_idx < 0 || abbrev_idx >= u64(len(abbrevs)) {
				fmt.printf("tried to get invalid abbrev id: %v\n", abbrev_idx)
				panic("%s\n", #location())
			}
			au := &abbrevs[abbrev_idx]

			block_offset := i - size
			//fmt.printf("%x | %d | %v\n", block_offset, abbrev_id, au.type)

			is_function := au.type == .subprogram || au.type == .inlined_subroutine
			for j := 0; j < len(au.attrs_buf); {
				attr_name, size, ok := read_uleb(au.attrs_buf[j:])
				if !ok {
					panic("%s\n", #location())
				}
				j += size

				attr_form, size2, ok2 := read_uleb(au.attrs_buf[j:])
				if !ok2 {
					panic("%s\n", #location())
				}
				j += size2

				if attr_name == 0 && attr_form == 0 {
					break
				}

				attr_code := Dw_Form(attr_form)
				data, skip_size, ok3 := parse_attr_data(attr_code, sections.info[i:], au.attrs_buf[j:], sections.debug_str, debug_str_offsets, sections.line_str)
				if !ok3 {
					fmt.printf("failed to parse %v\n", attr_code)
					panic("%s\n", #location())
				}

				/*
				attr_field := Dw_At(attr_name)
				attr_val := Attr_Entry{form = Dw_Form(attr_form), data = data}
				fmt.printf("\t%v (%v)\n", attr_field, attr_val)
				*/

				// implicit const lives in the attr buffer, rather than in the .debug_info
				if attr_code == .implicit_const {
					j += skip_size
				} else {
					i += skip_size
				}
			}

			if au.has_children {
				child_level += 1
			}
		}
		cu_start_offset = i
	}

	return true
}
