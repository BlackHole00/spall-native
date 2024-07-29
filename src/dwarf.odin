package main

import "core:os"
import "core:fmt"
import "core:strings"
import "core:slice"
import "core:encoding/varint"
import "core:reflect"

LOG_SPAM := false

Sections :: struct {
	debug_str:   []u8,
	str_offsets: []u8,
	line:        []u8,
	line_str:    []u8,
	addr:        []u8,
	abbrev:      []u8,
	info:        []u8,
	ranges:      []u8,
	rnglists:    []u8,
}

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

Dw_RLE :: enum u8 {
	end_of_list   = 0,
	base_addressx = 1,
	startx_endx   = 2,
	startx_length = 3,
	offset_pair   = 4,
	base_address  = 5,
	start_end     = 6,
	start_length  = 7,
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
	GNU_vector         = 0x2107,
	GNU_template_name  = 0x2110,
	GNU_pubnames       = 0x2134,

	GNU_discriminator  = 0x2136,
	GNU_locviews       = 0x2137,
	GNU_entry_view     = 0x2138,

	// LLVM extensions
	LLVM_include_path  = 0x3e00,
	LLVM_config_macros = 0x3e01,
	LLVM_isysroot      = 0x3e02,

	// Apple extensions
	APPLE_optimized    = 0x3fe1,
	APPLE_sdk          = 0x3fef,
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
	addr_size:           u8,
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
	addr_size:          u8,
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
	addr_size: u8,
}

DWARF32_V4_CU_Header :: struct #packed {
	abbrev_offset: u32,
	addr_size: u8,
}

DWARF32_V5_CU_Header :: struct #packed {
	unit_type: Dw_Unit_Type,
	addr_size: u8,
	abbrev_offset: u32,
}

DWARF_CU_Header :: struct {
	unit_type: Dw_Unit_Type,
	addr_size: int,
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

CU_Files_Unit :: struct {
	dir_table:    [dynamic]string,
	file_table:   [dynamic]File_Unit,
	line_table:   Line_Table,
}

DWARF_Context :: struct {
	sections: ^Sections,
	bits_64: bool,
	version: int,
	addr_size: int,
}

dw_addr       :: distinct u64
dw_addrx      :: distinct u64
dw_block      :: distinct []u8
dw_udata      :: distinct u64
dw_data16     :: distinct []u8
dw_sdata      :: distinct i64
dw_exprloc    :: distinct []u8
dw_flag       :: distinct bool
dw_sec_offset :: distinct u64
dw_ref        :: distinct u64
dw_ref_addr   :: distinct u64
dw_str        :: distinct cstring
dw_strp       :: distinct u64
dw_strx       :: distinct u64
dw_line_strp  :: distinct u64
dw_loclistx   :: distinct u64
dw_rnglistx   :: distinct u64

Attr_Data :: union {
	dw_addr,
	dw_addrx,
	dw_block,
	dw_udata,
	dw_data16,
	dw_sdata,
	dw_exprloc,
	dw_flag,
	dw_sec_offset,
	dw_ref,
	dw_ref_addr,
	dw_str,
	dw_strp,
	dw_strx,
	dw_line_strp,
	dw_loclistx,
	dw_rnglistx,
}

Attr_Result :: struct {
	id: Dw_At,
	val: Attr_Data,
}

Attr_Entry :: struct {
	attr_id: Dw_At,
	form_id: Dw_Form,
	extra: u64,
}

Abbrev_Unit :: struct {
	id: u64,
	offset: u64,
	type: Dw_Tag,

	has_children: bool,
	attrs: [dynamic]Attr_Entry,
}

CU_Unit :: struct {
	low_pc: u64,
	offset: u64,
	idx:    u64,
	abbrevs: []Abbrev_Unit,

	str_offsets_base: u64,
	addr_base:  u64,
	rnglists_base: u64,
	loclists_base: u64,
	frame_base: u64,
}
Function_Unit :: struct {
	name: cstring,
	has_pc: bool,

	low_pc:     u64,
	high_pc:    u64,
	ranges_off: u64,
	entry_pc:   u64,

	origin: u64,
	specification: u64,
}

init_abbrevs :: proc(ctx: ^DWARF_Context, au_offset_map: ^map[int][dynamic]Abbrev_Unit) {
	cu_start := 0

	au_offset_map[cu_start] = make([dynamic]Abbrev_Unit)
	abbrevs := &au_offset_map[cu_start]

	fmt.printf("DWARF: parsing debug_abbrev\n")
	for i := 0; i < len(ctx.sections.abbrev); {
		abbrev_code, size, ok := read_uleb(ctx.sections.abbrev[i:])
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
		entry.attrs = make([dynamic]Attr_Entry)

		entry_type, size2, ok2 := read_uleb(ctx.sections.abbrev[i:])
		if !ok2 {
			panic("%s\n", #location())
		}
		i += size2

		entry.type = Dw_Tag(entry_type)
		entry.has_children = ctx.sections.abbrev[i] > 0
		i += 1

		// get the size of attributes list for an abbrev
		attrs_start := i
		for i < len(ctx.sections.abbrev) {
			attr_id, size, ok := read_uleb(ctx.sections.abbrev[i:])
			if !ok {
				panic("%s\n", #location())
			}
			i += size

			form_id, size2, ok2 := read_uleb(ctx.sections.abbrev[i:])
			if !ok2 {
				panic("%s\n", #location())
			}
			i += size2

			// 0, 0 means we've hit the end of the list of attributes
			if attr_id == 0 && form_id == 0 {
				break
			}

			extra_val : i64 = 0
			// implicit const is stored in the attribute. Oh boy.
			if Dw_Form(form_id) == .implicit_const {
				extra_val, size, ok = read_ileb(ctx.sections.abbrev[i:])
				if !ok {
					panic("%s\n", #location())
				}
				i += size
			}
			attr := Attr_Entry{form_id = Dw_Form(form_id), attr_id = Dw_At(attr_id), extra = u64(extra_val)}
			non_zero_append(&entry.attrs, attr)
		}

		non_zero_append(abbrevs, entry)
	}

	return
}

read_debug_addr :: proc(ctx: ^DWARF_Context, cu: ^CU_Unit, val: u64) -> (u64, bool) {
	debug_addr := ctx.sections.addr
	addr_size := u64(debug_addr[cu.addr_base - 2])
	seg_size  := u64(debug_addr[cu.addr_base - 1])

	offset := cu.addr_base + ((addr_size + seg_size) * val)
	val, ok := slice_to_type(debug_addr[offset:], u64)
	return val, ok
}

get_attr :: proc(attrs: []Attr_Result, id: Dw_At) -> Attr_Data {
	for attr in attrs {
		if attr.id == id {
			return attr.val
		}
	}

	return nil
}

get_offset :: proc(ctx: ^DWARF_Context, buffer: []u8) -> (v: u64, size: int, ok: bool) {
	if ctx.bits_64 {
		v := slice_to_type(buffer, u64) or_return
		return v, size_of(u64), true
	} else {
		v := slice_to_type(buffer, u32) or_return
		return u64(v), size_of(u32), true
	}
}

get_addr :: proc(ctx: ^DWARF_Context, buffer: []u8) -> (v: u64, size: int, ok: bool) {
	if ctx.addr_size == 8 {
		v := slice_to_type(buffer, u64) or_return
		return v, size_of(u64), true
	} else {
		v := slice_to_type(buffer, u32) or_return
		return u64(v), size_of(u32), true
	}
}

parse_attr :: proc(ctx: ^DWARF_Context, buffer: []u8, attr: Attr_Entry) -> (ret: Attr_Data, size: int, ok: bool) {
	#partial switch attr.form_id {
	case .addr:
		v, size := get_addr(ctx, buffer) or_return
		return Attr_Data(dw_addr(v)), size, true
	case .addrx1:
		v := slice_to_type(buffer, u8) or_return
		return Attr_Data(dw_addrx(v)), size_of(u8), true
	case .addrx2:
		v := slice_to_type(buffer, u16) or_return
		return Attr_Data(dw_addrx(v)), size_of(u16), true
	case .addrx4:
		v := slice_to_type(buffer, u32) or_return
		return Attr_Data(dw_addrx(v)), size_of(u32), true
	case .addrx:
		v, size := read_uleb(buffer) or_return
		return Attr_Data(dw_addrx(v)), size, true

	case .block1:
		len := slice_to_type(buffer, u8) or_return
		return Attr_Data(dw_block(buffer[:len])), size_of(u8) + int(len), true
	case .block2:
		len := slice_to_type(buffer, u16) or_return
		return Attr_Data(dw_block(buffer[:len])), size_of(u16) + int(len), true
	case .block4:
		len := slice_to_type(buffer, u32) or_return
		return Attr_Data(dw_block(buffer[:len])), size_of(u32) + int(len), true
	case .block:
		len, size := read_uleb(buffer) or_return
		return Attr_Data(dw_block(buffer[:len])), size + int(len), true

	case .data1:
		v := slice_to_type(buffer, u8) or_return
		return Attr_Data(dw_udata(v)), size_of(u8), true
	case .data2:
		v := slice_to_type(buffer, u16) or_return
		return Attr_Data(dw_udata(v)), size_of(u16), true
	case .data4:
		v := slice_to_type(buffer, u32) or_return
		return Attr_Data(dw_udata(v)), size_of(u32), true
	case .data8:
		v := slice_to_type(buffer, u64) or_return
		return Attr_Data(dw_udata(v)), size_of(u64), true
	case .data16:
		return Attr_Data(dw_data16(buffer[:16])), 16, true
	case .udata:
		v, size := read_uleb(buffer) or_return
		return Attr_Data(dw_udata(v)), size, true
	case .sdata:
		v, size := read_ileb(buffer) or_return
		return Attr_Data(dw_sdata(v)), size, true

	case .exprloc:
		len, size := read_uleb(buffer) or_return
		return Attr_Data(dw_exprloc(buffer[:len])), size + int(len), true

	case .flag:
		v := slice_to_type(buffer, u8) or_return
		return Attr_Data(dw_flag(v != 0)), size_of(u8), true
	case .flag_present:
		return Attr_Data(dw_flag(true)), 0, true

	case .sec_offset:
		v, size := get_offset(ctx, buffer) or_return
		return Attr_Data(dw_sec_offset(v)), size, true

	case .ref1:
		v := slice_to_type(buffer, u8) or_return
		return Attr_Data(dw_ref(v)), size_of(u8), true
	case .ref2:
		v := slice_to_type(buffer, u16) or_return
		return Attr_Data(dw_ref(v)), size_of(u16), true
	case .ref4:
		v := slice_to_type(buffer, u32) or_return
		return Attr_Data(dw_ref(v)), size_of(u32), true
	case .ref8:
		v := slice_to_type(buffer, u64) or_return
		return Attr_Data(dw_ref(v)), size_of(u64), true
	case .ref_udata:
		v, size := read_uleb(buffer) or_return
		return Attr_Data(dw_ref(v)), size, true

	case .ref_addr:
		v, size := get_offset(ctx, buffer) or_return
		return Attr_Data(dw_ref_addr(v)), size, true
	case .ref_sig8:
		v := slice_to_type(buffer, u64) or_return
		return Attr_Data(dw_ref(v)), size_of(u64), true

	case .str:
		str := cstring(raw_data(buffer))
		return Attr_Data(dw_str(str)), len(str)+1, true
	case .strp:
		v, size := get_offset(ctx, buffer) or_return
		return Attr_Data(dw_strp(v)), size, true
	case .strx1:
		v := slice_to_type(buffer, u8) or_return
		return Attr_Data(dw_strx(v)), size_of(u8), true
	case .strx2:
		v := slice_to_type(buffer, u16) or_return
		return Attr_Data(dw_strx(v)), size_of(u16), true
	case .strx4:
		v := slice_to_type(buffer, u32) or_return
		return Attr_Data(dw_strx(v)), size_of(u32), true
	case .strx:
		v, size := read_uleb(buffer) or_return
		return Attr_Data(dw_strx(v)), size, true
	case .line_strp:
		v, size := get_offset(ctx, buffer) or_return
		return Attr_Data(dw_line_strp(v)), size, true

	/*
	case .indirect:
		v, size := read_uleb(buffer) or_return
		v2, sz2 := parse_attr(ctx, buffer[size:], Attr_Entry{form_id = attr.extra}) or_return
		return v2, size+sz2, true
	*/

	case .implicit_const:
		return Attr_Data(dw_sdata(attr.extra)), 0, true

	case .loclistx:
		v, size := read_uleb(buffer) or_return
		return Attr_Data(dw_loclistx(v)), size, true
	case .rnglistx:
		v, size := read_uleb(buffer) or_return
		return Attr_Data(dw_rnglistx(v)), size, true
	}

	return
}

attr_get_u64 :: proc(val: Attr_Data) -> (ret: u64, ok: bool) {
	#partial switch v in val {
	case dw_udata:
		return u64(v), true
	case dw_sdata:
		return u64(v), true
	case dw_sec_offset:
		return u64(v), true
	case: return
	}
}

parse_die :: proc(ctx: ^DWARF_Context, buffer: []u8, au_attrs: []Attr_Entry, out_attrs: ^[dynamic]Attr_Result) -> (int, bool) {
	i := 0
	for attr in au_attrs {
		v, size, ok := parse_attr(ctx, buffer[i:], attr)
		if !ok {
			return 0, false
		}

		append(out_attrs, Attr_Result{attr.attr_id, v})
		i += size
	}


	return i, true
}

parse_range_table :: proc(ctx: ^DWARF_Context, cu: ^CU_Unit, ranges_off: u64) -> u64 {
	new_low := max(u64)

	switch ctx.version {
	case 5:
		if len(ctx.sections.rnglists) <= int(ranges_off) {
			panic("Invalid range offset? %x <= %x\n", len(ctx.sections.rnglists), ranges_off)
		}

		rnglist := ctx.sections.rnglists[ranges_off:]

		base_addr : u64 = cu.low_pc

		i := 0
		still_scanning := true
		for still_scanning {
			type, ok := slice_to_type(rnglist[i:], Dw_RLE); i += 1
			assert(ok)

			#partial switch type {
			case .end_of_list:
				still_scanning = false

			case .base_addressx:
				idx, leb_size, ok := read_uleb(rnglist[i:]); i += leb_size
				assert(ok)

				addr, ok2 := read_debug_addr(ctx, cu, idx)
				assert(ok2)

				if LOG_SPAM { fmt.printf("\t%v | base: 0x%x\n", type, addr) }
				base_addr = addr

			case .startx_endx:
				start_idx, leb_size, ok := read_uleb(rnglist[i:]); i += leb_size
				assert(ok)

				end_idx, leb_size2, ok2 := read_uleb(rnglist[i:]); i += leb_size2
				assert(ok2)
				
				low_pc, ok3 := read_debug_addr(ctx, cu, start_idx)
				assert(ok3)

				high_pc, ok4 := read_debug_addr(ctx, cu, end_idx)
				assert(ok4)

				if LOG_SPAM { fmt.printf("\t%v | 0x%x -> 0x%x\n", type, low_pc, high_pc) }
				new_low = min(new_low, low_pc)

			case .startx_length:
				start_idx, leb_size, ok := read_uleb(rnglist[i:]); i += leb_size
				assert(ok)

				length, leb_size2, ok2 := read_uleb(rnglist[i:]); i += leb_size2
				assert(ok2)

				low_pc, ok3 := read_debug_addr(ctx, cu, start_idx)
				assert(ok3)

				if LOG_SPAM { fmt.printf("\t%v | 0x%x -> 0x%x\n", type, low_pc, low_pc + length) }
				new_low = min(new_low, low_pc)

			case .offset_pair:
				low_pc, leb_size, ok := read_uleb(rnglist[i:]); i += leb_size
				assert(ok)

				high_pc, leb_size2, ok2 := read_uleb(rnglist[i:]); i += leb_size2
				assert(ok2)

				if LOG_SPAM { fmt.printf("\t%v | 0x%x -> 0x%x\n", type, low_pc, high_pc) }
				new_low = min(new_low, low_pc)

			case .base_address:
				addr, ok := slice_to_type(rnglist[i:], u64); i += size_of(u64)
				assert(ok)
				
				if LOG_SPAM { fmt.printf("\t%v | base: 0x%x\n", type, addr) }
				base_addr = addr

			case .start_end:
				low_pc, ok := slice_to_type(rnglist[i:], u64); i += size_of(u64)
				assert(ok)

				high_pc, ok2 := slice_to_type(rnglist[i:], u64); i += size_of(u64)
				assert(ok2)
				
				if LOG_SPAM { fmt.printf("\t%v | 0x%x -> 0x%x\n", type, low_pc, high_pc) }
				new_low = min(new_low, low_pc)

			case .start_length:
				addr, ok := slice_to_type(rnglist[i:], u64); i += size_of(u64)
				assert(ok)

				length, leb_size, ok2 := read_uleb(rnglist[i:]); i += leb_size
				assert(ok2)

				if LOG_SPAM { fmt.printf("\t%v | 0x%x -> 0x%x\n", type, base_addr + addr, base_addr + addr + length) }
				new_low = min(new_low, addr)

			case:
				fmt.printf("unhandled range type: %v\n", type)
				assert(false)
				still_scanning = false
			}
		}

	case 4:
		if len(ctx.sections.ranges) <= int(ranges_off) {
			panic("Invalid range offset? %x <= %x\n", len(ctx.sections.ranges), ranges_off)
		}

		ranges := ctx.sections.ranges[ranges_off:]

		i := 0
		still_scanning := true
		for still_scanning {
			low_pc, ok := slice_to_type(ranges[i:], u64); i += size_of(u64)
			assert(ok)

			high_pc, ok2 := slice_to_type(ranges[i:], u64); i += size_of(u64)
			assert(ok2)

			if (low_pc == 0 && high_pc == 0) || (low_pc == high_pc) {
				still_scanning = false
				continue
			}
			
			new_low = min(new_low, low_pc)
		}
	case:
		panic("Ranges for DWARF %v not supported!\n", ctx.version)
	}

	return new_low
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
		common_hdr.addr_size             = hdr.addr_size
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
		common_hdr.addr_size             = 4
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
		common_hdr.addr_size             = 4
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
		common_hdr.addr_size = int(hdr.addr_size)
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

		common_hdr.addr_size = int(hdr.addr_size)
		common_hdr.abbrev_offset = hdr.abbrev_offset

		return common_hdr, size_of(hdr), true
	case 3:
		hdr, ok := slice_to_type(blob, DWARF32_V3_CU_Header)
		if !ok {
			return {}, 0, false
		}

		common_hdr.addr_size = int(hdr.addr_size)
		common_hdr.abbrev_offset = hdr.abbrev_offset

		return common_hdr, size_of(hdr), true
	case:
		return {}, 0, false
	}
}

cleanup_au_offsets :: proc(au_off_map: ^map[int][dynamic]Abbrev_Unit) {
	for k, v in au_off_map {
		for au in v {
			delete(au.attrs)
		}
		delete(v)
	}
	delete(au_off_map^)
}

cleanup_cu_files_list :: proc(cu_files_list: ^[dynamic]CU_Files_Unit) {
	for cu in cu_files_list {
		delete(cu.dir_table)
		delete(cu.file_table)
		delete(cu.line_table.lines)
	}
}

process_line_info :: proc(trace: ^Trace, ctx: ^DWARF_Context, cu_files_list: ^[dynamic]CU_Files_Unit, cu_file_map: ^map[CU_File_Entry]string) -> bool {
	version : u16 = 0
	fmt.printf("DWARF: parsing debug_line\n")
	for i := 0; i < len(ctx.sections.line); {
		cu_start := i

		unit_length, ok := slice_to_type(ctx.sections.line[i:], u32)
		if !ok {
			panic("%s\n", #location())
		}
		if unit_length == 0xFFFF_FFFF { 
			fmt.printf("Only supporting DWARF32 for now!\n")
			return false 
		}
		i += size_of(unit_length)

		if unit_length == 0 { continue }

		version, ok = slice_to_type(ctx.sections.line[i:], u16)
		if !ok {
			panic("%s\n", #location())
		}
		if !(version == 3 || version == 4 || version == 5) {
			fmt.printf("Only supports DWARF 3, 4 and 5, got %d\n", version)
			return false
		}
		i += size_of(version)

		ctx.bits_64 = false
		ctx.version = int(version)

		line_hdr, size, ok3 := parse_line_header(ctx, ctx.sections.line[i:])
		if !ok3 {
			panic("%s\n", #location())
		}
		i += size

		if line_hdr.opcode_base != 13 {
			fmt.printf("Unable to support custom line table ops!\n")
			return false
		}

		non_zero_append(cu_files_list, CU_Files_Unit{
			dir_table = make([dynamic]string),
			file_table = make([dynamic]File_Unit),
			line_table = Line_Table{
				lines = make([dynamic]Line_Machine),
			},
		})
		cu := &cu_files_list[len(cu_files_list) - 1]

		// this is fun
		opcode_table_len := line_hdr.opcode_base - 1
		i += int(opcode_table_len)

		if version == 5 {
			dir_entry_fmt_count, ok := slice_to_type(ctx.sections.line[i:], u8)
			if !ok {
				panic("%s\n", #location())
			}
			i += size_of(dir_entry_fmt_count)

			fmt_parse := [255]LineFmtEntry{}
			fmt_parse_len := 0
			for j := 0; j < int(dir_entry_fmt_count); j += 1 {
				content_type, size1, ok := read_uleb(ctx.sections.line[i:])
				if !ok {
					panic("%s\n", #location())
				}
				i += size1

				content_code := Dw_LNCT(content_type)

				form_type, size2, ok2 := read_uleb(ctx.sections.line[i:])
				if !ok2 {
					panic("%s\n", #location())
				}
				i += size2

				form_code := Dw_Form(form_type)

				fmt_parse[fmt_parse_len] = LineFmtEntry{content_code, form_code}
				fmt_parse_len += 1
			}

			dir_name_count, size2, ok2 := read_uleb(ctx.sections.line[i:])
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

							str_idx, ok := slice_to_type(ctx.sections.line[i:], u32)
							if !ok {
								panic("%s\n", #location())
							}

							cstr_dir_name := cstring(raw_data(ctx.sections.line_str[str_idx:]))
							non_zero_append(&cu.dir_table, string(cstr_dir_name))

							i += size_of(u32)
						} case: {
							fmt.printf("Unhandled line parser type! %v\n", def_block.content)
							return false
						}
					}
				}
			}

			file_entry_fmt_count, ok3 := slice_to_type(ctx.sections.line[i:], u8)
			if !ok3 {
				panic("%s\n", #location())
			}
			i += size_of(file_entry_fmt_count)

			fmt_parse = {}
			fmt_parse_len = 0
			for j := 0; j < int(file_entry_fmt_count); j += 1 {
				content_type, size, ok := read_uleb(ctx.sections.line[i:])
				if !ok {
					panic("%s\n", #location())
				}
				i += size

				content_code := Dw_LNCT(content_type)

				form_type, size2, ok2 := read_uleb(ctx.sections.line[i:])
				if !ok2 {
					panic("%s\n", #location())
				}
				i += size2

				form_code := Dw_Form(form_type)

				fmt_parse[fmt_parse_len] = LineFmtEntry{content_code, form_code}
				fmt_parse_len += 1
			}

			file_name_count, size3, ok4 := read_uleb(ctx.sections.line[i:])
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

							str_idx, ok := slice_to_type(ctx.sections.line[i:], u32)
							if !ok {
								panic("%s\n", #location())
							}

							cstr_file_name := cstring(raw_data(ctx.sections.line_str[str_idx:]))
							file.name = string(cstr_file_name)

							i += size_of(u32)
						} case .directory_index: {
							#partial switch def_block.form {
								case .data1: {
									dir_idx, ok := slice_to_type(ctx.sections.line[i:], u8)
									if !ok {
										panic("%s\n", #location())
									}
									file.dir_idx = int(dir_idx)
									i += size_of(u8)
								} case .data2: {
									dir_idx, ok := slice_to_type(ctx.sections.line[i:], u16)
									if !ok {
										panic("%s\n", #location())
									}
									file.dir_idx = int(dir_idx)
									i += size_of(u16)
								} case .udata: {
									dir_idx, size, ok := read_uleb(ctx.sections.line[i:])
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
							md5, ok := slice_to_type(ctx.sections.line[i:], [16]u8)
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
				op_buffer   = ctx.sections.line[i:i+rem_size],
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
				cstr_dir_name := cstring(raw_data(ctx.sections.line[i:]))

				i += len(cstr_dir_name) + 1
				if len(cstr_dir_name) == 0 {
					break
				}

				non_zero_append(&cu.dir_table, string(cstr_dir_name))
			}

			for {
				cstr_file_name := cstring(raw_data(ctx.sections.line[i:]))

				i += len(cstr_file_name) + 1
				if len(cstr_file_name) == 0 {
					break
				}

				dir_idx, size, ok := read_uleb(ctx.sections.line[i:])
				if !ok {
					panic("%s\n", #location())
				}
				i += size

				last_modified, size2, ok2 := read_uleb(ctx.sections.line[i:])
				if !ok2 {
					panic("%s\n", #location())
				}
				i += size2

				file_size, size3, ok3 := read_uleb(ctx.sections.line[i:])
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
				op_buffer   = ctx.sections.line[i:i+rem_size],
				opcode_base = line_hdr.opcode_base,
				line_base   = line_hdr.line_base,
				line_range  = line_hdr.line_range,
				default_is_stmt = line_hdr.default_is_stmt,
			}
			i += rem_size
		}
	}

	fmt.printf("DWARF: processing line info tables\n")
	for &cu, idx in cu_files_list {
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
						addr_inc, size, ok := read_uleb(line_table.op_buffer[i:]); i += size
						if !ok {
							panic("%s\n", #location())
						}
						lm_state.address += u64(addr_inc) //* line_hdr.min_inst_length
					} case .advance_line: {
						line_inc, size, ok := read_ileb(line_table.op_buffer[i:]); i += size
						if !ok {
							panic("%s\n", #location())
						}
						lm_state.line_num = u64(int(lm_state.line_num) + int(line_inc))
					} case .set_file: {
						file_idx, size, ok := read_uleb(line_table.op_buffer[i:]); i += size
						if !ok {
							panic("%s\n", #location())
						}
						lm_state.file_idx = file_idx
					} case .set_column: {
						col_num, size, ok := read_uleb(line_table.op_buffer[i:]); i += size
						if !ok {
							panic("%s\n", #location())
						}
						lm_state.col_num = col_num
					} case .negate_stmt: {
						lm_state.is_stmt = !lm_state.is_stmt
					} case .set_basic_block: {
						lm_state.basic_block = true
					} case .const_add_pc: {
						addr_inc := (255 - line_table.opcode_base) / line_table.line_range
						lm_state.address += u64(addr_inc) //* line_hdr.min_inst_length
					} case .fixed_advance_pc: {
						advance := slice_to_type(line_table.op_buffer[i:], u16); i += size_of(advance)
						lm_state.address += u64(advance)
						lm_state.op_idx = 0
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


	fmt.printf("DWARF: generating filenames\n")
	b := strings.builder_make(context.temp_allocator)
	for cu, c_idx in cu_files_list {
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

	return true
}

load_dwarf :: proc(trace: ^Trace, sections: ^Sections) -> bool {
	ctx := DWARF_Context{}
	ctx.sections = sections

	cu_files_list := make([dynamic]CU_Files_Unit)
	cu_file_map := make(map[CU_File_Entry]string)
	defer cleanup_cu_files_list(&cu_files_list)
	defer delete(cu_file_map)

	process_line_info(trace, &ctx, &cu_files_list, &cu_file_map) or_return

	au_offset_map := make(map[int][dynamic]Abbrev_Unit)
	defer cleanup_au_offsets(&au_offset_map)

	init_abbrevs(&ctx, &au_offset_map)

	MAX_BLOCK_STACK :: 30
	symbol_found := false
	skew_size : u64 = 0

	attr_scratch := [dynamic]Attr_Result{}

	// Resolve all the symbols we can
	fmt.printf("DWARF: Resolving symbols\n")
	cur_cu_offset := 0
	for cur_cu_offset < len(sections.info) {
		i := cur_cu_offset

		unit_length, ok := slice_to_type(sections.info[i:], u32)
		if !ok {
			panic("%s\n", #location())
		}
		if unit_length == 0xFFFF_FFFF { 
			fmt.printf("Only supporting DWARF32 for now!\n")
			return false 
		}
		i += size_of(unit_length)
		next_offset := 4 + unit_length

		ctx.bits_64 = false

		version, ok2 := slice_to_type(sections.info[i:], u16)
		if !ok2 {
			panic("%s\n", #location())
		}
		if (version < 3 || version > 5) {
			fmt.printf("Only supports DWARF 3, 4 and 5, got %d\n", version)
			return false
		}
		i += size_of(version)

		ctx.version = int(version)

		cu_hdr, size, ok3 := parse_cu_header(&ctx, sections.info[i:])
		if !ok3 {
			panic("%s\n", #location())
		}
		i += size

		ctx.addr_size = cu_hdr.addr_size
		if ctx.addr_size != 8 {
			fmt.printf("Doesn't support address size other than 8! %v\n", ctx.addr_size)
			return false
		}

		cu := CU_Unit{}
		cu.abbrevs = au_offset_map[int(cu_hdr.abbrev_offset)][:]

		next_cu_offset := cur_cu_offset + int(next_offset)
		for i < next_cu_offset {
			block_offset := i

			abbrev_code, size, ok := read_uleb(sections.info[i:])
			if !ok {
				return false
			}
			i += size

			if abbrev_code == 0 {
				continue
			}

			abbrev_idx := abbrev_code - 1
			if abbrev_idx < 0 || abbrev_idx > u64(len(cu.abbrevs)) {
				fmt.printf("Invalid AU idx\n")
				return false
			}
			au := &cu.abbrevs[abbrev_idx]
			if au.id != abbrev_code {
				fmt.printf("Invalid AU idx\n")
				return false
			}

			clear(&attr_scratch)
			size, ok = parse_die(&ctx, sections.info[i:], au.attrs[:], &attr_scratch)
			if !ok {
				fmt.printf("Failed to parse DIE\n")
				return false
			}
			i += size

			/*
			fmt.printf("0x%08x\n", block_offset)
			for attr, idx in attr_scratch {
				fmt.printf("\t%s - %s(%v)\n", attr.id, au.attrs[idx].form_id, attr.val)
			}
			*/

			#partial switch au.type {
			case .compile_unit:
				v := get_attr(attr_scratch[:], .str_offsets_base)
				if v == nil { cu.str_offsets_base = 0 }
				else {
					cu.str_offsets_base = attr_get_u64(v) or_return
				}

				v = get_attr(attr_scratch[:], .addr_base)
				if v == nil { cu.addr_base = 0 }
				else {
					cu.addr_base = attr_get_u64(v) or_return
				}

				v = get_attr(attr_scratch[:], .rnglists_base)
				if v == nil { cu.rnglists_base = 0 }
				else {
					cu.rnglists_base = attr_get_u64(v) or_return
				}

				v = get_attr(attr_scratch[:], .loclists_base)
				if v == nil { cu.loclists_base = 0 }
				else {
					cu.loclists_base = attr_get_u64(v) or_return
				}

				v = get_attr(attr_scratch[:], .frame_base)

			// If we're a function?
			case .subprogram: fallthrough
			case .inlined_subroutine: fallthrough
			case .entry_point:
				v := get_attr(attr_scratch[:], .name)
				fmt.printf("%v\n", v)
				return false
			}
		}

		cur_cu_offset = next_cu_offset
	}
	if !symbol_found {
		fmt.printf("Could not find \"spall_auto_init\" to address skew?\n")
		return false
	}

	fmt.printf("Found skew: 0x%x\n", skew_size)
	am_skew(&trace.addr_map, skew_size)
	/*
	for entry, _ in trace.addr_map.entries {
		fmt.printf("[0x%08x|0x%08x] - %s\n", entry.key, entry.key - skew_size, in_getstr(&trace.string_block, entry.val))
	}
	*/

	fmt.printf("DWARF: sorting lines\n")
	for &cu, c_idx in cu_files_list {
		for &line in cu.line_table.lines {
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

	return true
}
