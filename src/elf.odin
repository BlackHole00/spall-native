package main

import "base:intrinsics"
import "core:fmt"

/*
Handy References:
- https://refspecs.linuxbase.org/elf/elf.pdf
- http://man7.org/linux/man-pages/man5/elf.5.html
*/

ELF_MAGIC     := []u8{ 0x7f, 'E', 'L', 'F' }

ELFCLASS32  :: 1
ELFCLASS64  :: 2
ELFDATA2LSB :: 1
ELFDATA2MSB :: 2

File_Type :: enum {
	none        = 0x0,
	relocatable = 0x1,
	executable  = 0x2,
	shared_obj  = 0x3,
	core        = 0x4,
	lo_os       = 0xFE00,
	hi_os       = 0xFEFF,
	lo_proc     = 0xFF00,
	hi_proc     = 0xFFFF,
}

Processor_Type :: enum {
	none              = 0x000,
	att_we_32100      = 0x001,
	sparc             = 0x002,
	x86               = 0x003,
	m68k              = 0x004,
	m88k              = 0x005,
	imcu              = 0x006,
	i80860            = 0x007,
	mips              = 0x008,
	system_370        = 0x009,
	mips_rs3000_le    = 0x00A,
	hp_pa_risc        = 0x00E,
	i80960            = 0x013,
	ppc               = 0x014,
	ppc_64            = 0x015,
	s390              = 0x016,
	ibm_spu           = 0x017,
	nec_v800          = 0x024,
	fujitsu_fr20      = 0x025,
	trw_rh32          = 0x026,
	motorola_rce      = 0x027,
	arm               = 0x028,
	alpha             = 0x029,
	super_h           = 0x02A,
	sparc_v9          = 0x02B,
	siemens_tricore   = 0x02C,
	argonaut_risc     = 0x02D,
	hitachi_h8_300    = 0x02E,
	hitachi_h8_300h   = 0x02F,
	hitachi_h8s       = 0x030,
	hitachi_h8_500    = 0x031,
	itanium           = 0x032,
	stanford_mips_x   = 0x033,
	motorola_coldfire = 0x034,
	motorola_m68hc12  = 0x035,
	fujitsu_mma       = 0x036,
	siemens_pcp       = 0x037,
	sony_ncpu_risc    = 0x038,
	denso_ndr1        = 0x039,
	motorola_starcore = 0x03A,
	toyota_me16       = 0x03B,
	stmicro_st100     = 0x03C,
	alc_tinyj         = 0x03D,
	x86_64            = 0x03E,
	tms320c6000       = 0x08C,
	mcst_elbrus_e2k   = 0x0AF,
	arm_64            = 0x0B7,
	risc_v            = 0x0F3,
	bpf               = 0x0F7,
	wdc_65c816        = 0x101,
}

Target_ABI :: enum {
	system_v       = 0x00,
	hp_ux          = 0x01,
	netbsd         = 0x02,
	linux          = 0x03,
	gnu_hurd       = 0x04,
	solaris        = 0x06,
	aix            = 0x07,
	irix           = 0x08,
	freebsd        = 0x09,
	tru64          = 0x0A,
	novell_modesto = 0x0B,
	openbsd        = 0x0C,
	openvms        = 0x0D,
	nonstop_kernel = 0x0E,
	aros           = 0x0F,
	fenix_os       = 0x10,
	cloud_abi      = 0x11,
	open_vos       = 0x12,
}

Section_Flags :: enum u64 {
	write      = 0x1,
	alloc      = 0x2,
	executable = 0x4,
	merge      = 0x10,
	strings    = 0x20,
	info_link  = 0x40,
	os_nonconforming = 0x100,
	group      = 0x200,
	tls        = 0x400,
	mask_os    = 0x0FF00000,
	mask_proc  = 0xF0000000,
	ordered    = 0x4000000,
	exclude    = 0x8000000,
}

Section_Header_Type :: enum {
	null     = 0x00,
	progbits = 0x01,
	symtab   = 0x02,
	strtab   = 0x03,
	rela     = 0x04,
	hash     = 0x05,
	dyn      = 0x06,
	note     = 0x07,
	nobits   = 0x08,
	rel      = 0x09,
	dynsym   = 0x0B,
	init_array  = 0x0E,
	fini_array  = 0x0F,
	gnu_hash    = 0x6FFFFFF6,
	gnu_verdef  = 0x6FFFFFFD,
	gnu_verneed = 0x6FFFFFFE,
	gnu_versym  = 0x6FFFFFFF,
	unwind      = 0x70000001,
}

Section_Type :: enum {
	null    = 0,
	load    = 1,
	dyn     = 2,
	interp  = 3,
	note    = 4,
	shlib   = 5,
	phdr    = 6,
	tls     = 7,
	gnu_eh_frame = 0x6474e550,
	gnu_stack    = 0x6474e551,
	gnu_relro    = 0x6474e552,
	gnu_property = 0x6474e553,
	lowproc      = 0x70000000,
	hiproc       = 0x7FFFFFFF,
}

Dynamic_Type :: enum {
	null         = 0,
	needed       = 1,
	plt_rel_size = 2,
	plt_got      = 3,
	hash         = 4,
	strtab       = 5,
	symtab       = 6,
	rela         = 7,
	rela_size    = 8,
	rela_entry   = 9,
	str_size     = 10,
	symbol_entry = 11,
	init         = 12,
	fini         = 13,
	so_name      = 14,
	rpath        = 15,
	symbolic     = 16,
	rel          = 17,
	rel_size     = 18,
	rel_entry    = 19,
	plt_rel      = 20,
	debug        = 21,
	text_rel     = 22,
	jump_rel     = 23,
	bind_now     = 24,
	init_array   = 25,
	init_array_size  = 26,
	fini_array       = 27,
	fini_array_size  = 28,
	rela_count       = 0x6FFFFFF9,
	flags_1          = 0x6FFFFFFB,
	gnu_hash         = 0x6FFFFEF5,
	version_symbol   = 0x6FFFFFF0,
	version_need     = 0x6FFFFFFE,
	version_need_num = 0x6FFFFFFF,
	lo_proc          = 0x70000000,
	hi_proc          = 0x7FFFFFFF,
}

Dyn_Flags :: enum {
	pie = 0x08000000,
}

Symbol_Binding :: enum u8 {
	local  = 0,
	global = 1,
	weak   = 2,
	loos   = 10,
	hios   = 12,
	loproc = 13,
	hiproc = 15,
}

Symbol_Type :: enum u8 {
	notype  = 0,
	object  = 1,
	func    = 2,
	section = 3,
	file    = 4,
	common  = 5,
	tls     = 6,
	loos    = 10,
	hios    = 12,
	loproc  = 13,
	hiproc  = 15,
}

Symbol :: struct {
	name: cstring,
	value: u64,
	size: u64,
	type: Symbol_Type,
	bind: Symbol_Binding,
}

ELF_Pre_Header :: struct #packed {
	magic: [4]u8,
	class: u8,
	endian: u8,
	hdr_version: u8,
	target_abi: u8,
	pad: [8]u8,
}

ELF32_Header :: struct #packed {
	ident: [16]u8,

	type: u16,
	machine: u16,
	version: u32,
	entry: u32,
	program_hdr_offset: u32,
	section_hdr_offset: u32,
	flags: u32,
	ehsize: u16,
	program_hdr_entry_size: u16,
	program_hdr_num: u16,
	section_entry_size: u16,
	section_hdr_num: u16,
	section_hdr_str_idx: u16,
}

ELF64_Header :: struct #packed {
	ident: [16]u8,

	type: u16,
	machine: u16,
	version: u32,
	entry: u64,
	program_hdr_offset: u64,
	section_hdr_offset: u64,
	flags: u32,
	ehsize: u16,
	program_hdr_entry_size: u16,
	program_hdr_num: u16,
	section_entry_size: u16,
	section_hdr_num: u16,
	section_hdr_str_idx: u16,
}

ELF_Header :: struct {
	program_hdr_offset: u64,
	section_hdr_offset: u64,
	program_hdr_num: u16,
	program_hdr_entry_size: u16,
	section_entry_size: u16,
	section_hdr_num: u16,
	section_hdr_str_idx: u16,
}

ELF32_Section_Header :: struct #packed {
	name: u32,
	type: u32,
	flags: u32,
	addr: u32,
	offset: u32,
	size: u32,
	link: u32,
	info: u32,
	addr_align: u32,
	entry_size: u32,
}

ELF64_Section_Header :: struct #packed {
	name: u32,
	type: u32,
	flags: u64,
	addr: u64,
	offset: u64,
	size: u64,
	link: u32,
	info: u32,
	addr_align: u64,
	entry_size: u64,
}

ELF_Section_Header :: struct {
	name: u32,
	type: Section_Header_Type,
	flags: u64,
	addr: u64,
	offset: u64,
	size: u64,
	link: u32,
	info: u32,
	addr_align: u64,
	entry_size: u64,
}

ELF32_Program_Header :: struct #packed {
	type: u32,
	offset: u32,
	virtual_addr: u32,
	physical_addr: u32,
	file_size: u32,
	mem_size: u32,
	flags: u32,
	align: u32,
}

ELF64_Program_Header :: struct #packed {
	type: u32,
	flags: u32,
	offset: u64,
	virtual_addr: u64,
	physical_addr: u64,
	file_size: u64,
	mem_size: u64,
	align: u64,
}

ELF_Program_Header :: struct {
	type: Section_Type,
	flags:         u32,
	offset:        u64,
	virtual_addr:  u64,
	physical_addr: u64,
	file_size:     u64,
	mem_size:      u64,
	align:         u64,
}

ELF32_Dyn :: struct #packed {
	tag: i32,
	val: u32,
}

ELF64_Dyn :: struct #packed {
	tag: i64,
	val: u64,
}

ELF_Dynamic :: struct {
	tag: i64,
	val: u64,
}

ELF32_Sym :: struct #packed {
	name:  u32,
	value: u32,
	size:  u32,
	info:  u8,
	other: u8,
	shndx: u16,
}

ELF64_Sym :: struct #packed {
	name:  u32,
	info:  u8,
	other: u8,
	shndx: u16,
	value: u64,
	size:  u64,
}

ELF_Symbol :: struct {
	name:  u32,
	info:  u8,
	other: u8,
	shndx: u16,
	value: u64,
	size:  u64,
}

Section :: struct {
	name: string,
	type: Section_Header_Type,
	link: u32,

	flags: u64,
	data: []u8,
	file_offset: u64,
	virtual_addr: u64,
	addr_alignment: u64,

	children: []uint,
}

ELF_Context :: struct {
	little_endian: bool,
	bits_64: bool,
	target_abi: Target_ABI,
	file_type: File_Type,
	isa: Processor_Type,
}

fe_to_ne :: #force_inline proc(is_little_endian: bool, value: $T) -> T where intrinsics.type_is_integer(T) {
	if (ODIN_ENDIAN == .Little) != is_little_endian {
		return intrinsics.byte_swap(value)
	}

	return value
}

get_common_header_size :: proc(ctx: ^ELF_Context) -> int {
	if ctx.bits_64 {
		return size_of(ELF64_Header)
	} else {
		return size_of(ELF32_Header)
	}
}

parse_common_header :: proc(ctx: ^ELF_Context, blob: []u8) -> (ELF_Header, bool) {
	common_hdr := ELF_Header{}
	if ctx.bits_64 {
		hdr, ek := slice_to_type(blob, ELF64_Header)
		if !ek {
			return {}, false
		}

		common_hdr.program_hdr_offset     = fe_to_ne(ctx.little_endian, hdr.program_hdr_offset)
		common_hdr.program_hdr_num        = fe_to_ne(ctx.little_endian, hdr.program_hdr_num)
		common_hdr.program_hdr_entry_size = fe_to_ne(ctx.little_endian, hdr.program_hdr_entry_size)
		common_hdr.section_hdr_offset     = fe_to_ne(ctx.little_endian, hdr.section_hdr_offset)
		common_hdr.section_hdr_str_idx    = fe_to_ne(ctx.little_endian, hdr.section_hdr_str_idx)
		common_hdr.section_hdr_num        = fe_to_ne(ctx.little_endian, hdr.section_hdr_num)
		common_hdr.section_entry_size     = fe_to_ne(ctx.little_endian, hdr.section_entry_size)

		ctx.isa        = Processor_Type(hdr.machine)
		ctx.file_type  = File_Type(hdr.type)
	} else {
		hdr, ek := slice_to_type(blob, ELF32_Header)
		if !ek {
			return {}, false
		}

		common_hdr.program_hdr_offset     = u64(fe_to_ne(ctx.little_endian, hdr.program_hdr_offset))
		common_hdr.program_hdr_num        = fe_to_ne(ctx.little_endian, hdr.program_hdr_num)
		common_hdr.program_hdr_entry_size = fe_to_ne(ctx.little_endian, hdr.program_hdr_entry_size)
		common_hdr.section_hdr_offset     = u64(fe_to_ne(ctx.little_endian, hdr.section_hdr_offset))
		common_hdr.section_hdr_str_idx    = fe_to_ne(ctx.little_endian, hdr.section_hdr_str_idx)
		common_hdr.section_hdr_num        = fe_to_ne(ctx.little_endian, hdr.section_hdr_num)
		common_hdr.section_entry_size     = fe_to_ne(ctx.little_endian, hdr.section_entry_size)

		ctx.isa        = Processor_Type(hdr.machine)
		ctx.file_type  = File_Type(hdr.type)
	}

	return common_hdr, true
}

get_section_header_size :: proc(ctx: ^ELF_Context) -> int {
	if ctx.bits_64 {
		return size_of(ELF64_Section_Header)
	} else {
		return size_of(ELF32_Section_Header)
	}
}

parse_section_header :: proc(ctx: ^ELF_Context, blob: []u8) -> (ELF_Section_Header, bool) {
	cmn_hdr := ELF_Section_Header{}
	if ctx.bits_64 {
		hdr, strk := slice_to_type(blob, ELF64_Section_Header)
		if !strk {
			return {}, false
		}

		cmn_hdr.name       = fe_to_ne(ctx.little_endian, hdr.name)
		cmn_hdr.type       = Section_Header_Type(fe_to_ne(ctx.little_endian, hdr.type))
		cmn_hdr.flags      = fe_to_ne(ctx.little_endian, hdr.flags)
		cmn_hdr.addr       = fe_to_ne(ctx.little_endian, hdr.addr)
		cmn_hdr.offset     = fe_to_ne(ctx.little_endian, hdr.offset)
		cmn_hdr.size       = fe_to_ne(ctx.little_endian, hdr.size)
		cmn_hdr.link       = fe_to_ne(ctx.little_endian, hdr.link)
		cmn_hdr.info       = fe_to_ne(ctx.little_endian, hdr.info)
		cmn_hdr.addr_align = fe_to_ne(ctx.little_endian, hdr.addr_align)
		cmn_hdr.entry_size = fe_to_ne(ctx.little_endian, hdr.entry_size)
	} else {
		hdr, strk := slice_to_type(blob, ELF32_Section_Header)
		if !strk {
			return {}, false
		}

		cmn_hdr.name       = fe_to_ne(ctx.little_endian, hdr.name)
		cmn_hdr.type       = Section_Header_Type(fe_to_ne(ctx.little_endian, hdr.type))
		cmn_hdr.flags      = u64(fe_to_ne(ctx.little_endian, hdr.flags))
		cmn_hdr.addr       = u64(fe_to_ne(ctx.little_endian, hdr.addr))
		cmn_hdr.offset     = u64(fe_to_ne(ctx.little_endian, hdr.offset))
		cmn_hdr.size       = u64(fe_to_ne(ctx.little_endian, hdr.size))
		cmn_hdr.link       = fe_to_ne(ctx.little_endian, hdr.link)
		cmn_hdr.info       = fe_to_ne(ctx.little_endian, hdr.info)
		cmn_hdr.addr_align = u64(fe_to_ne(ctx.little_endian, hdr.addr_align))
		cmn_hdr.entry_size = u64(fe_to_ne(ctx.little_endian, hdr.entry_size))
	}

	return cmn_hdr, true
}

get_symbol_size :: proc(ctx: ^ELF_Context) -> int {
	if ctx.bits_64 {
		return size_of(ELF64_Sym)
	} else {
		return size_of(ELF32_Sym)
	}
}

parse_symbol :: proc(ctx: ^ELF_Context, blob: []u8) -> (ELF_Symbol, bool) {
	iter_size := 0

	cmn_sym := ELF_Symbol{}
	if ctx.bits_64 {
		sym, strk := slice_to_type(blob, ELF64_Sym)
		if !strk {
			return {}, false
		}

		cmn_sym.name  = fe_to_ne(ctx.little_endian, sym.name)
		cmn_sym.info  = sym.info
		cmn_sym.other = sym.other
		cmn_sym.shndx = fe_to_ne(ctx.little_endian, sym.shndx)
		cmn_sym.value = fe_to_ne(ctx.little_endian, sym.value)
		cmn_sym.size  = fe_to_ne(ctx.little_endian, sym.size)
	} else {
		sym, strk := slice_to_type(blob, ELF32_Sym)
		if !strk {
			return {}, false
		}

		cmn_sym.name  = fe_to_ne(ctx.little_endian, sym.name)
		cmn_sym.info  = sym.info
		cmn_sym.other = sym.other
		cmn_sym.shndx = fe_to_ne(ctx.little_endian, sym.shndx)
		cmn_sym.value = u64(fe_to_ne(ctx.little_endian, sym.value))
		cmn_sym.size  = u64(fe_to_ne(ctx.little_endian, sym.size))
	}

	return cmn_sym, true

}

get_dynamic_size :: proc(ctx: ^ELF_Context) -> int {
	if ctx.bits_64 {
		return size_of(ELF64_Dyn)
	} else {
		return size_of(ELF32_Dyn)
	}
}

parse_dynamic :: proc(ctx: ^ELF_Context, blob: []u8) -> (ELF_Dynamic, bool) {
	cmn_dyn := ELF_Dynamic{}
	if ctx.bits_64 {
		dyn, ok := slice_to_type(blob, ELF64_Dyn)
		if !ok {
			return {}, false
		}

		cmn_dyn.tag = fe_to_ne(ctx.little_endian, dyn.tag)
		cmn_dyn.val = fe_to_ne(ctx.little_endian, dyn.val)
	} else {
		dyn, ok := slice_to_type(blob, ELF32_Dyn)
		if !ok {
			return {}, false
		}

		cmn_dyn.tag = i64(fe_to_ne(ctx.little_endian, dyn.tag))
		cmn_dyn.val = u64(fe_to_ne(ctx.little_endian, dyn.val))
	}

	return cmn_dyn, true

}

load_elf :: proc(trace: ^Trace, binary_blob: []u8, bucket: ^Func_Bucket) -> bool {
	pre_hdr, rk := slice_to_type(binary_blob, ELF_Pre_Header)
	if !rk {
		return false
	}

	ctx := ELF_Context{}
	if pre_hdr.class == ELFCLASS64 {
		ctx.bits_64 = true
	} else if pre_hdr.class == ELFCLASS32 {
		ctx.bits_64 = false
	} else {
		return false
	}

	if pre_hdr.endian == ELFDATA2LSB {
		ctx.little_endian = true
	} else if pre_hdr.endian == ELFDATA2MSB {
		ctx.little_endian = false
	} else {
		return false
	}
	ctx.target_abi = Target_ABI(pre_hdr.target_abi)

	common_hdr, ok := parse_common_header(&ctx, binary_blob)
	if !ok {
		return false
	}

	if common_hdr.section_hdr_offset > u64(len(binary_blob)) {
		return false
	}

	str_table_hdr_idx := common_hdr.section_hdr_offset + u64(common_hdr.section_hdr_str_idx * common_hdr.section_entry_size)
	if str_table_hdr_idx > u64(len(binary_blob)) {
		return false
	}

	str_table_hdr, strk := parse_section_header(&ctx, binary_blob[str_table_hdr_idx:])
	if !strk {
		return false
	}

	if str_table_hdr.type != Section_Header_Type.strtab {
		return false
	}

	if str_table_hdr.offset > u64(len(binary_blob)) {
		return false
	}

	section_header_array_size := int(common_hdr.section_hdr_num) * int(common_hdr.section_entry_size)
	section_header_blob := binary_blob[int(common_hdr.section_hdr_offset):int(common_hdr.section_hdr_offset)+section_header_array_size]

	sym_buffer := []u8{}
	str_buffer := []u8{}
	sections := Sections{}
	use_aslr := false

	for i := 0; i < section_header_array_size; i += int(common_hdr.section_entry_size) {
		section_hdr, sk := parse_section_header(&ctx, section_header_blob[i:])
		if !sk {
			return false
		}

		if section_hdr.offset > u64(len(binary_blob)) {
			return false
		}

		section_name_blob := binary_blob[str_table_hdr.offset + u64(section_hdr.name):]
		if section_name_blob[0] == 0 {
			continue
		}

		addr := section_hdr.addr
		start := section_hdr.offset
		size := section_hdr.size
		section_name := string(cstring(raw_data(section_name_blob)))
		switch section_name {
		case ".dynamic":
			dyn_section := create_subbuffer(binary_blob, start, size) or_return
			dyn_size := get_dynamic_size(&ctx)

			for i := 0; i < len(dyn_section); i += dyn_size {
				dyn_entry := parse_dynamic(&ctx, dyn_section[i:]) or_return
				if Dynamic_Type(dyn_entry.tag) == .flags_1 && (dyn_entry.val & u64(Dyn_Flags.pie) != 0) {
					use_aslr = true
				}
			}
		case ".symtab":
			sym_buffer = create_subbuffer(binary_blob, start, size) or_return
		case ".strtab":
			str_buffer = create_subbuffer(binary_blob, start, size) or_return
		case ".debug_line":
			sections.line = create_subbuffer(binary_blob, start, size) or_return
		case ".debug_str":
			sections.debug_str = create_subbuffer(binary_blob, start, size) or_return
		case ".debug_str_offsets":
			sections.str_offsets = create_subbuffer(binary_blob, start, size) or_return
		case ".debug_line_str":
			sections.line_str = create_subbuffer(binary_blob, start, size) or_return
		case ".debug_info":
			sections.info = create_subbuffer(binary_blob, start, size) or_return
		case ".debug_abbrev":
			sections.abbrev = create_subbuffer(binary_blob, start, size) or_return
		case ".debug_addr":
			sections.addr = create_subbuffer(binary_blob, start, size) or_return
		case ".debug_ranges":
			sections.ranges = create_subbuffer(binary_blob, start, size) or_return
		case ".debug_rnglists":
			sections.rnglists = create_subbuffer(binary_blob, start, size) or_return
		}
	}

	tmp_buffer := make([]u8, 1024*1024, context.temp_allocator)
	sym_size := get_symbol_size(&ctx)
	for i := 0; i < len(sym_buffer); i += sym_size {
		symbol, ok := parse_symbol(&ctx, sym_buffer[i:])
		if !ok {
			return false
		}

		type := Symbol_Type(u8(symbol.info & 0xf))
		if type != .func || symbol.value == 0 {
			continue
		}

		symbol_name := string(cstring(raw_data(str_buffer[symbol.name:])))
		demangled_name, ok2 := demangle_symbol(symbol_name, tmp_buffer)
		if !ok2 {
			return false
		}
		sym_idx := in_get(&trace.intern, &trace.string_block, demangled_name)
		non_zero_append(&bucket.functions, Function{name = sym_idx, low_pc = u64(symbol.value), high_pc = u64(symbol.value)})
	}

	// This is apparently a thing in Old Linux?
	// file does this to determine if things are PIE before the PIE flag was invented
	if !use_aslr && ctx.file_type == .shared_obj {
		use_aslr = true
	}

	if !use_aslr {
		fmt.printf("ELF: Your binary is not relocatable, disabling ASLR correction\n")
		bucket.base_address = 0
	}

	// Start parsing DWARF normally from here
	if !load_dwarf(trace, &sections, bucket, 0) {
		fmt.printf("DWARF parsing failed!\n")
	}

	return true
}
