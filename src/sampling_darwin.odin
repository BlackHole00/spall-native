#+build darwin
 
package main

import "base:runtime"

import "core:fmt"
import "core:os"
import "core:os/os2"
import "core:path/filepath"
import "core:time"
import "core:slice"
import "core:strings"
import "core:sys/posix"
import "core:sys/darwin"

Segment_Range :: struct {
	file_off: u64,
	file_size: u64,
	mem_off: u64,
	mem_size: u64,

	mem_start: u64,
	mem_end: u64,
}

ARM_Compact_Unwind_Op :: struct {
	type: Mach_ARM_Unwind_Op_Type,
	addr: u32,
	len: u32,

	stack_size: u64,
}

Mach_Recv_Msg :: struct {
	header:    darwin.mach_msg_header_t,
	body:      darwin.mach_msg_body_t,
	task_port: darwin.mach_msg_port_descriptor_t,
	trailer:   darwin.mach_msg_trailer_t,
}

Mach_Send_Msg :: struct {
	header:    darwin.mach_msg_header_t,
	body:      darwin.mach_msg_body_t,
	task_port: darwin.mach_msg_port_descriptor_t,
}

Sample :: struct {
	ts:       i64,
	callstack: [dynamic]u64,
}

Sample_Thread :: struct {
	samples: [dynamic]Sample,
	max_depth: int,
}

UUID :: [16]u8

Sample_State :: struct {
	threads: map[u64]Sample_Thread,
	program_path: string,

	my_task: darwin.task_t,
	child_task: darwin.task_t,
	child_pid: posix.pid_t,

	processed_dyld: bool,
	shared_cache_uuid: UUID,
	dylib_uuid_to_bucket: map[UUID]^Func_Bucket,
}

map_child_mem :: proc(my_task: darwin.task_t, child_task: darwin.task_t, addr: u64, $T: typeid) -> (val: ^T, ok: bool) {
	start_addr := addr
	end_addr   := addr + size_of(T)

	page_start_addr := darwin.mach_vm_trunc_page(start_addr)
	page_end_addr   := darwin.mach_vm_trunc_page(end_addr) + darwin.vm_page_size
	full_size := page_end_addr - page_start_addr

	data: [^]u8
	cur_prot : i32 = (i32)(darwin.VM_PROT_NONE)
	max_prot : i32 = (i32)(darwin.VM_PROT_NONE)
	if darwin.mach_vm_remap(my_task, &data, full_size, 0, 1, child_task, page_start_addr, false, &cur_prot, &max_prot, .Share) != .Success {
		return
	}

	start_shim := start_addr - page_start_addr
	mem_blob := data[start_shim:]
	return transmute(^T)mem_blob, true
}
unmap_child_mem :: proc(my_task: darwin.task_t, orig_addr: u64, mem: $T) {
	mem_addr := darwin.mach_vm_trunc_page(u64(uintptr(mem)))
	mem_ptr := transmute([^]u64)rawptr(uintptr(mem_addr))

	start_addr := orig_addr
	end_addr   := orig_addr + size_of(mem^)

	start_addr = darwin.mach_vm_trunc_page(start_addr)
	end_addr   = darwin.mach_vm_trunc_page(end_addr) + darwin.vm_page_size
	full_size := end_addr - start_addr

	darwin.mach_vm_deallocate(my_task, mem_ptr, full_size)
}

map_child_slice :: proc(my_task: darwin.task_t, child_task: darwin.task_t, addr: u64, size: u64) -> (val: []u8, ok: bool) {
	start_addr := addr
	end_addr   := addr + size

	page_start_addr := darwin.mach_vm_trunc_page(start_addr)
	page_end_addr   := darwin.mach_vm_trunc_page(end_addr) + darwin.vm_page_size
	full_size := page_end_addr - page_start_addr

	data: [^]u8
	cur_prot : i32 = (i32)(darwin.VM_PROT_NONE)
	max_prot : i32 = (i32)(darwin.VM_PROT_NONE)
	if darwin.mach_vm_remap(my_task, &data, full_size, 0, 1, child_task, page_start_addr, false, &cur_prot, &max_prot, .Share) != .Success {
		return
	}

	start_shim := start_addr - page_start_addr
	buf := data[start_shim:]
	ret_buf := slice.from_ptr(buf, int(size))
	return ret_buf, true
}
unmap_child_slice :: proc(my_task: darwin.task_t, orig_addr: u64, mem: []u8) {
	mem_addr := darwin.mach_vm_trunc_page(u64(uintptr(raw_data(mem))))
	mem_ptr := transmute([^]u64)rawptr(uintptr(mem_addr))

	start_addr := orig_addr
	end_addr   := orig_addr + u64(len(mem))

	start_addr = darwin.mach_vm_trunc_page(start_addr)
	end_addr   = darwin.mach_vm_trunc_page(end_addr) + darwin.vm_page_size
	full_size := end_addr - start_addr

	darwin.mach_vm_deallocate(my_task, mem_ptr, full_size)
}

sample_arm64_thread :: proc(trace: ^Trace, my_task: darwin.task_t, child_task: darwin.task_t, thread: darwin.thread_act_t, ts: u64, sample_thread: ^Sample_Thread) -> (_ok: bool) {
	state: darwin.arm_thread_state64_t
	state_count: u32 = darwin.ARM_THREAD_STATE64_COUNT
	if darwin.thread_get_state(thread, darwin.ARM_THREAD_STATE64, darwin.thread_state_t(&state), &state_count) != .Success {
		return
	}

	cur_depth := 0

	non_zero_append(&sample_thread.samples, Sample{ts = i64(ts), callstack = make([dynamic]u64)})
	callstack := &sample_thread.samples[len(sample_thread.samples)-1].callstack

	sp := state.sp
	fp := state.fp
	pc := state.pc

	walk_loop: for {
		if pc == 0 {
			//fmt.printf("Finished stack scan?\n")
			break walk_loop
		}
		non_zero_append(callstack, pc)
		cur_depth += 1
		sample_thread.max_depth = max(sample_thread.max_depth, cur_depth)

		cur_bucket, ok := get_bucket(trace, pc)
		if !ok {
			//fmt.printf("no bucket found for 0x%08x\n", pc)
			break walk_loop
		}

		unwind_op : ^ARM_Compact_Unwind_Op = nil
		for &entry in cur_bucket.unwind_info {
			check_addr := cur_bucket.base_address + u64(entry.addr)
			if pc >= check_addr && pc <= (check_addr + u64(entry.len)) {
				unwind_op = &entry
				break
			} else {
				//fmt.printf("skipping entry: %#v\n", entry)
			}
		}

		if unwind_op == nil {
//			fmt.printf("no unwind op found?\n")
			break walk_loop
		}

		#partial switch unwind_op.type {
		case .Frameless: 
			pc_slot_addr := state.lr + 8
			pc_slot, ok := map_child_mem(my_task, child_task, pc_slot_addr, u64)
			if !ok {
				//fmt.printf("failed to map mem: %x\n", pc_slot_addr)
				break walk_loop
			}
			defer unmap_child_mem(my_task, pc_slot_addr, pc_slot)

			pc = (^u64)(uintptr(pc_slot))^
		case .Framed: 
			pc_slot_addr := fp + 8
			pc_slot, ok := map_child_mem(my_task, child_task, pc_slot_addr, u64)
			if !ok {
				//fmt.printf("failed to map mem: %x\n", pc_slot_addr)
				break walk_loop
			}
			defer unmap_child_mem(my_task, pc_slot_addr, pc_slot)

			fp_slot_addr := fp
			fp_slot, ok2 := map_child_mem(my_task, child_task, fp_slot_addr, u64)
			if !ok2 {
				//fmt.printf("failed to map mem: %x\n", fp_slot_addr)
				break walk_loop
			}
			defer unmap_child_mem(my_task, fp_slot_addr, fp_slot)

			pc = (^u64)(uintptr(pc_slot))^
			fp = (^u64)(uintptr(fp_slot))^

		// We don't have a rule, so we're gonna YOLO things.
		case .None:
			pc_slot_addr := fp + 8
			pc_slot, ok := map_child_mem(my_task, child_task, pc_slot_addr, u64)
			if !ok {
				//fmt.printf("failed to map mem: %x\n", pc_slot_addr)
				break walk_loop
			}
			defer unmap_child_mem(my_task, pc_slot_addr, pc_slot)

			fp_slot_addr := fp
			fp_slot, ok2 := map_child_mem(my_task, child_task, fp_slot_addr, u64)
			if !ok2 {
				//fmt.printf("failed to map mem: %x\n", fp_slot_addr)
				break walk_loop
			}
			defer unmap_child_mem(my_task, fp_slot_addr, fp_slot)

			pc = (^u64)(uintptr(pc_slot))^
			fp = (^u64)(uintptr(fp_slot))^
		case:
/*
			func_name_idx, ok := get_function_name(trace, pc)
			func_name := ""
			if ok {
				func_name = in_getstr(&trace.string_block, func_name_idx)
			}
			fmt.printf("Unhandled Unwind op %#v for 0x%08x | base address: 0x%08x | %s | %s\n", unwind_op, pc, cur_bucket.base_address, cur_bucket.source_path, func_name)
*/
			break walk_loop
		}
	}

	return true

/*
	//fmt.printf("starting sample\n")
	fp := state.fp
	sp := state.sp
	pc := state.pc
	for {
		//fmt.printf("pc: %x | sp: %x | fp: %x\n", pc, sp, fp)

		// If the frame pointer is 0, we're at the top of the stack
		if fp == 0 {
			return true
		}

		// base pointer should be aligned
		if fp % 8 != 0 {
			return false
		}

		slot, ok := map_child_mem(my_task, child_task, fp, u64)
		if !ok {
			fmt.printf("failed to map mem: %x\n", fp)
			return false
		}

		non_zero_append(callstack, fp)
		cur_depth += 1
		sample_thread.max_depth = max(sample_thread.max_depth, cur_depth)

		new_fp := (^u64)(uintptr(slot))^
		pc = (^u64)(uintptr(u64(uintptr(slot)) + 8))^
		sp = u64(uintptr(slot) + 16)
		unmap_child_mem(my_task, fp, slot)

		fp = new_fp
	}

    return true
*/
}

sample_x86_thread :: proc(trace: ^Trace, my_task: darwin.task_t, child_task: darwin.task_t, thread: darwin.thread_act_t, ts: u64, sample_thread: ^Sample_Thread) -> (ok: bool) {
	state: darwin.x86_thread_state64_t
	state_count: u32 = darwin.X86_THREAD_STATE64_COUNT
	if darwin.thread_get_state(thread, darwin.X86_THREAD_STATE64, darwin.thread_state_t(&state), &state_count) != .Success {
		return
	}

	cur_depth := 1

	non_zero_append(&sample_thread.samples, Sample{ts = i64(ts), callstack = make([dynamic]u64)})
	callstack := &sample_thread.samples[len(sample_thread.samples)-1].callstack
	non_zero_append(callstack, state.rip)
	sample_thread.max_depth = max(sample_thread.max_depth, cur_depth)

	sp := state.rsp
	bp := state.rbp
	for {

		// If the base pointer is 0, we're at the top of the stack
		if bp == 0 {
			return true
		}

		// base pointer should be aligned
		if bp % 8 != 0 {
			return false
		}

		slot := map_child_mem(my_task, child_task, bp, u64) or_return

		non_zero_append(callstack, bp)
		cur_depth += 1
		sample_thread.max_depth = max(sample_thread.max_depth, cur_depth)

		new_bp := slot^
		unmap_child_mem(my_task, bp, slot)

		bp = new_bp
	}

	return true
}

adjust_offset :: proc(file_offset: u64, text_seg: ^Segment_Range) -> (u64, bool) {
	if val_in_range(file_offset, text_seg.file_off, text_seg.file_off + text_seg.file_size) {
		adj_offset := text_seg.mem_off + (file_offset - text_seg.file_off)
		return adj_offset, true
	}

	return 0, false
}

process_object :: proc(trace: ^Trace, my_task: darwin.task_t, child_task: darwin.task_t, sample_state: ^Sample_State, file_path: string, load_addr: u64, shared_cache_slide: u64, tmp_buffer: []u8) -> bool {
	header := map_child_mem(my_task, child_task, load_addr, Mach_Header_64) or_return

	cmd_start_addr := load_addr + size_of(header^)
	header_and_cmds_size := size_of(header^) + u64(header.cmd_size)
	defer unmap_child_mem(my_task, load_addr, header)

	is_dyld := (header.file_type == MACH_FILETYPE_DYLD)
	is_executable := (header.file_type == MACH_FILETYPE_EXEC)
	is_dylib := (header.file_type == MACH_FILETYPE_DYLIB)
	in_shared_cache := (header.flags & MACH_DYLIB_IN_CACHE) != 0

	blank_uuid := UUID{}
	if in_shared_cache && sample_state.shared_cache_uuid != blank_uuid {
		return true
	}

	uuid_cmd := Mach_UUID_Command{}
	symtab_cmd := Mach_Symtab_Command{}
	header_and_cmds := map_child_slice(my_task, child_task, load_addr, header_and_cmds_size) or_return
	defer unmap_child_slice(my_task, load_addr, header_and_cmds)

	symtab_header := Mach_Symtab_Command{}

	text_seg := Segment_Range{}
	linkedit_seg := Segment_Range{}
	unwind_seg := Segment_Range{}
	has_unwind_info := false
	uuid := [16]u8{}

	func_starts_hdr := Mach_Linkedit_Data_Command{}
	has_func_starts := false

	cmd_count := 0
	sect_count := 0
	text_sect_idx := 0

	j := size_of(Mach_Header_64)
	for j < len(header_and_cmds) {
		current_buffer := header_and_cmds[j:]
		cmd := slice_to_type(current_buffer, Mach_Load_Command) or_return
		if cmd.size == 0 {
			return false
		}

		//fmt.printf("%v | got command [type %v (0x%08x), size: %v]\n", cmd_count, cmd.type, u32(cmd.type), cmd.size)
		cmd_count += 1
		#partial switch cmd.type {
		case .Segment_64:
			seg_hdr := slice_to_type(current_buffer, Mach_Segment_64_Command) or_return

			mem_skew : u64 = 0
			if in_shared_cache {
				mem_skew = shared_cache_slide
			}

			seg := Segment_Range{
				file_off  = seg_hdr.file_offset,
				file_size = seg_hdr.file_size,
				mem_off   = seg_hdr.address + mem_skew,
				mem_size  = seg_hdr.mem_size,
			}
			seg.mem_start = seg.mem_off
			seg.mem_end = seg.mem_off + seg.mem_size

			seg_name := strings.string_from_null_terminated_ptr(raw_data(seg_hdr.name[:]), 16)

			seg_min := max(u64)
			seg_max := min(u64)

			sections := slice.reinterpret([]Mach_Section, header_and_cmds[j + size_of(Mach_Segment_64_Command):][:int(cmd.size)])
			for &section in sections {
				sect_count += 1

				seg_min = min(seg_min, section.address)
				seg_max = max(seg_max, section.address + section.size)

				section_name := strings.string_from_null_terminated_ptr(raw_data(&section.name), 16)
				if section_name == "__unwind_info" {
					unwind_seg = Segment_Range{
						file_off  = u64(section.offset),
						file_size = section.size,
						mem_off   = u64(section.address) + mem_skew,
						mem_size  = section.size,
					}
					has_unwind_info = true
				} else if section_name == "__text" {
					text_sect_idx = sect_count
				}
			}
			seg.mem_start = seg_min + mem_skew
			seg.mem_end = seg_max + mem_skew

			if seg_name == "__TEXT" {
				text_seg = seg
			} else if seg_name == "__LINKEDIT" {
				linkedit_seg = seg
			}

/*
			fmt.printf("segment %s\n", seg_name)
			fmt.printf("0x%016x -> 0x%016x\n", seg.file_off, seg.file_off + seg.file_size)
			fmt.printf("0x%016x -> 0x%016x\n", seg.mem_off, seg.mem_off + seg.mem_size)
*/
		case .UUID:
			uuid_cmd = slice_to_type(current_buffer, Mach_UUID_Command) or_return
			uuid = uuid_cmd.uuid

		case .Symtab:
			symtab_header = slice_to_type(current_buffer, Mach_Symtab_Command) or_return
/*
			fmt.printf("symtab @ 0x%016x, count: %d\n", symtab_header.symbol_table_offset, symtab_header.symbol_count)
			fmt.printf("strtab @ 0x%016x, size: 0x%016x\n", symtab_header.string_table_offset, symtab_header.string_table_size)
*/
		case .Function_Starts:
			func_starts_hdr = slice_to_type(current_buffer, Mach_Linkedit_Data_Command) or_return
			has_func_starts = true
		}
		
		j += int(cmd.size)
	}

	_, found_uuid := sample_state.dylib_uuid_to_bucket[uuid]
	if found_uuid {
		return true
	}

	load_skew : u64 = 0
	if !in_shared_cache {
		load_skew = load_addr - text_seg.mem_off
	}

	symbol_table_size := u64(symtab_header.symbol_count) * size_of(Mach_Symbol_Entry_64)
	sym_table_offset  := adjust_offset(u64(symtab_header.symbol_table_offset), &linkedit_seg) or_return
	symbol_table_addr := load_skew + sym_table_offset
	symbol_table_bytes, ok := map_child_slice(my_task, child_task, symbol_table_addr, symbol_table_size)
	if !ok {
		fmt.printf("invalid symbol table addr 0x%016x for %s\n", symbol_table_addr, file_path)
		return false
	}
	defer unmap_child_slice(my_task, symbol_table_addr, symbol_table_bytes)

	string_table_size := u64(symtab_header.string_table_size)
	string_table_offset := adjust_offset(u64(symtab_header.string_table_offset), &linkedit_seg) or_return
	string_table_addr := load_skew + string_table_offset
	string_table, ok2 := map_child_slice(my_task, child_task, string_table_addr, string_table_size)
	if !ok2 {
		fmt.printf("invalid string table addr 0x%016x for %s\n", string_table_addr, file_path)
		return false
	}
	defer unmap_child_slice(my_task, string_table_addr, string_table)

	unwind_table := make([dynamic]ARM_Compact_Unwind_Op)
	if has_unwind_info {
		unwind_info_addr := load_skew + unwind_seg.mem_off
		unwind_info_bytes, ok4 := map_child_slice(my_task, child_task, unwind_info_addr, unwind_seg.mem_size)
		if !ok4 {
			fmt.printf("invalid unwind info addr 0x%016x for %s\n", unwind_info_addr, file_path)
			return false
		}
		defer unmap_child_slice(my_task, unwind_info_addr, unwind_info_bytes)

		unwind_hdr := slice_to_type(unwind_info_bytes, Mach_Unwind_Info_Header) or_return

		pages_end_offset := unwind_hdr.pages_offset + (unwind_hdr.pages_len * size_of(Mach_Page_Entry))
		global_opcodes := slice.reinterpret([]u32, unwind_info_bytes[unwind_hdr.global_opcodes_offset:][:(unwind_hdr.global_opcodes_len * size_of(u32))])
		pages          := slice.reinterpret([]Mach_Page_Entry, unwind_info_bytes[unwind_hdr.pages_offset:][:(unwind_hdr.pages_len) * size_of(Mach_Page_Entry)])
		for page in pages {
			if page.subpage_offset == 0 {
				if len(unwind_table) > 0 {
					prev_entry := &unwind_table[len(unwind_table)-1]
					prev_entry.len = u32(u64(page.first_addr) - u64(prev_entry.addr))
				}
				continue
			}

			subpage_type := slice_to_type(unwind_info_bytes[page.subpage_offset:], Mach_Subpage_Kind) or_return
			//fmt.printf("0x%08x | 0x%08x | %v\n", page.first_addr, page.subpage_offset, subpage_type)

			#partial switch subpage_type {
			case .Compressed:
				subpage := slice_to_type(unwind_info_bytes[page.subpage_offset:], Mach_Compressed_Subpage) or_return
				local_opcodes := slice.reinterpret([]u32, unwind_info_bytes[page.subpage_offset + u32(subpage.local_opcodes_offset):][:(subpage.local_opcodes_len * size_of(u32))])

				entries := slice.reinterpret([]u32, unwind_info_bytes[page.subpage_offset + u32(subpage.entries_offset):][:subpage.entries_len * size_of(u32)])
				for entry, idx in entries {
					op_idx := entry >> 24
					addr := entry << 8 >> 8

					op := u32(0)
					if op_idx < u32(len(global_opcodes)) {
						op = global_opcodes[op_idx]
					} else {
						local_idx := op_idx - u32(len(global_opcodes))
						op = local_opcodes[local_idx]
					}

					is_start := (op & (1 << 31)) != 0
					has_lsda := (op & (1 << 30)) != 0
					personality_idx := (op >> 28) & 0b11
					opcode := (op >> 24) & 0b1111

					unwind_op_type := Mach_ARM_Unwind_Op_Type(opcode)

					cfi_op := ARM_Compact_Unwind_Op{
						type = unwind_op_type,
						addr = page.first_addr + addr,
					}

					if idx > 0 {
						prev_entry := &unwind_table[len(unwind_table)-1]
						prev_entry.len = u32(u64(cfi_op.addr) - u64(prev_entry.addr))
						if file_path == "/Users/cloin/Desktop/renpy-8.4.1-sdk/lib/py3-mac-universal/librenpython.dylib" {
							//fmt.printf("0x%08x - %v | %v\n", prev_entry.addr, prev_entry.len, prev_entry.type)
						}
					}

					#partial switch unwind_op_type {
					case .Frameless:
						stack_size := ((op >> 12) & 0xFFF) * 16
						cfi_op.stack_size = u64(stack_size)
					}

					non_zero_append(&unwind_table, cfi_op)
				}
			case .Regular:
				subpage := slice_to_type(unwind_info_bytes[page.subpage_offset:], Mach_Regular_Subpage) or_return

				entries := slice.reinterpret([]Mach_Regular_Entry, unwind_info_bytes[page.subpage_offset + u32(subpage.entries_offset):][:subpage.entries_len * size_of(Mach_Regular_Entry)])
				for entry, idx in entries {

					op := entry.opcode
					is_start := (op & (1 << 31)) != 0
					has_lsda := (op & (1 << 30)) != 0
					personality_idx := (op >> 28) & 0b11
					opcode := (op >> 24) & 0b1111

					unwind_op_type := Mach_ARM_Unwind_Op_Type(opcode)
					cfi_op := ARM_Compact_Unwind_Op{
						type = unwind_op_type,
						addr = entry.inst_addr,
					}

					if idx > 0 {
						prev_entry := &unwind_table[len(unwind_table)-1]
						prev_entry.len = u32(u64(cfi_op.addr) - u64(prev_entry.addr))
						if file_path == "/Users/cloin/Desktop/renpy-8.4.1-sdk/lib/py3-mac-universal/librenpython.dylib" {
							//fmt.printf("0x%08x - %v | %v\n", prev_entry.addr, prev_entry.len, prev_entry.type)
						}
					}

					#partial switch unwind_op_type {
					case .Frameless:
						stack_size := ((op >> 12) & 0xFFF) * 16
						cfi_op.stack_size = u64(stack_size)
					}

					non_zero_append(&unwind_table, cfi_op)
				}
			case:
				fmt.printf("unhandled subpage type %v (%v)\n", subpage_type, u32(subpage_type))
				return false
			}
		}
	}

	if file_path == "/Users/cloin/Desktop/renpy-8.4.1-sdk/lib/py3-mac-universal/librenpython.dylib" {
/*
		fmt.printf("unwind for %s\n", file_path)
		for unwind in unwind_table {
			fmt.printf("0x%08x - %v | %v\n", unwind.addr, unwind.len, unwind.type)
		}
		return false
*/
	}


	// Ingest Function Starts... This is supposed to be better than
	// guessing with symbol addresses. Who knows?

	base_address := text_seg.mem_off
	if !is_executable && !in_shared_cache {
		base_address = load_addr
	}
	bucket := new_func_bucket(&trace.func_buckets, strings.clone(file_path), base_address)
	bucket.unwind_info = unwind_table[:]

	text_start := text_seg.mem_start
	text_end := text_seg.mem_end
	if !in_shared_cache {
		text_start = load_addr + (text_seg.mem_start - text_seg.mem_off)
		text_end   = load_addr + (text_seg.mem_end   - text_seg.mem_off)
	}

	if has_func_starts {
		func_starts_size := u64(func_starts_hdr.file_size)
		func_starts_offset := adjust_offset(u64(func_starts_hdr.file_off), &linkedit_seg) or_return
		func_starts_addr  := load_skew + func_starts_offset

		func_starts_bytes, ok3 := map_child_slice(my_task, child_task, func_starts_addr, func_starts_size)
		if !ok3 {
			fmt.printf("invalid func starts addr 0x%016x for %s\n", func_starts_addr, file_path)
			return false
		}
		defer unmap_child_slice(my_task, func_starts_addr, func_starts_bytes)

		prev_addr : u64 = 0

		rdr := stream_init(func_starts_bytes)
		for rdr.idx < len(func_starts_bytes) {
			addr_dt := stream_uleb(&rdr) or_return
			if addr_dt == 0 {
				break
			}

			cur_addr := prev_addr + addr_dt
			if prev_addr == 0 {
				prev_addr = cur_addr
				continue
			}

			skew := base_address
			if is_executable {
				skew += load_skew
			}

			func_start_addr := prev_addr + skew
			func_end_addr   := cur_addr + skew
			//fmt.printf("start: 0x%08x || 0x%08x || 0x%08x\n", prev_addr, func_start_addr, load_addr)

			bucket.scopes.low_pc = min(bucket.scopes.low_pc, func_start_addr)
			non_zero_append(&bucket.functions, Function{name = 0, low_pc = func_start_addr, high_pc = func_end_addr})
			prev_addr = cur_addr
		}

		skew := base_address
		if is_executable {
			skew += load_skew
		}
		func_start_addr := prev_addr + skew
		//fmt.printf("start: 0x%08x || 0x%08x || 0x%08x\n", prev_addr, func_start_addr, load_addr)

		bucket.scopes.low_pc = min(bucket.scopes.low_pc, func_start_addr)
		bucket.scopes.high_pc = max(bucket.scopes.high_pc, text_end)
		non_zero_append(&bucket.functions, Function{name = 0, low_pc = func_start_addr, high_pc = text_end})
	}

	symbol_table := slice.reinterpret([]Mach_Symbol_Entry_64, symbol_table_bytes)

	for symbol in symbol_table {
		symbol_name := string(cstring(raw_data(string_table[symbol.string_table_idx:])))

		if symbol_name == "" || symbol.value == 0 || (symbol.type & 0xE0) != 0 || int(symbol.section_idx) != text_sect_idx {
			continue
		}

		sym_addr := load_skew + symbol.value
		if in_shared_cache {
			sym_addr = symbol.value + shared_cache_slide
		}
		//fmt.printf("val: 0x%08x\n", symbol.value)

		if !val_in_range(sym_addr, text_start, text_end) {
			continue
		}

		demangled_name, ok := demangle_symbol(symbol_name, tmp_buffer)
		if !ok {
			continue
		}

		sym_idx := in_get(&trace.intern, &trace.string_block, demangled_name)

		func := find_func_by_low_pc(bucket.functions[:], sym_addr)
		if func != nil {
			func.name = sym_idx
		}
	}

	for &func in bucket.functions {
		if func.name == 0 {
			func_name := fmt.tprintf("func_%v", trace.unnamed_count)
			trace.unnamed_count += 1
			func.name = in_get(&trace.intern, &trace.string_block, func_name)
		}
	}

	bucket.uuid = uuid
	sample_state.dylib_uuid_to_bucket[uuid] = bucket

/*
		debug_path := guess_debug_path(file_path)
		debug_buffer, ok10 := os.read_entire_file_from_filename(debug_path)
		if !ok10 {
			continue dylib_loop
		}
		defer delete(debug_buffer)

		if !load_macho_debug(trace, debug_buffer, bucket) {
			continue dylib_loop
		}
*/

	return true
}

process_dylibs :: proc(trace: ^Trace, my_task: darwin.task_t, child_task: darwin.task_t, sample_state: ^Sample_State) -> bool {

	dyld_info := darwin.task_dyld_info{}
	count : u32 = darwin.TASK_DYLD_INFO_COUNT
	if darwin.task_info(child_task, darwin.TASK_DYLD_INFO, darwin.task_info_t(&dyld_info), &count) != .Success {
		return false
	}

	image_infos := map_child_mem(my_task, child_task, dyld_info.all_image_info_addr, darwin.dyld_all_image_infos) or_return
	defer unmap_child_mem(my_task, dyld_info.all_image_info_addr, image_infos)

	tmp_buffer := make([]u8, 1024*1024, context.temp_allocator)
	if !sample_state.processed_dyld {
		dyld_file_path_addr := u64(uintptr(rawptr(image_infos.dyld_path)))
		dyld_file_path_bytes := map_child_mem(my_task, child_task, dyld_file_path_addr, [512]u8) or_return
		defer unmap_child_mem(my_task, dyld_file_path_addr, dyld_file_path_bytes)
		dyld_file_path_cstr := cstring(raw_data((dyld_file_path_bytes^)[:]))
		dyld_file_path := string(dyld_file_path_cstr)

		if !process_object(trace, my_task, child_task, sample_state, dyld_file_path, image_infos.dyld_image_load_addr, image_infos.shared_cache_slide, tmp_buffer) {
			fmt.printf("Failed to process dyld!\n")
			return false
		}
		sample_state.processed_dyld = true
	}

	uuid_array_addr := u64(uintptr(image_infos.uuid_array))
	uuid_array_bytes := map_child_slice(my_task, child_task, uuid_array_addr, image_infos.uuid_array_count * size_of(darwin.dyld_uuid_info)) or_return
	defer unmap_child_slice(my_task, uuid_array_addr, uuid_array_bytes)

	uuid_infos := slice.reinterpret([]darwin.dyld_uuid_info, uuid_array_bytes)

	loaded_all_dylibs := true
	for uuid_info in uuid_infos {
		_, ok := sample_state.dylib_uuid_to_bucket[uuid_info.image_uuid]
		if !ok {
			loaded_all_dylibs = false
			break
		}
	}

	if sample_state.shared_cache_uuid == image_infos.shared_cache_uuid && loaded_all_dylibs {
		return true
	}

	dylib_loop: for i : u64 = 0; i < u64(image_infos.info_array_count); i += 1 {
		info_array_entry_addr := u64(uintptr(image_infos.info_array)) + (i * size_of(darwin.dyld_image_info))
		info_entry, ok := map_child_mem(my_task, child_task, info_array_entry_addr, darwin.dyld_image_info)
		if !ok { continue dylib_loop }
		defer unmap_child_mem(my_task, info_array_entry_addr, info_entry)

		file_path_addr := u64(uintptr(rawptr(info_entry.image_file_path)))
		file_path_bytes, ok2 := map_child_mem(my_task, child_task, file_path_addr, [512]u8)
		if !ok2 { continue dylib_loop }
		defer unmap_child_mem(my_task, file_path_addr, file_path_bytes)

		file_path_cstr := cstring(raw_data((file_path_bytes^)[:]))
		file_path := string(file_path_cstr)

		if !process_object(trace, my_task, child_task, sample_state, file_path, info_entry.image_load_addr, image_infos.shared_cache_slide, tmp_buffer) {
			fmt.printf("failed to process %s\n", file_path)
			return false
		}
	}

	bucket_order :: proc(a, b: Func_Bucket) -> bool {
		return a.base_address < b.base_address
	}

	slice.sort_by(trace.func_buckets[:], bucket_order)
	for &bucket, idx in trace.func_buckets {
		if !build_scopes(trace, &bucket) {
			return false
		}
	}

	sample_state.shared_cache_uuid = image_infos.shared_cache_uuid
	return true
}

sample_task :: proc(trace: ^Trace, my_task: darwin.task_t, child_task: darwin.task_t, child_pid: posix.pid_t, sample_state: ^Sample_State) -> (_ok: bool) {
	ts := time.read_cycle_counter()
	if darwin.task_suspend(child_task) != .Success {
		return
	}

	defer {
		if _ok {
			darwin.task_resume(child_task)
		}
	}

	if !process_dylibs(trace, my_task, child_task, sample_state) {
		return
	}

	thread_list: darwin.thread_list_t
	thread_count: u32
	if darwin.task_threads(child_task, &thread_list, &thread_count) != .Success {
		return
	}

	//fmt.printf("0x%08x | sampling %v threads\n", ts, thread_count)
	for i : u32 = 0; i < thread_count; i += 1 {
		thread := thread_list[i]

		id_info := darwin.thread_identifier_info{}
		count : u32 = darwin.THREAD_IDENTIFIER_INFO_COUNT
		if darwin.thread_info(thread, darwin.THREAD_IDENTIFIER_INFO, &id_info, &count) != .Success {
			continue
		}

		sample_thread, ok := &sample_state.threads[id_info.thread_id]
		if !ok {
			sample_state.threads[id_info.thread_id] = Sample_Thread{max_depth = 0, samples = make([dynamic]Sample)}
			sample_thread, _ = &sample_state.threads[id_info.thread_id]
		}

		//fmt.printf("%d | %016d ", i, id_info.thread_id)
		if ODIN_ARCH == .amd64 {
			sample_x86_thread(trace, my_task, child_task, thread, ts, sample_thread) or_return
        } else if ODIN_ARCH == .arm64 {
            sample_arm64_thread(trace, my_task, child_task, thread, ts, sample_thread) or_return
		} else {
			fmt.printf("don't support yet!\n")
			continue
		}
	}

	return true
}

MachSampleSetup :: struct {
	has_setup:                    bool,
	my_task:             darwin.task_t,
	recv_port:      darwin.mach_port_t,
	bootstrap_port: darwin.mach_port_t,
}

sample_setup := MachSampleSetup{}
sample_child :: proc(trace: ^Trace, program_name: string, path: string, args: []string) -> (ok: bool) {
	if !sample_setup.has_setup {
		sample_setup.my_task = darwin.task_t(darwin.mach_task_self())
		if darwin.mach_port_allocate(sample_setup.my_task, .Receive, &sample_setup.recv_port) != .Success {
			fmt.printf("failed to allocate port\n")
			return
		}

		if darwin.task_get_special_port(sample_setup.my_task, i32(darwin.Task_Port_Type.Bootstrap), &sample_setup.bootstrap_port) != .Success {
			fmt.printf("failed to get special port\n")
			return
		}

		right: darwin.mach_port_t
		acquired_right: darwin.mach_port_t
		if darwin.mach_port_extract_right(sample_setup.my_task, u32(sample_setup.recv_port), u32(darwin.Msg_Type.Make_Send), &right, &acquired_right) != .Success {
			fmt.printf("failed to get right\n")
			return
		}

		k_err := darwin.bootstrap_register2(sample_setup.bootstrap_port, "SPALL_BOOTSTRAP", right, 0)
		if k_err != .Success {
			fmt.printf("failed to register bootstrap | got: %v\n", k_err)
			return
		}

		sample_setup.has_setup = true
	}

	env_vars, e_err := os2.environ(context.temp_allocator)
    if e_err != nil {
        fmt.printf("Failed to get environ %v\n", e_err)
        return
    }
	envs := make([dynamic]string, len(env_vars)+1, context.temp_allocator)
	i := 0
	for ; i < len(env_vars); i += 1 {
		envs[i] = string(env_vars[i])
	}

	dir, err := os2.get_working_directory(context.temp_allocator)
	if err != nil { return }

	if path != "" {
		err = os2.set_working_directory(path)
		if err != nil { return }
	}

	envs[i] = fmt.tprintf("DYLD_INSERT_LIBRARIES=%s/tools/osx_dylib_sample/%s", dir, "same.dylib")

	child_pid, err2 := spawn(program_name, args, envs[:], nil, nil, true)
	if err2 != nil {
		fmt.printf("failed to spawn: %s | %v\n", program_name, err2)
		return
	}
	fmt.printf("Spawned %s @ %v\n", program_name, child_pid)

	buffer := [4096]u8{}
	darwin.proc_pidpath(child_pid, raw_data(buffer[:]), len(buffer))
	real_path := string(cstring(raw_data(buffer[:])))

	initial_timeout: u32 = 500 // ms

	// Get the Child's task and port
	recv_msg := Mach_Recv_Msg{}
	if darwin.mach_msg(&recv_msg, {.Receive_Msg, .Receive_Timeout}, 0, size_of(recv_msg), sample_setup.recv_port, initial_timeout, 0) != .Success {
		fmt.printf("failed to get child task\n")
		return
	}
	child_task := recv_msg.task_port.name

	if darwin.mach_msg(&recv_msg, {.Receive_Msg, .Receive_Timeout}, 0, size_of(recv_msg), sample_setup.recv_port, initial_timeout, 0) != .Success {
		fmt.printf("failed to get child port\n")
		return
	}
	child_port := recv_msg.task_port.name

	// Send the all clear
	send_msg := Mach_Send_Msg{}
	send_msg.header.msgh_remote_port = child_port
	send_msg.header.msgh_local_port = 0
	send_msg.header.msgh_bits = u32(darwin.Msg_Type.Copy_Send) | u32(darwin.Msg_Header_Bits.Complex)
	send_msg.header.msgh_size = size_of(send_msg)

	send_msg.body.msgh_descriptor_count = 1
	send_msg.task_port.name = sample_setup.my_task
	send_msg.task_port.disposition = u32(darwin.Msg_Type.Copy_Send)
	send_msg.task_port.type = darwin.MACH_MSG_PORT_DESCRIPTOR
	if darwin.mach_msg_send(&send_msg) != .Success {
		fmt.printf("failed to send all-clear to child\n")
		return
	}

	fmt.printf("Resuming child\n")

	sample_state := Sample_State{}
	sample_state.threads = make(map[u64]Sample_Thread)
	sample_state.program_path = real_path
	sample_state.dylib_uuid_to_bucket = make(map[UUID]^Func_Bucket)

	init_trace_allocs(trace, program_name)

	for !trace.requested_stop {
		if !sample_task(trace, sample_setup.my_task, child_task, child_pid, &sample_state) {
			break
		}
		time.sleep(1 * time.Millisecond)
	}
	trailing_ts := time.read_cycle_counter()

	// Pause after done
	{
		darwin.task_suspend(child_task)
/*
		status: i32 = 0
		posix.waitpid(child_pid, &status, nil)

		for !posix.WIFEXITED(status) && posix.WIFSIGNALED(status) {
			if posix.waitpid(child_pid, &status, nil) == -1 {
				fmt.printf("failed to wait on child\n")
				return
			}
		}
*/
	}

	if trace.requested_stop {
/*
		posix.kill(child_pid, .SIGTERM)
		darwin.task_terminate(child_task)
*/

	// Wait for the program to fully finish
	} else {
		fmt.printf("waiting for wrap\n")

		status: i32 = 0
		posix.waitpid(child_pid, &status, nil)

		for !posix.WIFEXITED(status) && posix.WIFSIGNALED(status) {
			if posix.waitpid(child_pid, &status, nil) == -1 {
				fmt.printf("failed to wait on child\n")
				return
			}
		}
    }

	freq, _ := time.tsc_frequency()

	trace.stamp_scale = ((1 / f64(freq)) * 1_000_000_000)

	proc_idx := setup_pid(trace, 0)
	process := &trace.processes[proc_idx]

	for thread_id, sample_thread in sample_state.threads {
		thread_idx := setup_tid(trace, proc_idx, u32(thread_id))
		thread := &process.threads[thread_idx]

		for len(thread.depths) < sample_thread.max_depth {
			depth := Depth{
				events = make([dynamic]Event),
			}
			non_zero_append(&thread.depths, depth)
		}

		push_event :: proc(trace: ^Trace, events: ^[dynamic]Event, addr: u64, ts: i64, dur: i64) {
			ev := add_event(events)
			ev^ = Event{
				has_addr = true,
				id = addr,
				args = 0,
				timestamp = ts,
				duration = dur,
			}
			trace.event_count += 1
		}

		// blast through the bulk of the samples
		for i := 0; i < len(sample_thread.samples) - 1; i += 1 {
			cur_sample := sample_thread.samples[i]
			next_sample := sample_thread.samples[i+1]
			duration := next_sample.ts - cur_sample.ts

			stack_similarity := true
			k := 0
			stack_loop: for j := len(cur_sample.callstack) - 1; j >= 0; j -= 1 {
				depth := &thread.depths[k]
				k += 1

				// If this is the first sample, we're not a continuation
				cur_addr := cur_sample.callstack[j]
				if i == 0 {
					push_event(trace, &depth.events, cur_addr, cur_sample.ts, duration)
					continue stack_loop
				}

				// If the previous callstack wasn't this deep
				prev_sample := sample_thread.samples[i-1]
				prev_j := len(prev_sample.callstack) - k
				if len(prev_sample.callstack) <= prev_j || prev_j < 0 {
					push_event(trace, &depth.events, cur_addr, cur_sample.ts, duration)
					continue stack_loop
				}
				prev_addr := prev_sample.callstack[prev_j]

				// If the last sample stack had a different address from us
				if prev_addr != cur_addr || !stack_similarity {
					push_event(trace, &depth.events, cur_addr, cur_sample.ts, duration)
					stack_similarity = false
					continue stack_loop
				}

				prev_ev := &depth.events[len(depth.events)-1]
				prev_ev.duration += duration
			}

			thread.min_time = min(thread.min_time, cur_sample.ts)
			process.min_time = min(process.min_time, cur_sample.ts)
			trace.total_min_time = min(trace.total_min_time, cur_sample.ts)
		}

		// handle last sample as a special case
		{
			i := len(sample_thread.samples)-1
			cur_sample := sample_thread.samples[i]
			duration := i64(trailing_ts) - cur_sample.ts

			stack_similarity := true
			k := 0
			stack_loop2: for j := len(cur_sample.callstack) - 1; j >= 0; j -= 1 {
				depth := &thread.depths[k]
				k += 1

				// If this is the first sample, we're not a continuation
				cur_addr := cur_sample.callstack[j]
				if i == 0 {
					push_event(trace, &depth.events, cur_addr, cur_sample.ts, duration)
					continue stack_loop2
				}

				// If the previous callstack wasn't this deep
				prev_sample := sample_thread.samples[i-1]
				prev_j := len(prev_sample.callstack) - k
				if len(prev_sample.callstack) <= prev_j || prev_j < 0 {
					push_event(trace, &depth.events, cur_addr, cur_sample.ts, duration)
					continue stack_loop2
				}
				prev_addr := prev_sample.callstack[prev_j]

				// If the last sample stack had a different address from us
				if prev_addr != cur_addr || !stack_similarity {
					push_event(trace, &depth.events, cur_addr, cur_sample.ts, duration)
					stack_similarity = false
					continue stack_loop2
				}

				prev_ev := &depth.events[len(depth.events)-1]
				prev_ev.duration += duration
			}

			trace.total_min_time = min(trace.total_min_time, cur_sample.ts)
			trace.total_max_time = max(trace.total_max_time, cur_sample.ts + duration)
			thread.min_time = min(thread.min_time, cur_sample.ts)
			thread.max_time = max(thread.max_time, cur_sample.ts + duration)
			process.min_time = min(process.min_time, cur_sample.ts)
		}
	}
	fmt.printf("Sampled %v events\n", trace.event_count)

	generate_color_choices(trace, false)
	chunk_events(trace)

	return true
}

spawn :: #force_inline proc(path: string, args: []string, envs: []string, file_actions: rawptr, attributes: rawptr, is_spawnp: bool) -> (posix.pid_t, os.Error) {
	runtime.DEFAULT_TEMP_ALLOCATOR_TEMP_GUARD()
	path_cstr := strings.clone_to_cstring(path, context.temp_allocator)

	args_cstrs := make([]cstring, len(args) + 2, context.temp_allocator)
	args_cstrs[0] = strings.clone_to_cstring(path, context.temp_allocator)
	for i := 0; i < len(args); i += 1 {
		args_cstrs[i+1] = strings.clone_to_cstring(args[i], context.temp_allocator)
	}

	envs_cstrs := make([]cstring, len(envs) + 1, context.temp_allocator)
	for i := 0; i < len(envs); i += 1 {
		envs_cstrs[i] = strings.clone_to_cstring(envs[i], context.temp_allocator)
	}

	child_pid: posix.pid_t
	status: posix.Errno
	if is_spawnp {
		status = posix.posix_spawnp(&child_pid, path_cstr, file_actions, attributes, raw_data(args_cstrs), raw_data(envs_cstrs))
	} else {
		status = posix.posix_spawn(&child_pid, path_cstr, file_actions, attributes, raw_data(args_cstrs), raw_data(envs_cstrs))
	}
	if status != .NONE {
		return 0, os.Platform_Error(status)
	}
	return child_pid, nil
}

