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
	name: string,
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

Sample_State :: struct {
	threads: map[u64]Sample_Thread,
	program_path: string,
	dylibs_checked: bool,

	should_sample: bool,
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

sample_arm64_thread :: proc(my_task: darwin.task_t, child_task: darwin.task_t, thread: darwin.thread_act_t, ts: u64, sample_thread: ^Sample_Thread) -> (ok: bool) {
	state: darwin.arm_thread_state64_t
	state_count: u32 = darwin.ARM_THREAD_STATE64_COUNT
	if darwin.thread_get_state(thread, darwin.ARM_THREAD_STATE64, darwin.thread_state_t(&state), &state_count) != .Success {
		return
	}

	cur_depth := 1

	append(&sample_thread.samples, Sample{ts = i64(ts), callstack = make([dynamic]u64)})
	callstack := &sample_thread.samples[len(sample_thread.samples)-1].callstack
    append(callstack, state.pc)
	sample_thread.max_depth = max(sample_thread.max_depth, cur_depth)

	fmt.printf("PC: 0x%x\n", state.pc)

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

		append(callstack, fp)
		cur_depth += 1
		sample_thread.max_depth = max(sample_thread.max_depth, cur_depth)

		new_fp := (^u64)(uintptr(slot))^
		pc = (^u64)(uintptr(u64(uintptr(slot)) + 8))^
		sp = u64(uintptr(slot) + 16)
		unmap_child_mem(my_task, fp, slot)

		fp = new_fp
	}
*/

    return true
}

sample_x86_thread :: proc(my_task: darwin.task_t, child_task: darwin.task_t, thread: darwin.thread_act_t, ts: u64, sample_thread: ^Sample_Thread) -> (ok: bool) {
	state: darwin.x86_thread_state64_t
	state_count: u32 = darwin.X86_THREAD_STATE64_COUNT
	if darwin.thread_get_state(thread, darwin.X86_THREAD_STATE64, darwin.thread_state_t(&state), &state_count) != .Success {
		return
	}

	cur_depth := 1

	append(&sample_thread.samples, Sample{ts = i64(ts), callstack = make([dynamic]u64)})
	callstack := &sample_thread.samples[len(sample_thread.samples)-1].callstack
	append(callstack, state.rip)
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

		append(callstack, bp)
		cur_depth += 1
		sample_thread.max_depth = max(sample_thread.max_depth, cur_depth)

		new_bp := slot^
		unmap_child_mem(my_task, bp, slot)

		bp = new_bp
	}

	return true
}

adjust_offset :: proc(file_offset: u64, mappings: []Segment_Range) -> (u64, bool) {
	for mapping in mappings {
		mapping_end := mapping.file_off + mapping.file_size
		if val_in_range(file_offset, mapping.file_off, mapping_end) {
			adj_offset := mapping.mem_off + (file_offset - mapping.file_off)
			return adj_offset, true
		}
	}

	return 0, false
}

process_dylibs :: proc(trace: ^Trace, my_task: darwin.task_t, child_task: darwin.task_t, sample_state: ^Sample_State) -> bool {
	if sample_state.dylibs_checked {
		return true
	}
	sample_state.dylibs_checked = true

	dyld_info := darwin.task_dyld_info{}
	count : u32 = darwin.TASK_DYLD_INFO_COUNT
	if darwin.task_info(child_task, darwin.TASK_DYLD_INFO, darwin.task_info_t(&dyld_info), &count) != .Success {
		return false
	}

	tmp_buffer := make([]u8, 1024*1024, context.temp_allocator)

	image_infos := map_child_mem(my_task, child_task, dyld_info.all_image_info_addr, darwin.dyld_all_image_infos) or_return
	defer unmap_child_mem(my_task, dyld_info.all_image_info_addr, image_infos)

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

		header, ok3 := map_child_mem(my_task, child_task, info_entry.image_load_addr, Mach_Header_64)
		if !ok3 { continue dylib_loop }
		cmd_start_addr := info_entry.image_load_addr + size_of(header^)
		cmd_end_addr := cmd_start_addr + u64(header.cmd_size)
		defer unmap_child_mem(my_task, info_entry.image_load_addr, header)

		is_executable := (header.file_type == MACH_FILETYPE_EXEC)
		in_shared_cache := (header.flags & MACH_DYLIB_IN_CACHE) != 0

		uuid_cmd := Mach_UUID_Command{}
		symtab_cmd := Mach_Symtab_Command{}
		header_and_cmds, ok4 := map_child_slice(my_task, child_task, info_entry.image_load_addr, cmd_end_addr - cmd_start_addr)
		if !ok4 { continue dylib_loop }
		defer unmap_child_slice(my_task, info_entry.image_load_addr, header_and_cmds)

		symtab_header := Mach_Symtab_Command{}

		segment_mappings := make([dynamic]Segment_Range)
		defer delete(segment_mappings)

		text_segment_idx := min(int)

		j := size_of(Mach_Header_64)
		for j < len(header_and_cmds) {
			current_buffer := header_and_cmds[j:]
			cmd, ok := slice_to_type(current_buffer, Mach_Load_Command)
			if cmd.size == 0 || !ok {
				continue dylib_loop
			}

			if cmd.type == MACH_CMD_SEGMENT_64 {
				seg_hdr, ok2 := slice_to_type(current_buffer, Mach_Segment_64_Command)
				if !ok2 {
					continue dylib_loop
				}

				mem_skew : u64 = 0
				if in_shared_cache {
					mem_skew = image_infos.shared_cache_slide
				}

				seg_name := strings.string_from_null_terminated_ptr(raw_data(seg_hdr.name[:]), 16)
				append(&segment_mappings, Segment_Range{
					file_off  = seg_hdr.file_offset,
					file_size = seg_hdr.file_size,
					mem_off   = seg_hdr.address + mem_skew,
					mem_size  = seg_hdr.mem_size,
					name      = strings.clone(seg_name),
				})

				if seg_name == "__TEXT" {
					text_segment_idx = len(segment_mappings) - 1
				}
			}
			if cmd.type == MACH_CMD_UUID {
				uuid_cmd, ok = slice_to_type(current_buffer, Mach_UUID_Command)
				if !ok {
					continue dylib_loop
				}
			}

			if cmd.type == MACH_CMD_SYMTAB {
				symtab_header, ok = slice_to_type(current_buffer, Mach_Symtab_Command)
				if !ok {
					continue dylib_loop
				}
			}

			j += int(cmd.size)
		}
		if text_segment_idx == min(int) {
			continue dylib_loop
		}

/*
		fmt.printf("%s\n", file_path)
		for s in segment_mappings {
			fmt.printf("%s || 0x%08x -> 0x%08x | 0x%08x -> 0x%08x\n",
				s.name, s.file_off, s.file_off + s.file_size, s.mem_off, s.mem_off + s.mem_size,
			)
		}
*/

		symbol_table_size := u64(symtab_header.symbol_count) * size_of(Mach_Symbol_Entry_64)
		sym_table_offset, ok5 := adjust_offset(u64(symtab_header.symbol_table_offset), segment_mappings[:])
		if !ok5 {
			fmt.printf("failed sym skew\n")
			continue dylib_loop
		}

		string_table_size := u64(symtab_header.string_table_size)
		string_table_offset, ok6 := adjust_offset(u64(symtab_header.string_table_offset), segment_mappings[:])
		if !ok6 {
			fmt.printf("failed string skew\n")
			continue dylib_loop
		}

		text_seg := segment_mappings[text_segment_idx]
		fmt.printf("%s || 0x%08x -> 0x%08x | 0x%08x -> 0x%08x\n",
			text_seg.name, text_seg.file_off, text_seg.file_off + text_seg.file_size, text_seg.mem_off, text_seg.mem_off + text_seg.mem_size,
		)
		if is_executable {
			info_entry.image_load_addr -= 0x100000000
		}

		load_skew := info_entry.image_load_addr
		if in_shared_cache {
			load_skew = 0
		}
		symbol_table_addr := load_skew + sym_table_offset
		string_table_addr := load_skew + string_table_offset

		symbol_table_bytes, ok7 := map_child_slice(my_task, child_task, symbol_table_addr, symbol_table_size)
		if !ok7 {
			fmt.printf("failed sym lookup\n")
			continue dylib_loop
		}
		defer unmap_child_slice(my_task, symbol_table_addr, symbol_table_bytes)

		string_table, ok8 := map_child_slice(my_task, child_task, string_table_addr, string_table_size)
		if !ok8 {
			fmt.printf("failed string lookup\n")
			continue dylib_loop
		}
		defer unmap_child_slice(my_task, string_table_addr, string_table)

		symbol_table := slice.reinterpret([]Mach_Symbol_Entry_64, symbol_table_bytes)

		text_skew := -image_infos.shared_cache_slide
		bucket := new_func_bucket(&trace.func_buckets, strings.clone(file_path), 0)
		if !load_macho_symbols(trace, bucket, symbol_table, string_table, text_skew, tmp_buffer) {
			continue dylib_loop
		}
		bucket.base_address = text_seg.mem_off

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
	}

	fmt.printf("processing dylibs\n")
	for &bucket in trace.func_buckets {
		//slice.sort_by(bucket.functions[:], func_order)
		build_scopes(trace, &bucket)

		fmt.printf("=== start bucket %s ===\n", bucket.source_path)
		for func in bucket.functions {
			fmt.printf("0x%08x -> 0x%08x | %s\n", func.low_pc, func.high_pc, in_getstr(&trace.string_block, func.name))
		}
		fmt.printf("=== end bucket %s ===\n", bucket.source_path)
		fmt.printf("0x%08x -> 0x%08x\n", bucket.scopes.low_pc, bucket.scopes.high_pc)
	}
	fmt.printf("done processing dylibs\n")

	dyld_path_addr := u64(uintptr(rawptr(image_infos.dyld_path)))
	dyld_path_bytes := map_child_mem(my_task, child_task, dyld_path_addr, [512]u8) or_return
	defer unmap_child_mem(my_task, dyld_path_addr, dyld_path_bytes)

	return true
}

sample_task :: proc(trace: ^Trace, my_task: darwin.task_t, child_task: darwin.task_t, child_pid: posix.pid_t, sample_state: ^Sample_State) -> bool {
	ts := time.read_cycle_counter()
	if darwin.task_suspend(child_task) != .Success {
		return false
	}
	//defer darwin.task_resume(child_task)

	if !sample_state.should_sample {
		return true
	}

	thread_list: darwin.thread_list_t
	thread_count: u32
	if darwin.task_threads(child_task, &thread_list, &thread_count) != .Success {
		return false
	}

	process_dylibs(trace, my_task, child_task, sample_state)

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

		if ODIN_ARCH == .amd64 {
			sample_x86_thread(my_task, child_task, thread, ts, sample_thread)
        } else if ODIN_ARCH == .arm64 {
            sample_arm64_thread(my_task, child_task, thread, ts, sample_thread)
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
	sample_state.should_sample = true

	init_trace_allocs(trace, program_name)

	for !trace.requested_stop {
		if !sample_task(trace, sample_setup.my_task, child_task, child_pid, &sample_state) {
			break
		}
		if true { sample_state.should_sample = false }
		time.sleep(1 * time.Millisecond)
	}
	trailing_ts := time.read_cycle_counter()

	if trace.requested_stop {
		posix.kill(child_pid, .SIGTERM)
		darwin.task_terminate(child_task)

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

