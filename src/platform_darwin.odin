//+build darwin

package main

import "core:fmt"
import "core:strings"
import "core:path/filepath"
import "core:sys/posix"
import "core:os"
import "core:os/os2"
import "core:sys/darwin"
import NS "core:sys/darwin/Foundation"

platform_pre_init :: proc() {
	velocity_multiplier = -15
}
platform_post_init :: proc() {
	user_defaults := NS.UserDefaults.standardUserDefaults()
	flag_str := NS.String.alloc()->initWithOdinString("AppleMomentumScrollSupported")
	user_defaults->setBoolForKey(true, flag_str)
}
platform_dpi_hack :: proc() -> f64 {
	return -1
}

open_file_dialog :: proc() -> (string, bool) {
	panel := NS.OpenPanel.openPanel()
	panel->setCanChooseFiles(true)
	panel->setResolvesAliases(true)
	panel->setCanChooseDirectories(false)
	panel->setAllowsMultipleSelection(false)

	if panel->runModal() == .OK {
		urls := panel->URLs()
		ret_count := urls->count()
		if ret_count != 1 {
			return "", false
		}

		url := urls->objectAs(0, ^NS.URL)
		return strings.clone_from_cstring(url->fileSystemRepresentation()), true
	}

	return "", false
}

foreign import abi "system:c++abi"
foreign abi {
	@(link_name="__cxa_demangle") _cxa_demangle :: proc(name: rawptr, out_buf: rawptr, len: rawptr, status: rawptr) -> cstring ---
}

demangle_symbol :: proc(name: string, tmp_buffer: []u8) -> (string, bool) {
	name_cstr := strings.clone_to_cstring(name, context.temp_allocator)

	buffer_size := len(tmp_buffer)

	status : i32 = 0
	ret_str := _cxa_demangle(rawptr(name_cstr), raw_data(tmp_buffer), &buffer_size, &status)
	if status == -2 {
		return name, true
	} else if status != 0 {
		return "", false
	}

	return string(ret_str), true
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

sample_child :: proc(program_name: string, args: []string) -> (ok: bool) {
	recv_port: darwin.mach_port_t
	my_task := darwin.mach_task_self()
	if darwin.mach_port_allocate(my_task, darwin.MACH_PORT_RIGHT_RECEIVE, &recv_port) != 0 {
		return
	}

	bootstrap_port: darwin.mach_port_t
	if darwin.task_get_special_port(my_task, darwin.TASK_BOOTSTRAP_PORT, &bootstrap_port) != 0 {
		return
	}

	right: darwin.mach_port_t
	acquired_right: darwin.mach_port_t
	if darwin.mach_port_extract_right(my_task, u32(recv_port), darwin.MACH_MSG_TYPE_MAKE_SEND, &right, &acquired_right) != 0 {
		return
	}

	if darwin.bootstrap_register2(bootstrap_port, "SPALL_BOOTSTRAP", right, 0) != 0 {
		return
	}

	env_vars := os2.environ(context.temp_allocator)
	envs := make([dynamic]string, len(env_vars)+1, context.temp_allocator)
	i := 0
	for ; i < len(env_vars); i += 1 {
		envs[i] = string(env_vars[i])
	}

	dir, err := os2.get_working_directory(context.temp_allocator)
	if err != nil { return }

	prog_path := program_name
	if !filepath.is_abs(prog_path) {
		prog_path = fmt.tprintf("%s/%s", dir, program_name)
	}
	
	envs[i] = fmt.tprintf("DYLD_INSERT_LIBRARIES=%s/tools/osx_dylib_sample/%s", dir, "same.dylib")

	child_pid, err2 := os.posix_spawn(prog_path, args, envs[:], nil, nil)
	if err2 != nil {
		fmt.printf("failed to spawn: %s\n", prog_path)
		return
	}
	fmt.printf("Spawned %v\n", child_pid)

	initial_timeout: u32 = 500 // ms

	// Get the Child's task and port
	recv_msg := Mach_Recv_Msg{}
	if darwin.mach_msg(&recv_msg, darwin.MACH_RCV_MSG | darwin.MACH_RCV_TIMEOUT, 0, size_of(recv_msg), recv_port, initial_timeout, 0) != 0 {
		return
	}
	child_task := recv_msg.task_port.name

	if darwin.mach_msg(&recv_msg, darwin.MACH_RCV_MSG | darwin.MACH_RCV_TIMEOUT, 0, size_of(recv_msg), recv_port, initial_timeout, 0) != 0 {
		return
	}
	child_port := recv_msg.task_port.name

	darwin.task_suspend(child_task)

	thread_list: darwin.thread_list_t
	thread_count: u32
	darwin.task_threads(child_task, &thread_list, &thread_count)

	for i : u32 = 0; i < thread_count; i += 1 {
		thread := thread_list[i]

		state: darwin.x86_thread_state64_t
		state_count: u32 = darwin.X86_THREAD_STATE64_COUNT
		if darwin.thread_get_state(thread, darwin.X86_THREAD_STATE64, darwin.thread_state_t(&state), &state_count) != 0 {
			continue
		}

		fmt.printf("RIP: 0x%08x\n", state.rip)
		fmt.printf("RSP: 0x%08x\n", state.rsp)

		sp := state.rsp

		page: [^]u64
		cur_prot : i32 = darwin.VM_PROT_NONE
		max_prot : i32 = darwin.VM_PROT_NONE
		if darwin.mach_vm_remap(my_task, &page, 4096, 0, 1, child_task, sp, false, &cur_prot, &max_prot, darwin.VM_INHERIT_SHARE) != 0 {
			continue
		}

		val := page[0]
		fmt.printf("top of stack page: 0x%08x\n", val)
	}

	darwin.task_resume(child_task)

	fmt.printf("got task and port from child | %v, %v\n", child_task, child_port)

	// Send the all clear
	send_msg := Mach_Send_Msg{}
	send_msg.header.msgh_remote_port = child_port
	send_msg.header.msgh_local_port = 0
	send_msg.header.msgh_bits = darwin.MACH_MSG_TYPE_COPY_SEND | darwin.MACH_MSGH_BITS_COMPLEX
	send_msg.header.msgh_size = size_of(send_msg)

	send_msg.body.msgh_descriptor_count = 1
	send_msg.task_port.name = my_task
	send_msg.task_port.disposition = darwin.MACH_MSG_TYPE_COPY_SEND
	send_msg.task_port.type = darwin.MACH_MSG_PORT_DESCRIPTOR
	if darwin.mach_msg_send(&send_msg) != 0 {
		return
	}

	fmt.printf("Resuming child\n")

	status: i32 = 0
	for !posix.WIFEXITED(status) && posix.WIFSIGNALED(status) {
		if posix.waitpid(posix.pid_t(child_pid), &status, nil) == -1 {
			fmt.printf("failed to wait on child\n")
			return
		}
	}
	fmt.printf("child exited?\n")

	return true
}

supports_sampling :: proc() -> (ok: bool) { return true }
