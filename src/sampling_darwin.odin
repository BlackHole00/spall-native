//+build darwin

package main

import "core:fmt"
import "core:os"
import "core:os/os2"
import "core:path/filepath"
import "core:time"
import "core:sys/posix"
import "core:sys/darwin"

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
	addr:     u64,
}

Sample_State :: struct {
	threads: map[u64][dynamic]Sample,
}

sample_x86_thread :: proc(my_task: darwin.task_t, child_task: darwin.task_t, thread: darwin.thread_act_t, ts: u64, s_stack: ^[dynamic]Sample) {
	state: darwin.x86_thread_state64_t
	state_count: u32 = darwin.X86_THREAD_STATE64_COUNT
	if darwin.thread_get_state(thread, darwin.X86_THREAD_STATE64, darwin.thread_state_t(&state), &state_count) != 0 {
		return
	}

	append(s_stack, Sample{ts = i64(ts), addr = state.rip})

	sp := state.rsp

	page: [^]u64
	page_size : u64 = 4096

	cur_prot : i32 = darwin.VM_PROT_NONE
	max_prot : i32 = darwin.VM_PROT_NONE
	if darwin.mach_vm_remap(my_task, &page, page_size, 0, 1, child_task, sp, false, &cur_prot, &max_prot, darwin.VM_INHERIT_SHARE) != 0 {
		return
	}

	darwin.mach_vm_deallocate(my_task, page, page_size)
}

sample_task :: proc(my_task: darwin.task_t, child_task: darwin.task_t, sample_state: ^Sample_State) -> bool {
	ts := time.read_cycle_counter()
	if darwin.task_suspend(child_task) != 0 {
		return false
	}

	thread_list: darwin.thread_list_t
	thread_count: u32
	if darwin.task_threads(child_task, &thread_list, &thread_count) != 0 {
		return false
	}

	for i : u32 = 0; i < thread_count; i += 1 {
		thread := thread_list[i]

		id_info := darwin.thread_identifier_info{}
		count : u32 = darwin.THREAD_IDENTIFIER_INFO_COUNT
		if darwin.thread_info(thread, darwin.THREAD_IDENTIFIER_INFO, &id_info, &count) != 0 {
			continue
		}

		s_stack, ok := &sample_state.threads[id_info.thread_id]
		if !ok {
			tmp := make([dynamic]Sample)
			sample_state.threads[id_info.thread_id] = tmp
			s_stack, _ := &sample_state.threads[id_info.thread_id]
		}

		if ODIN_ARCH == .amd64 {
			sample_x86_thread(my_task, child_task, thread, ts, s_stack)
		} else {
			fmt.printf("don't support yet!\n")
			continue
		}
	}

	if darwin.task_resume(child_task) != 0 {
		return false
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
sample_child :: proc(trace: ^Trace, program_name: string, args: []string) -> (ok: bool) {
	if !sample_setup.has_setup {
		sample_setup.my_task = darwin.mach_task_self()
		if darwin.mach_port_allocate(sample_setup.my_task, darwin.MACH_PORT_RIGHT_RECEIVE, &sample_setup.recv_port) != 0 {
			fmt.printf("failed to allocate port\n")
			return
		}

		if darwin.task_get_special_port(sample_setup.my_task, darwin.TASK_BOOTSTRAP_PORT, &sample_setup.bootstrap_port) != 0 {
			fmt.printf("failed to get special port\n")
			return
		}

		right: darwin.mach_port_t
		acquired_right: darwin.mach_port_t
		if darwin.mach_port_extract_right(sample_setup.my_task, u32(sample_setup.recv_port), darwin.MACH_MSG_TYPE_MAKE_SEND, &right, &acquired_right) != 0 {
			fmt.printf("failed to get right\n")
			return
		}

		k_err := darwin.bootstrap_register2(sample_setup.bootstrap_port, "SPALL_BOOTSTRAP", right, 0)
		if k_err != 0 {
			fmt.printf("failed to register bootstrap | got: %v\n", k_err)
			return
		}

		sample_setup.has_setup = true
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
	if darwin.mach_msg(&recv_msg, darwin.MACH_RCV_MSG | darwin.MACH_RCV_TIMEOUT, 0, size_of(recv_msg), sample_setup.recv_port, initial_timeout, 0) != 0 {
		fmt.printf("failed to get child task\n")
		return
	}
	child_task := recv_msg.task_port.name

	if darwin.mach_msg(&recv_msg, darwin.MACH_RCV_MSG | darwin.MACH_RCV_TIMEOUT, 0, size_of(recv_msg), sample_setup.recv_port, initial_timeout, 0) != 0 {
		fmt.printf("failed to get child port\n")
		return
	}
	child_port := recv_msg.task_port.name

	// Send the all clear
	send_msg := Mach_Send_Msg{}
	send_msg.header.msgh_remote_port = child_port
	send_msg.header.msgh_local_port = 0
	send_msg.header.msgh_bits = darwin.MACH_MSG_TYPE_COPY_SEND | darwin.MACH_MSGH_BITS_COMPLEX
	send_msg.header.msgh_size = size_of(send_msg)

	send_msg.body.msgh_descriptor_count = 1
	send_msg.task_port.name = sample_setup.my_task
	send_msg.task_port.disposition = darwin.MACH_MSG_TYPE_COPY_SEND
	send_msg.task_port.type = darwin.MACH_MSG_PORT_DESCRIPTOR
	if darwin.mach_msg_send(&send_msg) != 0 {
		fmt.printf("failed to send all-clear to child\n")
		return
	}

	fmt.printf("Resuming child\n")

	sample_state := Sample_State{}
	sample_state.threads = make(map[u64][dynamic]Sample)

	for {
		if !sample_task(sample_setup.my_task, child_task, &sample_state) {
			break
		}
		time.sleep(2 * time.Millisecond)
	}

	status: i32 = 0
	posix.waitpid(posix.pid_t(child_pid), &status, nil)

	for !posix.WIFEXITED(status) && posix.WIFSIGNALED(status) {
		if posix.waitpid(posix.pid_t(child_pid), &status, nil) == -1 {
			fmt.printf("failed to wait on child\n")
			return
		}
	}
	trailing_ts := time.read_cycle_counter()

	freq, _ := time.tsc_frequency()

	init_trace(trace)
	init_trace_allocs(trace, program_name)

	trace.stamp_scale = ((1 / f64(freq)) * 1_000_000_000)

	proc_idx := setup_pid(trace, 0)
	process := &trace.processes[proc_idx]

	for thread_id, samples in sample_state.threads {
		thread_idx := setup_tid(trace, proc_idx, u32(thread_id))
		thread := &process.threads[thread_idx]

		{
			depth := Depth{
				events = make([dynamic]Event),
			}
			non_zero_append(&thread.depths, depth)
		}
		depth := &thread.depths[0]

		// blast through the bulk of the samples
		for i := 0; i < len(samples) - 1; i += 1 {
			cur_sample := samples[i]
			next_sample := samples[i+1]
			duration := next_sample.ts - cur_sample.ts

			ev := add_event(&depth.events)
			ev^ = Event{
				has_addr = true,
				id = cur_sample.addr,
				args = 0,
				timestamp = cur_sample.ts,
				duration = duration,
			}

			thread.min_time = min(thread.min_time, cur_sample.ts)
			process.min_time = min(process.min_time, cur_sample.ts)
			trace.total_min_time = min(trace.total_min_time, cur_sample.ts)
			trace.event_count += 1
		}

		// handle last sample as a special case
		{
			cur_sample := samples[len(samples)-1]
			duration := i64(trailing_ts) - cur_sample.ts

			ev := add_event(&depth.events)
			ev^ = Event{
				has_addr = true,
				id = cur_sample.addr,
				args = 0,
				timestamp = cur_sample.ts,
				duration = duration,
			}

			trace.total_min_time = min(trace.total_min_time, cur_sample.ts)
			trace.total_max_time = max(trace.total_max_time, cur_sample.ts + duration)
			thread.min_time = min(thread.min_time, cur_sample.ts)
			thread.max_time = max(thread.max_time, cur_sample.ts + duration)
			process.min_time = min(process.min_time, cur_sample.ts)
			trace.event_count += 1
		}
	}

	fmt.printf("Sampled %v events\n", trace.event_count)
	generate_color_choices(trace)
	chunk_events(trace)

	return true
}
