//+build linux
package main

import "core:c"
import "core:sys/unix"
import "core:os"
import "core:fmt"
import "core:strings"
import "core:time"

platform_pre_init :: proc() {
	velocity_multiplier = -100
}
platform_post_init :: proc() { }

platform_dpi_hack :: proc() -> f64 {
	return -1
}

open_file_dialog :: proc() -> (string, bool) {
	buffer := [4096]u8{}
	fds := [2]os.Handle{}
	ret := unix.sys_pipe2(raw_data(&fds), 0)

	pid, err := os.fork()
	if err != os.ERROR_NONE {
		fmt.printf("Spall uses Zenity for file dialogs! Please install Zenity or launch your trace via the command line, ex: spall <trace>\n")
		unix.sys_close(int(fds[0]))
		unix.sys_close(int(fds[1]))
		return "", false
	}

	if pid == 0 {
		unix.sys_dup2(int(fds[1]), 1)
		unix.sys_close(int(fds[1]))
		unix.sys_close(int(fds[0]))
		os.execvp("zenity", []string{"--file-selection"})
		os.exit(1)
	}
	unix.sys_close(int(fds[1]))

	for {
		ret_bytes := unix.sys_read(int(fds[0]), raw_data(buffer[:]), len(buffer))
		if ret_bytes > 0 {
			unix.sys_close(int(fds[0]))
			return strings.clone_from_bytes(buffer[:ret_bytes-1]), true
		} else {
			break
		}
	}

	unix.sys_close(int(fds[0]))
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
