//+build linux
package main

import "core:c"
import "core:sys/unix"
import "core:os"
import "core:fmt"
import "core:strings"
import "core:time"

open_file_dialog :: proc() -> (string, bool) {
	buffer := [4096]u8{}
	fds := [2]os.Handle{}
	ret := unix.sys_pipe2(raw_data(&fds), 0)

	pid, err := os.fork()
	if err != os.ERROR_NONE {
		fmt.printf("Spall uses Zenity for file dialogs! Please install Zenity or launch your trace with the command line\n")
		unix.sys_close(int(fds[0]))
		unix.sys_close(int(fds[1]))
		return "", false
	}

	if pid == 0 {
		fmt.printf("starting zenity!\n")
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
