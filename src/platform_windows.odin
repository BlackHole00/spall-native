//+build windows
package main

import "core:fmt"
import "core:strings"
import "core:sys/windows"

platform_init :: proc() {
	velocity_multiplier = -100
}

open_file_dialog :: proc() -> (string, bool) {
	path_buf := make([]u16, windows.MAX_PATH_WIDE)
	defer delete(path_buf)

	filters := []string{"All Files", "*.*"}
	filter: string
	filter = strings.join(filters, "\u0000", context.temp_allocator)
	filter = strings.concatenate({filter, "\u0000"}, context.temp_allocator)

	title := "Select tracefile to open"
	dir := "."
	default_ext := ""

	ofn := windows.OPENFILENAMEW{
		lStructSize     = size_of(windows.OPENFILENAMEW),
		lpstrFile       = windows.wstring(&path_buf[0]),
		nMaxFile        = windows.MAX_PATH_WIDE,
		lpstrTitle      = windows.utf8_to_wstring(title, context.temp_allocator),
		lpstrFilter     = windows.utf8_to_wstring(filter, context.temp_allocator),
		lpstrInitialDir = windows.utf8_to_wstring(dir, context.temp_allocator),
		nFilterIndex    = 1,
		lpstrDefExt     = windows.utf8_to_wstring(default_ext, context.temp_allocator),
		Flags           = windows.OPEN_FLAGS,
	}

	ok := windows.GetOpenFileNameW(&ofn)
	if !ok {
		return "", false
	}

	file_name, _ := windows.utf16_to_utf8(path_buf[:])
	path := strings.trim_right_null(file_name)

	fmt.printf("path: %s\n", path)
	return path, true
}
