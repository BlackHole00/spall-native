package main

import "core:os"
import "core:flags"

opt := Cmd_Options{}
Cmd_Options :: struct {
	file: string `args:"pos=0" usage:"Trace file to load"`,
	terminal_mode: bool `args:"hidden, name=terminal-mode" usage:"Loads traces headlessly"`,
	full_speed: bool `args:"hidden, name=full-speed" usage:"Disables power-limiter to max out framerate"`,
	symbol_path: string `args:"name=symbol-path" usage:"Overrides symbol path for trace files"`,
}

main :: proc() {
	flags.parse_or_exit(&opt, os.args, .Unix)

	pt := Platform_State{}
	pt.p_height = 14
	pt.h1_height = 18
	pt.h2_height = 16
	pt.em = pt.p_height

	init_keymap(&pt)
	set_color_mode(&pt, false, true)

	create_context(&pt, "spall", 1280, 720)
	setup_graphics(&pt)

	stored_height := pt.height
	stored_width  := pt.width

	ev := PlatformEvent{}
	main_loop: for {
		event_loop: for {
			ev = get_next_event(&pt, !pt.awake)
			if ev.type == .None {
				break event_loop
			}
			if !pt.awake {
				pt.was_sleeping = true
				pt.awake = true
			}

			#partial switch ev.type {
			case .Exit:
				break main_loop
			case .Resize:
				stored_height = ev.h
				stored_width  = ev.w
			}
		}
		setup_frame(&pt, int(stored_height), int(stored_width))

		side_min := min(pt.width / 2, pt.height / 2)
		x_pos, y_pos := center_xy(pt.width, pt.height, side_min, side_min)

		container := Rect{x_pos, y_pos, side_min, side_min}
		draw_rect(&pt, container, pt.colors.error)

		draw_centered_text(&pt, container, "Hello World", .H1Size, .DefaultFont, pt.colors.text)

		flush_rects(&pt)
		finish_frame(&pt)
	}
}
