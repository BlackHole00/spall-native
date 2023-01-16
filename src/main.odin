package main

import "core:fmt"
import "core:time"
import "core:os"
import "core:mem"
import "core:intrinsics"
import "core:strings"
import "core:math"
import "core:runtime"
import "core:slice"
import "core:container/queue"
import "core:container/lru"
import "core:thread"

import glm "core:math/linalg/glsl"

import SDL "vendor:sdl2"
import gl "vendor:OpenGL"

import SDL_TTF "vendor:sdl2/ttf"

import "formats:spall"


// input state
is_mouse_down  := false
was_mouse_down := false
clicked        := false
mouse_up_now   := false
is_hovering    := false
shift_down     := false
ctrl_down      := false

last_mouse_pos := Vec2{}
mouse_pos      := Vec2{}
clicked_pos    := Vec2{}
scroll_val_y: f64 = 0
info_pane_scroll: f64 = 0
info_pane_scroll_vel: f64 = 0

cam := Camera{Vec2{0, 0}, Vec2{0, 0}, 0, 1, 1}

// selection state
selected_func := INStr{-1, 0}
selected_event := EventID{-1, -1, -1, -1}

pressed_event := EventID{-1, -1, -1, -1}
released_event := EventID{-1, -1, -1, -1}

did_multiselect := false
clicked_on_rect := false

// tooltip-state
rect_tooltip_rect := EventID{-1, -1, -1, -1}
rect_tooltip_pos := Vec2{}
rendered_rect_tooltip := false

did_pan := false

stats_state := StatState.NoStats
stat_sort_type := SortState.SelfTime
stat_sort_descending := true
resort_stats := false
cur_stat_offset := StatOffset{}
total_tracked_time := 0.0

// drawing state
colormode      := ColorMode.Dark
default_cursor: ^SDL.Cursor
pointer_cursor: ^SDL.Cursor

// font data
dpr: f64 = 1
p_height : f64 = 14
em : f64 = p_height
h1_height: f64 = 18
h2_height: f64 = 16
p_font_size := p_height
h1_font_size := h1_height
h2_font_size := h2_height
ch_width: f64 = 0
thread_gap     : f64 = 8

all_fonts: []^SDL_TTF.Font

build_hash := 0
enable_debug := false
fps_history: queue.Queue(f64)
lru_text_cache: lru.Cache(LRU_Key, LRU_Text)


fullscreen := false

t               : f64
multiselect_t   : f64
greyanim_t      : f32
greymotion      : f32
anim_playing    : bool
frame_count     : int
last_frame_count: int
rect_count      : int
bucket_count    : int
was_sleeping    : bool
random_seed     : u64

// loading / trace state
start_trace := ""
loading_config := false
post_loading := true

// gl-rect nonsense
idx_pos := [?]glm.vec2{ 
	{0.0, 0.0}, 
	{1.0, 0.0}, 
	{0.0, 1.0}, 
	{1.0, 1.0},
}

to_world_x :: proc(cam: Camera, x: f64) -> f64 {
	return (x - cam.pan.x) / cam.current_scale
}
to_world_y :: proc(cam: Camera, y: f64) -> f64 {
	return y + cam.pan.y
}
to_world_pos :: proc(cam: Camera, pos: Vec2) -> Vec2 {
	return Vec2{to_world_x(cam, pos.x), to_world_y(cam, pos.y)}
}

get_current_window :: proc(cam: Camera, ui_state: ^UIState) -> (f64, f64) {
	display_range_start := to_world_x(cam, 0)
	display_range_end   := to_world_x(cam, ui_state.full_flamegraph_rect.w)
	return display_range_start, display_range_end
}

reset_flamegraph_camera :: proc(trace: ^Trace, ui_state: ^UIState) {
	cam = Camera{Vec2{0, 0}, Vec2{0, 0}, 0, 1, 1}
	if trace.event_count == 0 { trace.total_min_time = 0; trace.total_max_time = 1000 }

	start_time: f64 = 0
	end_time  := trace.total_max_time - trace.total_min_time

	side_pad  := 2 * em

	cam.current_scale = rescale(cam.current_scale, start_time, end_time, 0, ui_state.full_flamegraph_rect.w - (side_pad * 2))
	cam.target_scale = cam.current_scale

	cam.pan.x += side_pad
	cam.target_pan_x = cam.pan.x
}

load_font :: proc(rw: ^SDL.RWops, size: i32) -> (^SDL_TTF.Font, bool) {
	font := SDL_TTF.OpenFontRW(rw, true, size)
	if font == nil {
		return nil, false
	}

	SDL_TTF.SetFontHinting(font, SDL_TTF.HINTING_NORMAL)
	return font, true
}

grab_dynamic_fonts :: proc(names: []string, sizes: []f64) -> []^SDL_TTF.Font {
	start_cstr := SDL.GetBasePath()
	path_str := strings.clone_from_cstring(start_cstr)
	fonts := make([dynamic]^SDL_TTF.Font)

	for filename in names {
		full_path := strings.concatenate([]string{path_str, filename})
		full_path_cstring := strings.clone_to_cstring(full_path)
		
		rw := SDL.RWFromFile(full_path_cstring, "rb")
		for size in sizes {
			font, ok := load_font(rw, i32(size))
			if !ok {
				fmt.printf("Failed to open %s @ %f\n", full_path_cstring, size)
				push_fatal(SpallError.Bug)
			}
			append(&fonts, font)
		}
	}

	return fonts[:]
}

grab_static_fonts :: proc(font_buffers: [][]u8, sizes: []f64) -> []^SDL_TTF.Font {
	fonts := make([dynamic]^SDL_TTF.Font)

	for font_buffer in font_buffers {
		rw := SDL.RWFromConstMem(raw_data(font_buffer), i32(len(font_buffer)))
		for size in sizes {
			font, ok := load_font(rw, i32(size))
			if !ok {
				fmt.printf("Failed to open a compiled font @ size: %f?\n", size)
				push_fatal(SpallError.Bug)
			}
			append(&fonts, font)
		}
	}

	return fonts[:]
}

ThreadState :: struct {
	filename: string,
	trace: ^Trace,
}

threaded_config_load :: proc(data: rawptr) {
	state := cast(^ThreadState)(data)
	
	trace := state.trace
	filename := state.filename
	free(state)

	start_time := time.tick_now()
	load_file(trace, filename)
	duration := time.tick_since(start_time)
	fmt.printf("runtime: %f ms, got %d events\n", time.duration_milliseconds(duration), trace.event_count)

	loading_config = false
	post_loading = true
}

main :: proc() {

	// If the user passed us a trace, save off the filename now
	if len(os.args) == 2 {
		start_trace = strings.clone(os.args[1])
	}

	orig_window_width: i32 = 1280
	orig_window_height: i32 = 720

	set_color_mode(false, true)

	SDL.Init({.VIDEO})
	SDL_TTF.Init()

	GL_VERSION_MAJOR :: 3
	GL_VERSION_MINOR :: 3
	SDL.GL_SetAttribute(.CONTEXT_PROFILE_MASK,  i32(SDL.GLprofile.CORE))
	SDL.GL_SetAttribute(.CONTEXT_MAJOR_VERSION, GL_VERSION_MAJOR)
	SDL.GL_SetAttribute(.CONTEXT_MINOR_VERSION, GL_VERSION_MINOR)

	SDL.GL_SetAttribute(.MULTISAMPLEBUFFERS, 1)
	SDL.GL_SetAttribute(.MULTISAMPLESAMPLES, 2)
	SDL.GL_SetAttribute(SDL.GLattr.FRAMEBUFFER_SRGB_CAPABLE, 1)

	SDL.SetHint(SDL.HINT_MOUSE_FOCUS_CLICKTHROUGH, "1")

	window := SDL.CreateWindow("spall", SDL.WINDOWPOS_CENTERED, SDL.WINDOWPOS_CENTERED, orig_window_width, orig_window_height, {.OPENGL, .RESIZABLE, .ALLOW_HIGHDPI})
	if window == nil {
		fmt.eprintln("Failed to create window")
		return
	}

	default_cursor = SDL.CreateSystemCursor(.ARROW)
	pointer_cursor = SDL.CreateSystemCursor(.HAND)

	gl_context := SDL.GL_CreateContext(window)
	gl.load_up_to(GL_VERSION_MAJOR, GL_VERSION_MINOR, SDL.gl_set_proc_address)
	SDL.GL_SetSwapInterval(-1)

	gl.Enable(gl.BLEND)
	gl.BlendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA)
	gl.Enable(gl.MULTISAMPLE)
	gl.Enable(gl.FRAMEBUFFER_SRGB)

	real_window_width: i32
	real_window_height: i32
	SDL.GL_GetDrawableSize(window, &real_window_width, &real_window_height)
	dpr = f64(real_window_width) / f64(orig_window_width)
	width := f64(orig_window_width)
	height := f64(orig_window_height)

	lru.init(&lru_text_cache, 1000)
	lru_text_cache.on_remove = rm_text_cache

	/*
	// Use dynamic on-disk fonts
	names := []string{ "Montserrat-Regular.ttf", "FiraMono-Regular.ttf", "fontawesome-webfont.ttf" }
	sizes := []f64{ p_height * dpr, h1_height * dpr, h2_height * dpr }
	all_fonts = grab_dynamic_fonts(names, sizes)
	*/

	// Load statically packed fonts
	sans_font := #load("../fonts/Montserrat-Regular.ttf")
	mono_font := #load("../fonts/FiraMono-Regular.ttf")
	icon_font := #load("../fonts/fontawesome-webfont.ttf")
	fonts := [][]u8{ sans_font, mono_font, icon_font }
	sizes := []f64{ p_height * dpr, h1_height * dpr, h2_height * dpr }
	all_fonts = grab_static_fonts(fonts, sizes)

	rect_program, rect_prog_ok := gl.load_shaders_source(rect_vert_src, rect_frag_src)
	if !rect_prog_ok {
		fmt.eprintln("Failed to create rect shader")
		return
	}

	rect_uniforms := gl.get_uniforms_from_program(rect_program)
	gl.UseProgram(rect_program)

	vao: u32
	gl.GenVertexArrays(1, &vao)
	gl.BindVertexArray(vao)

	tex: u32
	gl.GenTextures(1, &tex)
	gl.BindTexture(gl.TEXTURE_2D, tex)
	gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST)
	gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST)
	gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE)
	gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE)
	gl.TexImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 4096, 4096, 0, gl.RGBA, gl.UNSIGNED_BYTE, nil)

	// Set up dynamic rect buffer
	rect_deets_buffer: u32
	gl.GenBuffers(1, &rect_deets_buffer)
	gl.BindBuffer(gl.ARRAY_BUFFER, rect_deets_buffer)

	gl.EnableVertexAttribArray(u32(VertAttrs.RectPos))
	gl.VertexAttribPointer(u32(VertAttrs.RectPos), 4, gl.FLOAT, false, size_of(DrawRect), offset_of(DrawRect, pos))
	gl.VertexAttribDivisor(u32(VertAttrs.RectPos), 1)

	gl.EnableVertexAttribArray(u32(VertAttrs.Color))
	gl.VertexAttribPointer(u32(VertAttrs.Color), 4, gl.UNSIGNED_BYTE, true, size_of(DrawRect), offset_of(DrawRect, color))
	gl.VertexAttribDivisor(u32(VertAttrs.Color), 1)

	gl.EnableVertexAttribArray(u32(VertAttrs.UV))
	gl.VertexAttribPointer(u32(VertAttrs.UV), 2, gl.FLOAT, false, size_of(DrawRect), offset_of(DrawRect, uv))
	gl.VertexAttribDivisor(u32(VertAttrs.UV), 1)

	// Set up rect points buffer
	rect_points_buffer: u32
	gl.GenBuffers(1, &rect_points_buffer)
	gl.BindBuffer(gl.ARRAY_BUFFER, rect_points_buffer)
	gl.BufferData(gl.ARRAY_BUFFER, len(idx_pos)*size_of(idx_pos[0]), raw_data(idx_pos[:]), gl.STATIC_DRAW)
	gl.EnableVertexAttribArray(u32(VertAttrs.IdxPos))
	gl.VertexAttribPointer(u32(VertAttrs.IdxPos), 2, gl.FLOAT, false, 0, 0)

	ch_width = measure_text("a", .PSize, .MonoFont)
	
	trace := new(Trace)
	rects := make([dynamic]DrawRect)
	text_rects := make([dynamic]TextRect)

	start_tick := time.tick_now()
	last_tick: time.Tick
	main_loop: for {
		defer {
			clicked = false
			is_hovering = false
			was_mouse_down = false
			mouse_up_now = false
			released_event = {-1, -1, -1, -1}
			frame_count += 1
		}

		rect_tooltip_rect = EventID{-1, -1, -1, -1}
		rect_tooltip_pos = Vec2{}
		rendered_rect_tooltip = false

		cur_tick := time.tick_now()
		duration := time.tick_since(start_tick)
		t = time.duration_milliseconds(duration)

		dt := time.duration_seconds(time.tick_diff(last_tick, cur_tick))
		last_tick = cur_tick

		if queue.len(fps_history) > 100 { queue.pop_front(&fps_history) }
		queue.push_back(&fps_history, 1 / dt)

		// update animation timers
		greyanim_t = f32((t - multiselect_t) * 5)
		greymotion = ease_in_out(greyanim_t)

		should_toggle_fullscreen := false

		ui_state := UIState{}

		// event polling
		event: SDL.Event = ---
		first := true
		event_loop: for {
/*
			if first {
				SDL.WaitEvent(&event)
				first = false
			} else {
			}
*/
			ret := SDL.PollEvent(&event)
			if !ret {
				break event_loop
			}

			#partial switch event.type {
			case .QUIT:
				break main_loop
			case .KEYDOWN:
				#partial switch event.key.keysym.sym {
				case .LSHIFT: fallthrough
				case .RSHIFT:
					shift_down = true
				case .LCTRL: fallthrough
				case .RCTRL:
					ctrl_down = true
				case .RETURN:
					if event.key.keysym.mod & SDL.KMOD_ALT != (SDL.Keymod{}) {
						should_toggle_fullscreen = true
					}
				case .F11:
					should_toggle_fullscreen = true
				}
			case .KEYUP:
				#partial switch event.key.keysym.sym {
				case .LSHIFT: fallthrough
				case .RSHIFT:
					shift_down = false
				case .LCTRL: fallthrough
				case .RCTRL:
					ctrl_down = false
				}
			case .MOUSEMOTION:
				if frame_count != last_frame_count {
					last_mouse_pos = mouse_pos
					last_frame_count = frame_count
				}

				mouse_pos = Vec2{f64(event.motion.x), f64(event.motion.y)}
			case .MOUSEBUTTONDOWN:
				switch event.button.button {
				case SDL.BUTTON_LEFT:
					is_mouse_down = true
					mouse_pos = Vec2{f64(event.button.x), f64(event.button.y)}

					if frame_count != last_frame_count {
						last_mouse_pos = mouse_pos
						last_frame_count = frame_count
					}

					clicked = true
					clicked_pos = mouse_pos
				}
			case .MOUSEBUTTONUP:
				switch event.button.button {
				case SDL.BUTTON_LEFT:
					is_mouse_down = false
					was_mouse_down = true
					mouse_up_now = true

					if frame_count != last_frame_count {
						last_mouse_pos = mouse_pos
						last_frame_count = frame_count
					}

					mouse_pos = Vec2{f64(event.button.x), f64(event.button.y)}
				}
			case .MOUSEWHEEL:
				y_dist := f64(event.wheel.y) * -100
				if event.wheel.direction == u32(SDL.SDL_MouseWheelDirection.FLIPPED) {
					y_dist *= -1
				}
				if ctrl_down {
					y_dist *= 10
				}
				scroll_val_y += y_dist
			case .WINDOWEVENT:
				#partial switch event.window.event {
				case .RESIZED:
					width = f64(event.window.data1)
					height = f64(event.window.data2)
				}
			case .DROPFILE:
				start_trace = strings.clone_from_cstring(event.drop.file)
				SDL.free(rawptr(event.drop.file))
			}
		}

		if should_toggle_fullscreen {
			fullscreen = !fullscreen
			if fullscreen {
				SDL.SetWindowFullscreen(window, SDL.WINDOW_FULLSCREEN_DESKTOP)
			} else {
				SDL.SetWindowFullscreen(window, SDL.WindowFlags{})
			}
			iw : i32
			ih : i32
			SDL.GetWindowSize(window, &iw, &ih)
			width = f64(iw)
			height = f64(ih)
		}

		gl.Viewport(0, 0, i32(width * dpr), i32(height * dpr))
		gl.Uniform1f(rect_uniforms["u_dpr"].location, f32(dpr))
		gl.Uniform2f(rect_uniforms["u_resolution"].location, f32(width * dpr), f32(height * dpr))
		gl.BindBuffer(gl.ARRAY_BUFFER, rect_deets_buffer)
		gl.BindVertexArray(vao);

		if start_trace != "" && !loading_config {
			free_trace(trace)
			trace^ = Trace{}
			loading_config = true

			state := new(ThreadState)
			state^ = ThreadState{
				filename = start_trace,
				trace = trace,
			}
			start_trace = ""
			thread.create_and_start_with_data(state, threaded_config_load)
		}

		gl.ClearColor(
			f32(bg_color2.x) / 255,
			f32(bg_color2.y) / 255, 
			f32(bg_color2.z) / 255,
			f32(bg_color2.w) / 255,
		)
		gl.Clear(gl.COLOR_BUFFER_BIT)

		if loading_config {
			offset := trace.parser.offset
			size := trace.total_size

			pad_size : f64 = 4
			chunk_size : f64 = 10

			load_box := Rect{0, 0, 100, 100}
			load_box = Rect{
				(width / 2) - (load_box.w / 2) - pad_size, 
				(height / 2) - (load_box.h / 2) - pad_size, 
				load_box.w + pad_size, 
				load_box.h + pad_size,
			}

			draw_rect(&rects, load_box, BVec4{30, 30, 30, 255})
			chunk_count := int(rescale(f64(offset), 0, f64(size), 0, 100))

			chunk := Rect{0, 0, chunk_size, chunk_size}
			start_x := load_box.x + pad_size
			start_y := load_box.y + pad_size
			for i := chunk_count; i >= 0; i -= 1 {
				cur_x := f64(i %% int(chunk_size))
				cur_y := f64(i /  int(chunk_size))
				draw_rect(&rects, Rect{
					start_x + (cur_x * chunk_size), 
					start_y + (cur_y * chunk_size), 
					chunk_size - pad_size, 
					chunk_size - pad_size,
				}, loading_block_color)
			}

			flush_rects(&rects)
			SDL.GL_SwapWindow(window)
			continue
		}

		spall_x_pad     := 3 * em
		header_height   := 3 * em
		activity_height := 2 * em
		timebar_height  := 3 * em
		rect_height     := em + (0.75 * em)
		top_line_gap    := (em / 1.5)

		info_pane_height : f64 = 0
		info_line_count := 7
		for i := 0; i < info_line_count; i += 1 {
			next_line(&info_pane_height, em)
		}

		topbars_height    := header_height + timebar_height + activity_height
		minigraph_width   := 15 * em
		flamegraph_width  := width - (spall_x_pad + minigraph_width)
		flamegraph_height := height - topbars_height - info_pane_height

		ui_state.height = height
		ui_state.width  = width
		ui_state.side_pad                  = spall_x_pad
		ui_state.rect_height               = rect_height
		ui_state.topbars_height            = topbars_height
		ui_state.top_line_gap              = top_line_gap
		ui_state.flamegraph_toptext_height = (ui_state.top_line_gap * 2) + em
		ui_state.flamegraph_header_height  = ui_state.flamegraph_toptext_height + em

		ui_state.header_rect             = Rect{0, 0, width, header_height}
		ui_state.global_timebar_rect     = Rect{0, header_height, width, timebar_height}
		ui_state.global_activity_rect    = Rect{spall_x_pad, header_height + timebar_height, flamegraph_width, activity_height}
		ui_state.local_timebar_rect      = Rect{spall_x_pad, header_height + timebar_height + activity_height, flamegraph_width, timebar_height}
		ui_state.minimap_rect            = Rect{width - minigraph_width, topbars_height, minigraph_width, flamegraph_height}
		ui_state.info_pane_rect          = Rect{0, height - info_pane_height, width, info_pane_height}

		ui_state.full_flamegraph_rect    = Rect{spall_x_pad, topbars_height, flamegraph_width, flamegraph_height}

		ui_state.inner_flamegraph_rect    = ui_state.full_flamegraph_rect
		ui_state.inner_flamegraph_rect.y += ui_state.flamegraph_toptext_height
		ui_state.inner_flamegraph_rect.h -= ui_state.flamegraph_toptext_height

		ui_state.padded_flamegraph_rect    = ui_state.inner_flamegraph_rect
		ui_state.padded_flamegraph_rect.y += em
		ui_state.padded_flamegraph_rect.h -= em

		if post_loading {
			if trace.event_count == 0 { trace.total_min_time = 0; trace.total_max_time = 1000 }
			reset_flamegraph_camera(trace, &ui_state)

			if trace.file_name != "" {
				name := fmt.ctprintf("%s - spall", trace.base_name)
				SDL.SetWindowTitle(window, name)
			}
			post_loading = false
		}

		// process key/mouse inputs
		if clicked {
			did_pan = false
			pressed_event = {-1, -1, -1, -1} // so no stale events are tracked
		}
		start_time, end_time, pan_delta := process_inputs(trace, dt, &ui_state)

		clicked_on_rect = false
		rect_count = 0
		bucket_count = 0

		draw_flamegraphs(&rects, &text_rects, trace, start_time, end_time, &ui_state)
 
		draw_minimap(&rects, trace, &ui_state)
		draw_topbars(&rects, trace, start_time, end_time, &ui_state)

		// draw sidelines
		draw_line(&rects, Vec2{ui_state.side_pad, header_height + timebar_height},       Vec2{ui_state.side_pad, ui_state.info_pane_rect.y}, 1, line_color)
		draw_line(&rects, Vec2{ui_state.minimap_rect.x, header_height + timebar_height}, Vec2{ui_state.minimap_rect.x, ui_state.info_pane_rect.y}, 1, line_color)

		just_started, render_one_more := process_multiselect(&rects, trace, pan_delta, dt, &ui_state)
		draw_stats(&rects, trace, info_line_count, just_started, &ui_state)
		if resort_stats {
			sort_stats(trace)
			resort_stats = false
		}

		draw_header(&rects, trace, &ui_state)

		// reset the cursor if we're not over a selectable thing
		if !is_hovering {
			reset_cursor()
		}

		if enable_debug {
			draw_debug(&rects, &ui_state)
		}

		// if there's a rectangle tooltip to render, now's the time.
		if rendered_rect_tooltip {
			draw_rect_tooltip(&rects, trace, &ui_state)
		}

		if trace.error_message != "" {
			draw_errorbox(&rects, trace, &ui_state)
		}

		// Phew... Ok, time to dump to the screen
		flush_rects(&rects)

		gl.Finish()
		SDL.GL_SwapWindow(window)
		gl.Finish()
	}
}
