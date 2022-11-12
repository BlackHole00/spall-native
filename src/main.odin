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

last_mouse_pos := Vec2{}
mouse_pos      := Vec2{}
clicked_pos    := Vec2{}
scroll_val_y: f64 = 0
info_pane_scroll: f64 = 0
info_pane_scroll_vel: f64 = 0

cam := Camera{Vec2{0, 0}, Vec2{0, 0}, 0, 1, 1}

// selection state
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
disp_rect: Rect
graph_rect: Rect
padded_graph_rect: Rect

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
loading_config := true
post_loading := true

// gl-rect nonsense
idx_pos := []glm.vec2{ 
	{0.0, 0.0}, 
	{1.0, 0.0}, 
	{0.0, 1.0}, 
	{1.0, 1.0}
}
indices := []u16{
	0, 1, 2,
	2, 1, 3,
}

@(cold)
push_fatal :: proc(err: SpallError) -> ! {
	fmt.eprintf("Error: %v\n", err)
	os.exit(1)
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

get_current_window :: proc(cam: Camera, display_width: f64) -> (f64, f64) {
	display_range_start := to_world_x(cam, 0)
	display_range_end   := to_world_x(cam, display_width)
	return display_range_start, display_range_end
}

reset_camera :: proc(trace: ^Trace, display_width: f64) {
	cam = Camera{Vec2{0, 0}, Vec2{0, 0}, 0, 1, 1}
	if trace.event_count == 0 { trace.total_min_time = 0; trace.total_max_time = 1000 }

	start_time: f64 = 0
	end_time  := trace.total_max_time - trace.total_min_time

	side_pad  := 2 * em

	cam.current_scale = rescale(cam.current_scale, start_time, end_time, 0, display_width - (side_pad * 2))
	cam.target_scale = cam.current_scale

	cam.pan.x += side_pad
	cam.target_pan_x = cam.pan.x
}

grab_fonts :: proc(names: []string, sizes: []f64) -> []^SDL_TTF.Font {
	start_cstr := SDL.GetBasePath()
	path_str := strings.clone_from_cstring(start_cstr)
	fonts := make([dynamic]^SDL_TTF.Font)

	for filename in names {
		full_path := strings.concatenate([]string{path_str, filename})
		full_path_cstring := strings.clone_to_cstring(full_path)
		
		for size in sizes {
			font := SDL_TTF.OpenFont(full_path_cstring, i32(size))
			if font == nil {
				fmt.printf("Failed to open %s @ %d\n", full_path_cstring, size)
				push_fatal(SpallError.Bug)
			}

			SDL_TTF.SetFontHinting(font, SDL_TTF.HINTING_NORMAL)
			append(&fonts, font)
		}
	}

	return fonts[:]
}

main :: proc() {
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
	SDL.GL_SetAttribute(.MULTISAMPLESAMPLES, 8)

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
	gl.BlendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA)
	gl.Enable(gl.MULTISAMPLE)

	real_window_width: i32
	real_window_height: i32
	SDL.GL_GetDrawableSize(window, &real_window_width, &real_window_height)
	dpr = f64(real_window_width) / f64(orig_window_width)
	width := f64(orig_window_width)
	height := f64(orig_window_height)

	lru.init(&lru_text_cache, 1000)
	lru_text_cache.on_remove = rm_text_cache

	names := []string{ "Montserrat-Regular.ttf", "FiraMono-Regular.ttf", "fontawesome-webfont.ttf" }
	sizes := []f64{ p_height * dpr, h1_height * dpr, h2_height * dpr }
	all_fonts = grab_fonts(names, sizes)

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
	gl.BufferData(gl.ARRAY_BUFFER, len(idx_pos)*size_of(idx_pos[0]), raw_data(idx_pos), gl.STATIC_DRAW)
	gl.EnableVertexAttribArray(u32(VertAttrs.IdxPos))
	gl.VertexAttribPointer(u32(VertAttrs.IdxPos), 2, gl.FLOAT, false, 0, 0)


	// Set up rect index buffer
	rect_idx_buffer: u32
	gl.GenBuffers(1, &rect_idx_buffer)
	gl.BindBuffer(gl.ELEMENT_ARRAY_BUFFER, rect_idx_buffer)
	gl.BufferData(gl.ELEMENT_ARRAY_BUFFER, len(indices)*size_of(indices[0]), raw_data(indices), gl.STATIC_DRAW)

	ch_width = measure_text("a", .PSize, .MonoFont)
	
	trace: Trace
	rects := make([dynamic]DrawRect)

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
				case .LSHIFT:
					shift_down = true
				}
			case .KEYUP:
				#partial switch event.key.keysym.sym {
				case .LSHIFT:
					shift_down = false
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
				scroll_val_y += y_dist
			case .WINDOWEVENT:
				#partial switch event.window.event {
				case .RESIZED:
					width = f64(event.window.data1)
					height = f64(event.window.data2)
				}
			case .DROPFILE:
				filename := strings.clone_from_cstring(event.drop.file)
				SDL.free(rawptr(event.drop.file))

				free_trace(&trace)
				mem.zero(&trace, size_of(Trace))
				start_time := time.tick_now()
				load_file(&trace, filename)
				duration := time.tick_since(start_time)
				fmt.printf("runtime: %f ms, got %d events\n", time.duration_milliseconds(duration), trace.event_count)

				post_loading = true
			}
		}
		resize(&rects, 0)

		gl.ClearColor(
			f32(bg_color2.x) / 255,
			f32(bg_color2.y) / 255, 
			f32(bg_color2.z) / 255,
			f32(bg_color2.w) / 255
		)
		gl.Clear(gl.COLOR_BUFFER_BIT)

		gl.Viewport(0, 0, i32(width * dpr), i32(height * dpr))
		gl.Uniform1f(rect_uniforms["u_dpr"].location, f32(dpr))
		gl.Uniform2f(rect_uniforms["u_resolution"].location, f32(width * dpr), f32(height * dpr))
		gl.BindBuffer(gl.ARRAY_BUFFER, rect_deets_buffer)
		gl.BindVertexArray(vao);

		// Start the drawing madness
		rect_height := em + (0.75 * em)
		top_line_gap := (em / 1.5)
		toolbar_height := 3 * em

		pane_y : f64 = 0

		info_line_count := 7
		for i := 0; i < info_line_count; i += 1 {
			next_line(&pane_y, em)
		}

		x_pad_size := 3 * em
		x_subpad := em

		info_pane_height := pane_y + top_line_gap
		info_pane_y := height - info_pane_height
		
		mini_graph_width := 15 * em
		mini_graph_pad := (em)
		mini_graph_padded_width := mini_graph_width + (mini_graph_pad * 2)
		mini_start_x := width - mini_graph_padded_width

		time_bar_y := toolbar_height
		time_bar_height := (top_line_gap * 2) + em

		wide_graph_y := time_bar_y + time_bar_height
		wide_graph_height := (em * 2)

		start_x := x_pad_size
		end_x := width - x_pad_size
		display_width := width - (start_x + mini_graph_padded_width)
		start_y := toolbar_height + time_bar_height + wide_graph_height
		end_y   := info_pane_y
		display_height := end_y - start_y

		if post_loading {
			if trace.event_count == 0 { trace.total_min_time = 0; trace.total_max_time = 1000 }
			reset_camera(&trace, display_width)
			post_loading = false
		}

		graph_header_text_height := (top_line_gap * 2) + em
		graph_header_line_gap := em
		graph_header_height := graph_header_text_height + graph_header_line_gap
		max_x := width - x_pad_size

		disp_rect = rect(start_x, start_y, display_width, display_height)
		graph_rect = disp_rect
		graph_rect.pos.y += graph_header_text_height
		graph_rect.size.y -= graph_header_text_height
		padded_graph_rect = graph_rect
		padded_graph_rect.pos.y += graph_header_line_gap
		padded_graph_rect.size.y -= graph_header_line_gap
		stat_pane := rect(0, info_pane_y, width, height - info_pane_y)

		mini_graph_rect := rect(mini_start_x, graph_rect.pos.y, mini_graph_padded_width, display_height - graph_header_text_height)

		// process key/mouse inputs
		if clicked {
			did_pan = false
			pressed_event = {-1, -1, -1, -1} // so no stale events are tracked
		}
		start_time, end_time, pan_delta := process_inputs(&trace, stat_pane, mini_graph_rect, dt, display_width, rect_height, start_x)

		clicked_on_rect = false
		rect_count = 0
		bucket_count = 0

		draw_flamegraphs(&rects, &trace,
			start_time, end_time, start_x, rect_height, info_pane_y,
			graph_header_height, graph_header_text_height, top_line_gap, display_width)
 
		draw_minimap(&rects, &trace,
			rect_height, mini_graph_width, display_height, mini_start_x, 
			mini_graph_pad, mini_graph_padded_width, graph_header_text_height)

		draw_topbars(&rects, &trace, 
			width, height, display_width, graph_header_height, top_line_gap, 
			start_x, toolbar_height, graph_header_text_height, time_bar_height, 
			wide_graph_height, wide_graph_y, mini_graph_padded_width, start_time, end_time)

		// draw sidelines
		draw_line(&rects, Vec2{start_x, toolbar_height + time_bar_height}, Vec2{start_x, info_pane_y}, 1, line_color)
		draw_line(&rects, Vec2{mini_start_x, toolbar_height + time_bar_height}, Vec2{mini_start_x, info_pane_y}, 1, line_color)

		render_one_more := process_multiselect(&rects, &trace, pan_delta, dt, info_pane_y, rect_height)
		draw_stats(&rects, &trace, info_pane_y, info_pane_height, top_line_gap, x_subpad, width, height, display_width, info_line_count)
		if resort_stats {
			sort_stats(&trace)
			resort_stats = false
		}

		draw_toolbar(&rects, &trace, toolbar_height, width, display_width)

		// reset the cursor if we're not over a selectable thing
		if !is_hovering {
			reset_cursor()
		}

		if enable_debug {
			text_y := height - em - top_line_gap
			graph_pos := Vec2{width - mini_graph_padded_width - 150, disp_rect.pos.y + graph_header_height}
			draw_debug(&rects, width, text_y, x_subpad, graph_pos)
		}

		// if there's a rectangle tooltip to render, now's the time.
		if rendered_rect_tooltip {
			draw_rect_tooltip(&rects, &trace, dpr)
		}

		// Phew... Ok, time to dump to the screen
		gl.BufferData(gl.ARRAY_BUFFER, len(rects)*size_of(rects[0]), raw_data(rects), gl.DYNAMIC_DRAW)
		gl.DrawElementsInstanced(gl.TRIANGLES, i32(len(indices)), gl.UNSIGNED_SHORT, nil, i32(len(rects)))

		SDL.GL_SwapWindow(window)
	}
}
