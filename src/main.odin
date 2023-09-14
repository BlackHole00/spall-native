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
import "core:prof/spall"

import glm "core:math/linalg/glsl"

import SDL "vendor:sdl2"
import gl "vendor:OpenGL"

import SDL_TTF "vendor:sdl2/ttf"

// input state
is_mouse_down  := false
was_mouse_down := false
clicked        := false
double_clicked := false
clicked_t      : time.Tick
mouse_up_now   := false
is_hovering    := false
shift_down     := false
ctrl_down      := false

last_mouse_pos := Vec2{}
mouse_pos      := Vec2{}
clicked_pos    := Vec2{}
scroll_val_y: f64 = 0
velocity_multiplier: f64 = 0

cam := Camera{Vec2{0, 0}, Vec2{0, 0}, 0, 1, 1}

// selection state
clicked_on_rect := false

// tooltip-state
rect_tooltip_rect := empty_event
rect_tooltip_pos := Vec2{}
rendered_rect_tooltip := false

did_pan := false

stat_sort_type := SortState.SelfTime
stat_sort_descending := true
resort_stats := false

// drawing state
colormode      := ColorMode.Dark
default_cursor: ^SDL.Cursor
pointer_cursor: ^SDL.Cursor

// font data
dpr:       f64 = 1
p_height:  f64 = 14
h1_height: f64 = 18
h2_height: f64 = 16
em:        f64 = p_height
p_font_size:  f64 = p_height
h1_font_size: f64 = h1_height
h2_font_size: f64 = h2_height
ch_width:   f64 = 0
thread_gap: f64 = 8

all_fonts: []^SDL_TTF.Font

build_hash := 0
enable_debug := false
fps_history: queue.Queue(f64)
lru_text_cache: lru.Cache(LRU_Key, LRU_Text)
global_pool := Pool{}


fullscreen := false

t               : f64
multiselect_t   : f64
greyanim_t      : f32
greymotion      : f32
frame_count     : int
last_frame_count: int
rect_count      : int
bucket_count    : int
was_sleeping    : bool
awake           : bool
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

set_flamegraph_camera :: proc(trace: ^Trace, ui_state: ^UIState, start_ticks, duration_ticks: i64) {
	cam.vel = Vec2{}

	cam.current_scale = rescale(1.0, 0, f64(duration_ticks), 0, ui_state.full_flamegraph_rect.w)
	cam.target_scale = cam.current_scale

	adj_start_ticks := f64(start_ticks - trace.total_min_time)

	cam.pan.x = -(adj_start_ticks * cam.current_scale)
	cam.target_pan_x = cam.pan.x
}

reset_flamegraph_camera :: proc(trace: ^Trace, ui_state: ^UIState) {
	cam = Camera{Vec2{0, 0}, Vec2{0, 0}, 0, 1, 1}
	if trace.event_count == 0 { trace.total_min_time = 0; trace.total_max_time = 100000000000000; trace.stamp_scale = 1; }

	start_time: f64 = 0
	end_time  := f64(trace.total_max_time - trace.total_min_time)

	side_pad  := 2 * em

	cam.current_scale = rescale(cam.current_scale, start_time, end_time, 0, ui_state.full_flamegraph_rect.w - (side_pad * 2))
	cam.target_scale = cam.current_scale

	cam.pan.x += side_pad
	cam.target_pan_x = cam.pan.x
}

get_event :: proc(trace: ^Trace, ev_id: EventID) -> ^Event {
	p_idx := ev_id.pid
	t_idx := ev_id.tid
	d_idx := ev_id.did
	e_idx := ev_id.eid

	return &trace.processes[p_idx].threads[t_idx].depths[d_idx].events[e_idx]
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

ThreadFileLoadState :: struct {
	filename: string,
	trace: ^Trace,
}

threaded_config_load :: proc(pool: ^Pool, data: rawptr) {
	state := cast(^ThreadFileLoadState)(data)

	trace := state.trace
	filename := state.filename
	free(state)

	start_time := time.tick_now()
	load_file(trace, filename)
	duration := time.tick_since(start_time)
	fmt.printf("runtime: %f ms, got %s events\n", time.duration_milliseconds(duration), tens_fmt(u64(trace.event_count)))

	loading_config = false
	post_loading = true
}

load_config :: proc(pool: ^Pool, trace: ^Trace) -> bool {
	if loading_config {
		return false
	}

	free_trace(trace)
	init_trace(trace)
	loading_config = true

	state := new(ThreadFileLoadState)
	state^ = ThreadFileLoadState{
		filename = start_trace,
		trace = trace,
	}
	start_trace = ""

	pool_add_task(pool, Pool_Task{threaded_config_load, state})
	return true
}

spall_ctx: spall.Context
@(thread_local) spall_buffer: spall.Buffer

SELF_TRACE :: false
FULL_SPEED :: false
GOOD_BOY_MODE :: false
terminal_mode := false
main :: proc() {
	when SELF_TRACE {
		current_time := time.time_to_unix(time.now())
		trace_name := fmt.tprintf("spall_timing_%d.spall", current_time)
		spall_ctx = spall.context_create(trace_name)
		defer spall.context_destroy(&spall_ctx)

		buffer_backing := make([]u8, spall.BUFFER_DEFAULT_SIZE)
		spall_buffer = spall.buffer_create(buffer_backing)
		defer spall.buffer_destroy(&spall_ctx, &spall_buffer)

		spall.SCOPED_EVENT(&spall_ctx, &spall_buffer, "")
	}
	clicked_t = time.tick_now()

	// If the user passed us a trace, save off the filename now
	if len(os.args) == 2 {
		start_trace = strings.clone(os.args[1])
	}

	thread_count := max(os.processor_core_count() - 1, 1)
	pool_init(&global_pool, thread_count)

	trace := new(Trace)
	init_trace(trace)

	if terminal_mode {
		if start_trace == "" {
			return
		}

		ok := load_config(&global_pool, trace)
		if !ok {
			return
		}

		pool_wait(&global_pool)
		return
	}

	orig_window_width: i32 = 1280
	orig_window_height: i32 = 720

	platform_pre_init()

	dpi_hack_val := platform_dpi_hack()
	if dpi_hack_val > 0 {
		dpr = dpi_hack_val
		orig_window_width = i32(f64(orig_window_width) * dpr)
		orig_window_height = i32(f64(orig_window_height) * dpr)
	}

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

	platform_post_init()

	default_cursor = SDL.CreateSystemCursor(.ARROW)
	pointer_cursor = SDL.CreateSystemCursor(.HAND)

	gl_context := SDL.GL_CreateContext(window)
	if gl_context == nil {
		fmt.eprintln("Failed to create gl context!")
		return
	}

	gl.load_up_to(GL_VERSION_MAJOR, GL_VERSION_MINOR, SDL.gl_set_proc_address)

	if FULL_SPEED {
		SDL.GL_SetSwapInterval(0)
	} else {
		SDL.GL_SetSwapInterval(-1)
	}

	version_str := gl.GetString(gl.VERSION)
	if version_str == "1.1.0" {
		fmt.eprintf("GL version is too old! Got %s, needs at least %d.%d.0\n", version_str, GL_VERSION_MAJOR, GL_VERSION_MINOR)
		return
	}

	gl.Enable(gl.BLEND)
	gl.BlendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA)
	gl.Enable(gl.MULTISAMPLE)
	gl.Enable(gl.FRAMEBUFFER_SRGB)

	real_window_width: i32
	real_window_height: i32
	pretend_window_width: i32
	pretend_window_height: i32
	SDL.GetWindowSize(window, &pretend_window_width, &pretend_window_height)
	SDL.GL_GetDrawableSize(window, &real_window_width, &real_window_height)
	width := f64(pretend_window_width)
	height := f64(pretend_window_height)


	// on certain platforms (windows) we need to grab the DPI explicitly, on certain (mac or linux)
	// we can infer it from the window size we got vs the window size we asked for (it scales it up
	// based on DPI).
	if dpi_hack_val < 0 {
		dpr_w := f64(real_window_width) / f64(pretend_window_width)
		dpr_h := f64(real_window_height) / f64(pretend_window_height)
		dpr = dpr_w
		width = width * dpr
		height = height * dpr
	}

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
	u_dpr := rect_uniforms["u_dpr"].location
	u_res := rect_uniforms["u_resolution"].location

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

	rects := make([dynamic]DrawRect)
	text_rects := make([dynamic]TextRect)

	ui_state := UIState{}
	next_line(&ui_state.line_height, em)
	ui_state.info_pane_height = ui_state.line_height * 8

	start_tick := time.tick_now()
	last_tick: time.Tick
	awake := true
	was_sleeping := false
	main_loop: for {
		defer {
			clicked = false
			double_clicked = false
			is_hovering = false
			was_mouse_down = false
			mouse_up_now = false
			ui_state.render_one_more = false
			frame_count += 1
			free_all(context.temp_allocator)
		}

		rect_tooltip_rect = empty_event
		rect_tooltip_pos = Vec2{}
		rendered_rect_tooltip = false

		if !event_cmp(trace.zoom_event, empty_event) {
			ev := get_event(trace, trace.zoom_event)
			thread := trace.processes[trace.zoom_event.pid].threads[trace.zoom_event.tid]
			duration := bound_duration(ev, thread.max_time)

			set_flamegraph_camera(trace, &ui_state, ev.timestamp, duration)
			trace.zoom_event = empty_event
		}

		cur_tick := time.tick_now()
		duration := time.tick_since(start_tick)
		t = time.duration_milliseconds(duration)

		dt := time.duration_seconds(time.tick_diff(last_tick, cur_tick))
		last_tick = cur_tick

		if queue.len(fps_history) > 100 { queue.pop_front(&fps_history) }
		queue.push_back(&fps_history, 1 / dt)

		// prevent dt from going *too* nuts if we've just woken up
		if was_sleeping {
			dt = min(0.016, dt)
			was_sleeping = false
		}

		// update animation timers
		greyanim_t = f32((t - multiselect_t) * 5)
		greymotion = ease_in_out(greyanim_t)

		should_toggle_fullscreen := false

		// event polling
		event: SDL.Event = ---
		event_loop: for {
			if !awake {
				ret := SDL.WaitEvent(&event)
				if !ret {
					break event_loop
				}

				was_sleeping = true
				awake = true
			} else {
				ret := SDL.PollEvent(&event)
				if !ret {
					break event_loop
				}
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
				x := f64(event.motion.x)
				y := f64(event.motion.y)
				if dpi_hack_val > 0 {
					x /= dpr
					y /= dpr
				}
				mouse_moved(x, y)
			case .MOUSEBUTTONDOWN:
				switch event.button.button {
				case SDL.BUTTON_LEFT:
					is_mouse_down = true

					x := f64(event.button.x)
					y := f64(event.button.y)
					if dpi_hack_val > 0 {
						x /= dpr
						y /= dpr
					}
					mouse_down(x, y)
				}
			case .MOUSEBUTTONUP:
				switch event.button.button {
				case SDL.BUTTON_LEFT:
					x := f64(event.button.x)
					y := f64(event.button.y)
					if dpi_hack_val > 0 {
						x /= dpr
						y /= dpr
					}
					mouse_up(x, y)
				}
			case .MOUSEWHEEL:
				mouse_scroll(f64(event.wheel.y))
			case .WINDOWEVENT:
				#partial switch event.window.event {
				case .RESIZED:
					width = f64(event.window.data1)
					height = f64(event.window.data2)
					if dpi_hack_val < 0 {
						width *= dpr
						height *= dpr
					}
				}
			case .DROPFILE:
				start_trace = strings.clone_from_cstring(event.drop.file)
				SDL.free(rawptr(event.drop.file))
			}
		}

		when SELF_TRACE {
			spall.SCOPED_EVENT(&spall_ctx, &spall_buffer, "frame")
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

		gl.Viewport(0, 0, i32(width), i32(height))
		gl.Uniform1f(u_dpr, f32(dpr))
		gl.Uniform2f(u_res, f32(width), f32(height))
		gl.BindBuffer(gl.ARRAY_BUFFER, rect_deets_buffer)
		gl.BindVertexArray(vao);

		if start_trace != "" && !loading_config {
			load_config(&global_pool, trace)
		}

		gl.ClearColor(
			f32(bg_color2.x) / 255,
			f32(bg_color2.y) / 255,
			f32(bg_color2.z) / 255,
			f32(bg_color2.w) / 255,
		)
		gl.Clear(gl.COLOR_BUFFER_BIT)

		ui_state.height = height / dpr
		ui_state.width  = width / dpr

		if loading_config {
			offset := trace.parser.offset
			size := trace.total_size

			pad_size : f64 = 4
			chunk_size : f64 = 10

			load_box := Rect{0, 0, 100, 100}
			load_box = Rect{
				(ui_state.width / 2) - (load_box.w / 2) - pad_size,
				(ui_state.height / 2) - (load_box.h / 2) - pad_size,
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
		defer {
			trace.stats.released_event = empty_event
		}

		spall_x_pad     := 3 * em
		header_height   := 3 * em
		activity_height := 2 * em
		timebar_height  := 3 * em
		rect_height     := em + (0.75 * em)
		top_line_gap    := (em / 1.5)

		topbars_height    := header_height + timebar_height + activity_height
		minigraph_width   := 15 * em
		flamegraph_width  := ui_state.width - (spall_x_pad + minigraph_width)
		flamegraph_height := ui_state.height - topbars_height - ui_state.info_pane_height

		tab_select_height := 2 * em
		filter_pane_width := ui_state.filters_open ? (15 * em) : 0
		stats_pane_x := filter_pane_width

		ui_state.side_pad                  = spall_x_pad
		ui_state.rect_height               = rect_height
		ui_state.topbars_height            = topbars_height
		ui_state.top_line_gap              = top_line_gap
		ui_state.flamegraph_toptext_height = (ui_state.top_line_gap * 2) + (2 * em)
		ui_state.flamegraph_header_height  = ui_state.flamegraph_toptext_height + em

		ui_state.header_rect             = Rect{0, 0, ui_state.width, header_height}
		ui_state.global_timebar_rect     = Rect{0, header_height, ui_state.width, timebar_height}
		ui_state.global_activity_rect    = Rect{spall_x_pad, header_height + timebar_height, flamegraph_width, activity_height}
		ui_state.local_timebar_rect      = Rect{spall_x_pad, header_height + timebar_height + activity_height, flamegraph_width, timebar_height}
		ui_state.minimap_rect            = Rect{ui_state.width - minigraph_width, topbars_height, minigraph_width, flamegraph_height}

		ui_state.info_pane_rect          = Rect{0, ui_state.height - ui_state.info_pane_height, ui_state.width, ui_state.info_pane_height}
		ui_state.tab_rect                = Rect{0, ui_state.info_pane_rect.y, ui_state.width, tab_select_height}

		pane_start_y := ui_state.tab_rect.y + ui_state.tab_rect.h

		info_subpane_height := ui_state.info_pane_height - tab_select_height
		ui_state.filter_pane_rect        = Rect{0, pane_start_y, filter_pane_width, info_subpane_height}
		ui_state.stats_pane_rect         = Rect{stats_pane_x, pane_start_y, ui_state.width - stats_pane_x, info_subpane_height}

		ui_state.full_flamegraph_rect    = Rect{spall_x_pad, topbars_height, flamegraph_width, flamegraph_height}

		ui_state.inner_flamegraph_rect    = ui_state.full_flamegraph_rect
		ui_state.inner_flamegraph_rect.y += ui_state.flamegraph_toptext_height
		ui_state.inner_flamegraph_rect.h -= ui_state.flamegraph_toptext_height

		ui_state.padded_flamegraph_rect    = ui_state.inner_flamegraph_rect
		ui_state.padded_flamegraph_rect.y += em
		ui_state.padded_flamegraph_rect.h -= em

		if post_loading {
			if trace.event_count == 0 { trace.total_min_time = 0; trace.total_max_time = 1000 }
			ui_state.multiselecting = false
			reset_flamegraph_camera(trace, &ui_state)

			if trace.file_name != "" {
				name := fmt.ctprintf("%s - spall beta 0.2", trace.base_name)
				SDL.SetWindowTitle(window, name)
			}
			post_loading = false
		}

		// process key/mouse inputs
		if clicked {
			did_pan = false
			trace.stats.pressed_event = empty_event // so no stale events are tracked
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

		process_multiselect(&rects, trace, pan_delta, dt, &ui_state)
		process_stats(trace, &ui_state)

		draw_stats(&rects, trace, &ui_state)
		trace.stats.just_started = false
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

		// save me my battery, plz
		if should_sleep(&cam, &ui_state) {
			cam.pan.x = cam.target_pan_x
			cam.vel.y = 0
			cam.current_scale = cam.target_scale
			ui_state.stats_pane_scroll_vel = 0
			ui_state.filter_pane_scroll_vel = 0

			awake = false
		} else {
			awake = true
		}

		gl.Finish()
		SDL.GL_SwapWindow(window)
		gl.Finish()
	}

	when SELF_TRACE || GOOD_BOY_MODE {
		pool_wait(&global_pool)
		pool_destroy(&global_pool)
	}

	when GOOD_BOY_MODE {
		gl.destroy_uniforms(rect_uniforms)

		delete(all_fonts)
		delete(rects)
		delete(text_rects)

		free_trace(trace)
		free(trace)

		queue.destroy(&fps_history)
		lru.destroy(&lru_text_cache, true)
	}
}

should_sleep :: proc(cam: ^Camera, ui_state: ^UIState) -> bool {
	PAN_X_EPSILON :: 0.01
	PAN_Y_EPSILON :: 1.0
	SCALE_EPSILON :: 0.01
	SCROLL_EPSILON :: 0.01

	if FULL_SPEED {
		return false
	}

	panning_x := math.abs(cam.pan.x - cam.target_pan_x) > PAN_X_EPSILON
	panning_y := math.abs(cam.vel.y - 0) > PAN_Y_EPSILON
	scaling   := math.abs((cam.current_scale - cam.target_scale) / cam.target_scale) > SCALE_EPSILON
	scrolling := (math.abs(ui_state.filter_pane_scroll_vel) > SCROLL_EPSILON) || (math.abs(ui_state.stats_pane_scroll_vel) > SCROLL_EPSILON)

	return (!ui_state.render_one_more && !panning_x && !panning_y && !scaling && !scrolling)
}
