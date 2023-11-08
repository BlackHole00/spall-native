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
import "core:unicode/utf8"
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

alt_down       := false
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
text_cursor:    ^SDL.Cursor

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
	ui_state: ^UIState,
}

threaded_config_load :: proc(pool: ^Pool, data: rawptr) {
	state := cast(^ThreadFileLoadState)(data)

	trace := state.trace
	filename := state.filename
	ui_state := state.ui_state
	free(state)

	start_time := time.tick_now()
	load_file(trace, filename)
	duration := time.tick_since(start_time)
	fmt.printf("runtime: %f ms, got %s events\n", time.duration_milliseconds(duration), tens_fmt(u64(trace.event_count)))

	ui_state.loading_config = false
	ui_state.post_loading = true
}

load_config :: proc(pool: ^Pool, trace: ^Trace, ui_state: ^UIState) -> bool {
	if ui_state.loading_config {
		return false
	}

	free_trace(trace)
	init_trace(trace)
	ui_state.loading_config = true

	state := new(ThreadFileLoadState)
	state^ = ThreadFileLoadState{
		filename = start_trace,
		trace = trace,
		ui_state = ui_state,
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
	ui_state := UIState{
		ui_mode = .MainMenu,
		post_loading = true,
		textboxes = make(map[TextboxKind]TextboxState),
	}

	ui_state.textboxes[.ProgramInput] = init_textbox_state()
	ui_state.textboxes[.CmdArgsInput] = init_textbox_state()
	first := &ui_state.textboxes[.ProgramInput]
	second := &ui_state.textboxes[.CmdArgsInput]
	first.next = second
	first.prev = second
	second.next = first
	second.prev = first

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

		ok := load_config(&global_pool, trace, &ui_state)
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
	text_cursor    = SDL.CreateSystemCursor(.IBEAM)

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

		should_toggle_fullscreen := false

		// if any of the textboxes are in focus, enable keyboard capture
		capture_text := false
		selected_box_id: TextboxKind
		selected_box: ^TextboxState = nil
		for id, box in &ui_state.textboxes {
			if box.focus {
				capture_text = true
				selected_box_id = id
				break
			}
		}
		if capture_text {
			SDL.StartTextInput()
			selected_box = &ui_state.textboxes[selected_box_id]
		} else {
			SDL.StopTextInput()
		}

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
				alt_down   = (event.key.keysym.mod & SDL.KMOD_ALT) != SDL.Keymod{}
				shift_down = (event.key.keysym.mod & SDL.KMOD_SHIFT) != SDL.Keymod{}
				ctrl_down  = (event.key.keysym.mod & SDL.KMOD_CTRL) != SDL.Keymod{}

				#partial switch event.key.keysym.sym {
				case .RETURN:
					if alt_down {
						should_toggle_fullscreen = true
					}
				case .F11:
					should_toggle_fullscreen = true
				case .BACKSPACE:
					if capture_text {
						new_cursor := step_left_rune(selected_box.b.buf[:], selected_box.cursor)
						remove_range(&selected_box.b.buf, new_cursor, selected_box.cursor)
						selected_box.cursor = new_cursor
					}
				case .TAB:
					if capture_text {
						selected_box.focus = false
						if shift_down {
							selected_box = selected_box.prev
						} else {
							selected_box = selected_box.next
						}
						selected_box.focus = true
					}
				case .LEFT:
					if capture_text {
						selected_box.cursor = step_left_rune(selected_box.b.buf[:], selected_box.cursor)
					}
				case .RIGHT:
					if capture_text {
						selected_box.cursor = step_right_rune(selected_box.b.buf[:], selected_box.cursor)
					}
				case .UP:
					if capture_text {
						selected_box.cursor = 0
					}
				case .DOWN:
					if capture_text {
						selected_box.cursor = len(selected_box.b.buf)
					}
				case .V:
					if capture_text && ctrl_down {
						path := get_clipboard()
						strings.builder_reset(&selected_box.b)
						strings.write_string(&selected_box.b, path)
						cur_str := strings.to_string(selected_box.b)
						selected_box.cursor = len(cur_str)
					}
				}
			case .KEYUP:
				alt_down   = (event.key.keysym.mod & SDL.KMOD_ALT) != SDL.Keymod{}
				shift_down = (event.key.keysym.mod & SDL.KMOD_SHIFT) != SDL.Keymod{}
				ctrl_down  = (event.key.keysym.mod & SDL.KMOD_CTRL) != SDL.Keymod{}
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
				ui_state.ui_mode = .TraceView
				fmt.printf("start trace: %s\n", start_trace)
				SDL.free(rawptr(event.drop.file))
			case .DROPTEXT:
				SDL.free(rawptr(event.drop.file))
			case .TEXTINPUT:
				if capture_text {
					cur_str := strings.to_string(selected_box.b)
					r_len := utf8.rune_count_in_string(cur_str)

					new_rune := string(cstring(rawptr(&event.text.text)))
					if selected_box.cursor == r_len {
						strings.write_string(&selected_box.b, new_rune)
						selected_box.cursor += 1
					} else {
						inject_at(&selected_box.b.buf, selected_box.cursor, new_rune)
						selected_box.cursor += 1
					}
				}
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

		gl.ClearColor(
			f32(bg_color2.x) / 255,
			f32(bg_color2.y) / 255,
			f32(bg_color2.z) / 255,
			f32(bg_color2.w) / 255,
		)
		gl.Clear(gl.COLOR_BUFFER_BIT)

		ui_state.height = height / dpr
		ui_state.width  = width / dpr

		header_height   := 3 * em
		spall_x_pad     := 3 * em
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

		#partial switch ui_state.ui_mode {
			case .MainMenu: draw_main_menu(&rects, trace, &ui_state, dt, window)
			case .TraceView: draw_trace(&rects, &text_rects, trace, &ui_state, &global_pool, dt, window)
		}

		// reset the cursor if we're not over a selectable thing
		if !is_hovering {
			reset_cursor()
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
