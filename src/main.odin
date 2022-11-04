package main

import "core:fmt"
import "core:time"
import "core:os"
import "core:mem"
import "core:intrinsics"
import "core:strings"
import "core:math"
import "core:container/queue"

import glm "core:math/linalg/glsl"

import SDL "vendor:sdl2"
import gl "vendor:OpenGL"

import "formats:spall"

cam := Camera{Vec2{0, 0}, Vec2{0, 0}, 0, 1, 1}
em : f64 = 14.0
p_height : f64 = 14
h1_height: f64 = 18
h2_height: f64 = 16
ch_width : f64 = 1
graph_size: f64 = 150
fps_history: queue.Queue(u32)

@(cold)
push_fatal :: proc(err: SpallError) -> ! {
	fmt.eprintf("Error: %v\n", err)
	os.exit(1)
}

draw_graph :: proc(rects: ^[dynamic]DrawRect, header: string, history: ^queue.Queue(u32), pos: Vec2) {
	line_width : f64 = 1
	graph_edge_pad : f64 = 2 * em
	line_gap := (em / 1.5)

	max_val : u32 = 0
	min_val : u32 = 100
	sum_val : u32 = 0
	for i := 0; i < queue.len(history^); i += 1 {
		entry := queue.get(history, i)
		max_val = max(max_val, entry)
		min_val = min(min_val, entry)
		sum_val += entry
	}
	max_range := max_val - min_val
	avg_val := sum_val / 100

	graph_top := pos.y + em + line_gap
	draw_rect(rects, rect(pos.x, graph_top, graph_size, graph_size), bg_color2)
	draw_rect_outline(rects, rect(pos.x, graph_top, graph_size, graph_size), 2, outline_color)

	draw_line(rects, Vec2{pos.x - 5, graph_top + graph_size - graph_edge_pad}, Vec2{pos.x + 5, graph_top + graph_size - graph_edge_pad}, 1, graph_color)
	draw_line(rects, Vec2{pos.x - 5, graph_top + graph_edge_pad}, Vec2{pos.x + 5, graph_top + graph_edge_pad}, 1, graph_color)

	if queue.len(history^) > 1 {
		high_height := graph_top + graph_edge_pad - (em / 2)
		low_height := graph_top + graph_size - graph_edge_pad - (em / 2)
		avg_height := rescale(f64(avg_val), f64(min_val), f64(max_val), low_height, high_height)

		if queue.len(history^) > 90 {
			draw_line(rects, Vec2{pos.x - 5, avg_height + (em / 2)}, Vec2{pos.x + 5, avg_height + (em / 2)}, 1, graph_color)
		}
	}

	graph_y_bounds := graph_size - (graph_edge_pad * 2)
	graph_x_bounds := graph_size - graph_edge_pad

	last_x : f64 = 0
	last_y : f64 = 0
	for i := 0; i < queue.len(history^); i += 1 {
		entry := queue.get(history, i)

		point_x_offset : f64 = 0
		if queue.len(history^) != 0 {
			point_x_offset = f64(i) * (graph_x_bounds / f64(queue.len(history^)))
		}

		point_y_offset : f64 = 0
		if max_range != 0 {
			point_y_offset = f64(entry - min_val) * (graph_y_bounds / f64(max_range))
		}

		point_x := pos.x + point_x_offset + (graph_edge_pad / 2)
		point_y := graph_top + graph_size - point_y_offset - graph_edge_pad

		if queue.len(history^) > 1  && i > 0 {
			draw_line(rects, Vec2{last_x, last_y}, Vec2{point_x, point_y}, line_width, graph_color)
		}

		last_x = point_x
		last_y = point_y
	}
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

draw_rect :: proc(rects: ^[dynamic]DrawRect, rect: Rect, color: BVec4) {
	append(rects, DrawRect{FVec4{f32(rect.pos.x), f32(rect.pos.y), f32(rect.size.x), f32(rect.size.y)}, color, FVec2{0.0, 0.0}})
}

draw_line :: proc(rects: ^[dynamic]DrawRect, start, end: Vec2, width: f64, color: BVec4) {
	start, end := start, end
	if start.x > end.x {
		end, start = start, end
	}

	append(rects, DrawRect{FVec4{f32(start.x), f32(start.y), f32(end.x), f32(end.y)}, color, FVec2{f32(width), -1}})
}

draw_rect_outline :: proc(rects: ^[dynamic]DrawRect, rect: Rect, width: f64, color: BVec4) {
	x1 := rect.pos.x
	y1 := rect.pos.y
	x2 := rect.pos.x + rect.size.x
	y2 := rect.pos.y + rect.size.y

	draw_line(rects, Vec2{x1, y1}, Vec2{x2, y1}, width, color)
	draw_line(rects, Vec2{x1, y1}, Vec2{x1, y2}, width, color)
	draw_line(rects, Vec2{x2, y1}, Vec2{x2, y2}, width, color)
	draw_line(rects, Vec2{x1, y2}, Vec2{x2, y2}, width, color)
}

colormode: ColorMode
main :: proc() {
	orig_window_width: i32 = 1280
	orig_window_height: i32 = 720

	set_color_mode(false, false)

	SDL.Init({.VIDEO})

	GL_VERSION_MAJOR :: 3
	GL_VERSION_MINOR :: 3
	SDL.GL_SetAttribute(.CONTEXT_PROFILE_MASK,  i32(SDL.GLprofile.CORE))
	SDL.GL_SetAttribute(.CONTEXT_MAJOR_VERSION, GL_VERSION_MAJOR)
	SDL.GL_SetAttribute(.CONTEXT_MINOR_VERSION, GL_VERSION_MINOR)

	SDL.GL_SetSwapInterval(1)
	SDL.GL_SetAttribute(.MULTISAMPLEBUFFERS, 1)
	SDL.GL_SetAttribute(.MULTISAMPLESAMPLES, 16)

	window := SDL.CreateWindow("spall", SDL.WINDOWPOS_CENTERED, SDL.WINDOWPOS_CENTERED, orig_window_width, orig_window_height, {.OPENGL, .RESIZABLE, .ALLOW_HIGHDPI})
	if window == nil {
		fmt.eprintln("Failed to create window")
		return
	}

	gl_context := SDL.GL_CreateContext(window)
	gl.load_up_to(GL_VERSION_MAJOR, GL_VERSION_MINOR, SDL.gl_set_proc_address)

	gl.Enable(gl.BLEND)
	gl.BlendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA)
	gl.Enable(gl.MULTISAMPLE)

	real_window_width: i32
	real_window_height: i32
	SDL.GL_GetDrawableSize(window, &real_window_width, &real_window_height)
	width := f64(real_window_width)
	height := f64(real_window_height)
	scale := f64(real_window_width) / f64(orig_window_width)
					fmt.printf("%f, %f\n", width, height)

	rect_program, rect_prog_ok := gl.load_shaders_source(rect_vert_src, rect_frag_src)
	if !rect_prog_ok {
		fmt.eprintln("Failed to create rect shader")
		return
	}
	text_program, text_prog_ok := gl.load_shaders_source(rect_vert_src, text_frag_src)
	if !text_prog_ok {
		fmt.eprintln("Failed to create text shader")
		return
	}

	rect_uniforms := gl.get_uniforms_from_program(rect_program)
	text_uniforms := gl.get_uniforms_from_program(text_program)
	gl.UseProgram(rect_program)

	vao: u32
	gl.GenVertexArrays(1, &vao);
	gl.BindVertexArray(vao)


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
	idx_pos := []glm.vec2{ 
		{0.0, 0.0}, 
		{1.0, 0.0}, 
		{0.0, 1.0}, 
		{1.0, 1.0}
	}
	rect_points_buffer: u32
	gl.GenBuffers(1, &rect_points_buffer)
	gl.BindBuffer(gl.ARRAY_BUFFER, rect_points_buffer)
	gl.BufferData(gl.ARRAY_BUFFER, len(idx_pos)*size_of(idx_pos[0]), raw_data(idx_pos), gl.STATIC_DRAW)
	gl.EnableVertexAttribArray(u32(VertAttrs.IdxPos))
	gl.VertexAttribPointer(u32(VertAttrs.IdxPos), 2, gl.FLOAT, false, 0, 0)


	// Set up rect index buffer
	indices := []u16{
		0, 1, 2,
		2, 1, 3,
	}
	rect_idx_buffer: u32
	gl.GenBuffers(1, &rect_idx_buffer)
	gl.BindBuffer(gl.ELEMENT_ARRAY_BUFFER, rect_idx_buffer)
	gl.BufferData(gl.ELEMENT_ARRAY_BUFFER, len(indices)*size_of(indices[0]), raw_data(indices), gl.STATIC_DRAW)
	
	trace: Trace
	rects := make([dynamic]DrawRect)

	start_tick := time.tick_now()
	last_tick: time.Tick
	loop: for {
		cur_tick := time.tick_now()
		duration := time.tick_since(start_tick)
		t := f32(time.duration_milliseconds(duration))

		dt := time.duration_seconds(time.tick_diff(last_tick, cur_tick))
		last_tick = cur_tick

		// event polling
		event: SDL.Event = ---
		first := true
		event_loop: for {
			if first {
				SDL.WaitEvent(&event)
				first = false
			} else {
				ret := SDL.PollEvent(&event)
				if !ret {
					break event_loop
				}
			}

			#partial switch event.type {
			case .QUIT:
				break loop
			case .KEYDOWN:
				#partial switch event.key.keysym.sym {
				case .ESCAPE:
					break loop
				}
			case .WINDOWEVENT:
				#partial switch event.window.event {
				case .RESIZED:
					width = f64(event.window.data1) * scale
					height = f64(event.window.data2) * scale
				}
			case .DROPFILE:
				filename := strings.clone_from_cstring(event.drop.file)
				SDL.free(rawptr(event.drop.file))

				free_trace(&trace)
				mem.zero(&trace, size_of(Trace))
				start_time := time.tick_now()
				load_file(&trace, filename)
				duration := time.tick_since(start_time)
				if trace.event_count == 0 { 
					trace.total_min_time = 0;
					trace.total_max_time = 1000
				}

				delete(filename)
				fmt.printf("runtime: %f ms, got %d events\n", time.duration_milliseconds(duration), trace.event_count)
			}
		}

		resize(&rects, 0)

		gl.ClearColor(
			f32(bg_color2.x) / 255,
			f32(bg_color2.y) / 255, 
			f32(bg_color2.z) / 255,
			f32(bg_color2.w) / 255
		)
		gl.Viewport(0, 0, i32(width), i32(height))
		gl.Clear(gl.COLOR_BUFFER_BIT)

		gl.Uniform1f(rect_uniforms["u_dpr"].location, 2)
		gl.Uniform2f(rect_uniforms["u_resolution"].location, f32(width), f32(height))
		gl.BindBuffer(gl.ARRAY_BUFFER, rect_deets_buffer)
		gl.BindVertexArray(vao);


		rect_height := em + (0.75 * em)
		top_line_gap := (em / 1.5)
		toolbar_height := 3 * em

		pane_y : f64 = 0
		next_line :: proc(y: ^f64, h: f64) -> f64 {
			res := y^
			y^ += h + (h / 1.5)
			return res
		}
		prev_line := proc(y: ^f64, h: f64) -> f64 {
			res := y^
			y^ -= h + (h / 3)
			return res
		}

		info_line_count := 7
		for i := 0; i < info_line_count; i += 1 {
			next_line(&pane_y, em)
		}

		x_subpad := em

		info_pane_height := pane_y + top_line_gap
		info_pane_y := height - info_pane_height

		mini_graph_width := 15 * em
		mini_graph_pad := em
		mini_graph_padded_width := mini_graph_width + (mini_graph_pad * 2)
		time_bar_y := toolbar_height
		time_bar_height := (top_line_gap * 2) + em
		wide_graph_y := time_bar_y + time_bar_height
		wide_graph_height := (em * 2)
		
		start_x := 3 * em
		end_x := width - start_x
		start_y := toolbar_height + time_bar_height + wide_graph_height
		end_y   := info_pane_y
		display_height := end_y - start_y
		display_width := width - (start_x + mini_graph_padded_width)

		graph_header_text_height := (top_line_gap * 2) + em
		graph_header_line_gap := em
		graph_header_height := graph_header_text_height + graph_header_line_gap

		start_time, end_time: f64
		highlight_start_x := rescale(start_time, 0, trace.total_max_time - trace.total_min_time, 0, display_width)
		highlight_end_x   := rescale(end_time,   0, trace.total_max_time - trace.total_min_time, 0, display_width)
		disp_rect := rect(start_x, start_y, display_width, display_height)

		division: f64
		draw_tick_start: f64
		ticks: int
		{
			start_time : f64 = 0
			end_time   := trace.total_max_time - trace.total_min_time
			default_scale := rescale(1.0, start_time, end_time, 0, display_width)

			mus_range := display_width / default_scale
			v1 := math.log10(mus_range)
			v2 := math.floor(v1)
			rem := v1 - v2

			subdivisions := 10
			division := math.pow(10, v2); // multiples of 10
			if rem < 0.3      { division -= (division * 0.8); } // multiples of 2
			else if rem < 0.6 { division -= (division / 2); } // multiples of 5

			display_range_start := -width / default_scale
			display_range_end := width / default_scale

			draw_tick_start = f_round_down(display_range_start, division)
			draw_tick_end := f_round_down(display_range_end, division)
			tick_range := draw_tick_end - draw_tick_start

			division /= f64(subdivisions)
			ticks := (int(tick_range / division) + 1)

			for i := 0; i < ticks; i += 1 {
				tick_time := draw_tick_start + (f64(i) * division)
				x_off := (tick_time * default_scale)

				line_start_y: f64
				if (i % subdivisions) == 0 {
					line_start_y = toolbar_height + (time_bar_height / 2) - (em / 2) + p_height
				} else {
					line_start_y = toolbar_height + (time_bar_height / 2) - (em / 2) + p_height + (p_height / 6)
				}

				draw_line(&rects,
					Vec2{start_x + x_off, line_start_y}, 
					Vec2{start_x + x_off, toolbar_height + time_bar_height - 2}, 2, division_color)
			}

			draw_line(&rects, Vec2{start_x + highlight_start_x, toolbar_height + (time_bar_height / 2) - (em / 2) + p_height}, Vec2{start_x + highlight_start_x, toolbar_height + time_bar_height + wide_graph_height}, 2, xbar_color)
			draw_line(&rects, Vec2{start_x + highlight_end_x, toolbar_height + (time_bar_height / 2) - (em / 2) + p_height}, Vec2{start_x + highlight_end_x, toolbar_height + time_bar_height + wide_graph_height}, 2, xbar_color)
			draw_line(&rects, Vec2{0, toolbar_height + time_bar_height + wide_graph_height}, Vec2{width, toolbar_height + time_bar_height + wide_graph_height}, 1, line_color)
		}

		draw_rect(&rects, rect(0, 0, width, toolbar_height), toolbar_color)

		if queue.len(fps_history) > 100 { queue.pop_front(&fps_history) }
		queue.push_back(&fps_history, u32(1 / dt))
		draw_graph(&rects, "FPS", &fps_history, Vec2{width - mini_graph_padded_width - 160, disp_rect.pos.y + graph_header_height})

		gl.BufferData(gl.ARRAY_BUFFER, len(rects)*size_of(rects[0]), raw_data(rects), gl.DYNAMIC_DRAW)
		gl.DrawElementsInstanced(gl.TRIANGLES, i32(len(indices)), gl.UNSIGNED_SHORT, nil, i32(len(rects)))
		SDL.GL_SwapWindow(window)
	}
}
