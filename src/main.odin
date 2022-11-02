package main

import "core:fmt"
import "core:time"
import "core:os"
import "core:mem"
import "core:intrinsics"
import "core:strings"

import glm "core:math/linalg/glsl"

import SDL "vendor:sdl2"
import gl "vendor:OpenGL"

import "formats:spall"


VertAttrs :: enum u32 {
	IdxPos = 0,
	RectPos = 1,
	Color = 2,
}

vertex_source := `#version 330 core

// idx_pos  {x, y}
layout(location=0) in vec2 idx_pos;

// rect_pos {x, y, width, height}
layout(location=1) in vec4 rect_pos;
layout(location=2) in vec4 color;

uniform float u_dpr;
uniform vec2  u_resolution;

out vec4 v_color;

void main() {
	vec2 xy = vec2(rect_pos.x * u_dpr, rect_pos.y) + (idx_pos * vec2(rect_pos.z * u_dpr, rect_pos.w * u_dpr));

	gl_Position = vec4((xy / u_resolution) * 2.0 - 1.0, 0.0, 1.0);
	gl_Position.y = -gl_Position.y;

	v_color = color;
}
`

fragment_source := `#version 330 core
in vec4 v_color;
out vec4 out_color;

void main() {
	out_color = v_color;
}
`

@(cold)
push_fatal :: proc(err: SpallError) -> ! {
	fmt.eprintf("Error: %v\n", err)
	os.exit(1)
}

main :: proc() {
	window_width: i32 = 640
	window_height: i32 = 480

	SDL.Init({.VIDEO})

	window := SDL.CreateWindow("spall", SDL.WINDOWPOS_CENTERED, SDL.WINDOWPOS_CENTERED, window_width, window_height, {.OPENGL, .RESIZABLE, .ALLOW_HIGHDPI})
	if window == nil {
		fmt.eprintln("Failed to create window")
		return
	}

	SDL.GetWindowSize(window, &window_width, &window_height)

	GL_VERSION_MAJOR :: 3
	GL_VERSION_MINOR :: 3
	SDL.GL_SetAttribute(.CONTEXT_PROFILE_MASK,  i32(SDL.GLprofile.CORE))
	SDL.GL_SetAttribute(.CONTEXT_MAJOR_VERSION, GL_VERSION_MAJOR)
	SDL.GL_SetAttribute(.CONTEXT_MINOR_VERSION, GL_VERSION_MINOR)

	gl_context := SDL.GL_CreateContext(window)
	gl.load_up_to(GL_VERSION_MAJOR, GL_VERSION_MINOR, SDL.gl_set_proc_address)

	SDL.GL_SetSwapInterval(-1)

	program, program_ok := gl.load_shaders_source(vertex_source, fragment_source)
	if !program_ok {
		fmt.eprintln("Failed to create GLSL program")
		return
	}

	gl.UseProgram(program)
	uniforms := gl.get_uniforms_from_program(program)

	vao: u32
	gl.GenVertexArrays(1, &vao);
	gl.BindVertexArray(vao)

	// Set up dynamic rect buffer
	_RectPos :: struct {
		x: f32,
		y: f32,
		width: f32,
		height: f32,
	}
	_Color :: struct {
		r: f32,
		g: f32,
		b: f32,
		a: f32,
	}
	_Vertex :: struct {
		rect_pos: _RectPos,
		color: _Color,
	}

	rect_deets_buffer: u32
	gl.GenBuffers(1, &rect_deets_buffer)
	gl.BindBuffer(gl.ARRAY_BUFFER, rect_deets_buffer)

	gl.EnableVertexAttribArray(u32(VertAttrs.RectPos))
	gl.VertexAttribPointer(u32(VertAttrs.RectPos), 4, gl.FLOAT, false, size_of(_Vertex), offset_of(_Vertex, rect_pos))
	gl.VertexAttribDivisor(u32(VertAttrs.RectPos), 1)

	gl.EnableVertexAttribArray(u32(VertAttrs.Color))
	gl.VertexAttribPointer(u32(VertAttrs.Color), 4, gl.FLOAT, false, size_of(_Vertex), offset_of(_Vertex, color))
	gl.VertexAttribDivisor(u32(VertAttrs.Color), 1)


	// Set up rect points buffer
	rect_pos := []glm.vec2{ {0.0, 0.0}, {1.0, 0.0}, {0.0, 1.0}, {1.0, 1.0} }
	rect_points_buffer: u32
	gl.GenBuffers(1, &rect_points_buffer)
	gl.BindBuffer(gl.ARRAY_BUFFER, rect_points_buffer)
	gl.BufferData(gl.ARRAY_BUFFER, len(rect_pos)*size_of(rect_pos[0]), raw_data(rect_pos), gl.STATIC_DRAW)
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
	
	width := f32(window_width)
	height := f32(window_height)
	gl.Viewport(0, 0, window_width, window_height)

	start_tick := time.tick_now()
	loop: for {
		duration := time.tick_since(start_tick)
		t := f32(time.duration_seconds(duration))

		// event polling
		event: SDL.Event = ---
		for SDL.PollEvent(&event) {
			#partial switch event.type {
			case .KEYDOWN:
				#partial switch event.key.keysym.sym {
				case .ESCAPE:
					break loop
				}
			case .QUIT:
				break loop
			case .WINDOWEVENT:
				#partial switch event.window.event {
				case .RESIZED:
					width = f32(event.window.data1)
					height = f32(event.window.data2)
					gl.Viewport(0, 0, event.window.data1, event.window.data2)
				}
			case .DROPFILE:
				filename := strings.clone_from_cstring(event.drop.file)
				SDL.free(rawptr(event.drop.file))

				start_time := time.tick_now()
				trace := load_file(filename)
				duration := time.tick_since(start_time)
				free_trace(&trace)

				delete(filename)
				fmt.printf("runtime: %f ms, got %d events\n", time.duration_milliseconds(duration), trace.event_count)
			}
		}

		gl.ClearColor(0.5, 0.7, 1.0, 1.0)
		gl.Clear(gl.COLOR_BUFFER_BIT)

		gl.Uniform1f(uniforms["u_dpr"].location, 1)
		gl.Uniform2f(uniforms["u_resolution"].location, width, height)
		gl.BindBuffer(gl.ARRAY_BUFFER, rect_deets_buffer)
		gl.BindVertexArray(vao);

		rects := []_Vertex{
			{{(width / 4), (height / 4), width / 2, height / 2}, {0.0, 0.0, 1.0, 1.0}}
		}
		gl.BufferData(gl.ARRAY_BUFFER, len(rects)*size_of(rects[0]), raw_data(rects), gl.DYNAMIC_DRAW)
		gl.DrawElementsInstanced(gl.TRIANGLES, i32(len(indices)), gl.UNSIGNED_SHORT, nil, i32(len(rects)))

		SDL.GL_SwapWindow(window)
	}
}
