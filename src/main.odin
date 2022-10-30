package main

import "core:fmt"
import "core:time"
import "core:os"

import glm "core:math/linalg/glsl"

import SDL "vendor:sdl2"
import gl "vendor:OpenGL"

import "formats:spall"


vertex_source := `#version 330 core
layout(location=0) in vec3 a_position;
layout(location=1) in vec4 a_color;

out vec4 v_color;

uniform mat4 u_transform;

void main() {
	gl_Position = u_transform * vec4(a_position, 1.0);
	v_color = a_color;
}
`

fragment_source := `#version 330 core
in vec4 v_color;

out vec4 o_color;

void main() {
	o_color = v_color;
}
`

push_fatal :: proc(err: SpallError) -> ! {
	fmt.eprintf("Error: %v\n", err)
	os.exit(1)
}

string_block: [dynamic]u8

main :: proc() {
	if len(os.args) < 2 {
		fmt.eprintf("Expected: %v <tracename.spall>\n", os.args[0])
		os.exit(1)
	}

	trace_fd, err := os.open(os.args[1])
	if err != 0 {
		fmt.printf("Failed to open %s\n", os.args[1])
		os.exit(1)
	}
	total_size, err2 := os.file_size(trace_fd)
	if err != 0 {
		fmt.printf("Failed to get file size for %s\n", os.args[1])
		os.exit(1)
	}

	CHUNK_BUFFER_SIZE :: 64 * 1024
	string_block = make([dynamic]u8)
	chunk_buffer := make([]u8, CHUNK_BUFFER_SIZE)

	rd_sz, err3 := os.read(trace_fd, chunk_buffer)
	if err2 != 0 {
		fmt.printf("Failed to read %s\n", os.args[1])
		os.exit(1)
	}

	// parse header
	chunk := chunk_buffer[:rd_sz]

	header_sz := i64(size_of(spall.Header))
	if i64(len(chunk)) < header_sz {
		push_fatal(SpallError.InvalidFile)
	}

	magic := (^u64)(raw_data(chunk))^
	if magic != spall.MAGIC {
		push_fatal(SpallError.InvalidFile)
	}

	hdr := cast(^spall.Header)raw_data(chunk)
	if hdr.version != 1 {
		fmt.printf("Your file version (%d) is not supported!\n", hdr.version)
		push_fatal(SpallError.InvalidFileVersion)
	}
	
	p := init_parser(total_size)
	p.pos += header_sz

	// loop over the event data
	for {
		p.full_chunk = chunk
		hot_loop: for {
			ev, state := get_next_event(&p)
			#partial switch state {
			case .PartialRead:
				p.offset = p.pos

				_, err := os.seek(trace_fd, p.offset, os.SEEK_SET)
				if err != 0 {
					fmt.printf("Failed to seek %s\n", os.args[1])
					os.exit(1)
				}
				rd_sz, err2 := os.read(trace_fd, chunk_buffer)
				if err2 != 0 {
					fmt.printf("Failed to read %s\n", os.args[1])
					os.exit(1)
				}

				chunk = chunk_buffer[:rd_sz]
				break hot_loop
			case .Finished:
				os.exit(0)
			}
		}

	}

/*
	WINDOW_WIDTH  :: 640
	WINDOW_HEIGHT :: 480

	SDL.Init({.VIDEO})

	window := SDL.CreateWindow("spall", SDL.WINDOWPOS_UNDEFINED, SDL.WINDOWPOS_UNDEFINED, WINDOW_WIDTH, WINDOW_HEIGHT, {.OPENGL})
	if window == nil {
		fmt.eprintln("Failed to create window")
		return
	}

	GL_VERSION_MAJOR :: 3
	GL_VERSION_MINOR :: 3
	SDL.GL_SetAttribute(.CONTEXT_PROFILE_MASK,  i32(SDL.GLprofile.CORE))
	SDL.GL_SetAttribute(.CONTEXT_MAJOR_VERSION, GL_VERSION_MAJOR)
	SDL.GL_SetAttribute(.CONTEXT_MINOR_VERSION, GL_VERSION_MINOR)

	gl_context := SDL.GL_CreateContext(window)
	gl.load_up_to(GL_VERSION_MAJOR, GL_VERSION_MINOR, SDL.gl_set_proc_address)

	program, program_ok := gl.load_shaders_source(vertex_source, fragment_source)
	if !program_ok {
		fmt.eprintln("Failed to create GLSL program")
		return
	}

	gl.UseProgram(program)

	uniforms := gl.get_uniforms_from_program(program)

	vao: u32
	gl.GenVertexArrays(1, &vao); defer gl.DeleteVertexArrays(1, &vao)
	gl.BindVertexArray(vao)

	vbo, ebo: u32
	gl.GenBuffers(1, &vbo); defer gl.DeleteBuffers(1, &vbo)
	gl.GenBuffers(1, &ebo); defer gl.DeleteBuffers(1, &ebo)

	Vertex :: struct {
		pos: glm.vec3,
		col: glm.vec4,
	}

	vertices := []Vertex{
		{{-0.5, +0.5, 0}, {1.0, 0.0, 0.0, 0.75}},
		{{-0.5, -0.5, 0}, {1.0, 1.0, 0.0, 0.75}},
		{{+0.5, -0.5, 0}, {0.0, 1.0, 0.0, 0.75}},
		{{+0.5, +0.5, 0}, {0.0, 0.0, 1.0, 0.75}},
	}

	indices := []u16{
		0, 1, 2,
		2, 3, 0,
	}

	gl.BindBuffer(gl.ARRAY_BUFFER, vbo)
	gl.BufferData(gl.ARRAY_BUFFER, len(vertices)*size_of(vertices[0]), raw_data(vertices), gl.STATIC_DRAW)
	gl.EnableVertexAttribArray(0)
	gl.EnableVertexAttribArray(1)
	gl.VertexAttribPointer(0, 3, gl.FLOAT, false, size_of(Vertex), offset_of(Vertex, pos))
	gl.VertexAttribPointer(1, 4, gl.FLOAT, false, size_of(Vertex), offset_of(Vertex, col))

	gl.BindBuffer(gl.ELEMENT_ARRAY_BUFFER, ebo)
	gl.BufferData(gl.ELEMENT_ARRAY_BUFFER, len(indices)*size_of(indices[0]), raw_data(indices), gl.STATIC_DRAW)

	// high precision timer
	start_tick := time.tick_now()

	loop: for {
		duration := time.tick_since(start_tick)
		t := f32(time.duration_seconds(duration))

		// event polling
		event: SDL.Event
		for SDL.PollEvent(&event) {
			#partial switch event.type {
			case .KEYDOWN:
				#partial switch event.key.keysym.sym {
				case .ESCAPE:
					break loop
				}
			case .QUIT:
				break loop
			}
		}

		// Native support for GLSL-like functionality
		pos := glm.vec3{glm.cos(t * 2), glm.sin(t * 2), 0,}
		pos *= 0.3

		model := glm.mat4{
			0.5,   0,   0, 0,
			  0, 0.5,   0, 0,
			  0,   0, 0.5, 0,
			  0,   0,   0, 1,
		}

		model[0, 3] = -pos.x
		model[1, 3] = -pos.y
		model[2, 3] = -pos.z
		model[3].yzx = pos.yzx

		model = model * glm.mat4Rotate({0, 1, 1}, t)

		view := glm.mat4LookAt({0, -1, +1}, {0, 0, 0}, {0, 0, 1})
		proj := glm.mat4Perspective(45, 1.3, 0.1, 100.0)

		u_transform := proj * view * model

		gl.UniformMatrix4fv(uniforms["u_transform"].location, 1, false, &u_transform[0, 0])

		gl.Viewport(0, 0, WINDOW_WIDTH, WINDOW_HEIGHT)
		gl.ClearColor(0.5, 0.7, 1.0, 1.0)
		gl.Clear(gl.COLOR_BUFFER_BIT)

		gl.DrawElements(gl.TRIANGLES, i32(len(indices)), gl.UNSIGNED_SHORT, nil)

		SDL.GL_SwapWindow(window)
	}
*/
}
