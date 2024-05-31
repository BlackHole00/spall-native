package main

import "core:strings"
import "core:fmt"
import "core:math"
import "core:container/lru"
import "core:time"
import "core:unicode/utf8"

import SDL "vendor:sdl2"
import gl "vendor:OpenGL"

import stbtt "vendor:stb/truetype"

mouse_down :: proc(x, y: f64) {
	is_mouse_down = true
	mouse_pos = Vec2{x, y}

	if frame_count != last_frame_count {
		last_mouse_pos = mouse_pos
		last_frame_count = frame_count
	}

	clicked = true
	clicked_pos = mouse_pos

	cur_time := time.tick_now()
	time_diff := time.tick_diff(clicked_t, cur_time)
	click_window := time.duration_milliseconds(time_diff)
	double_click_window_ms := 400.0

	if click_window < double_click_window_ms {
		double_clicked = true
	} else {
		double_clicked = false
	}
	clicked_t = cur_time
}

mouse_up :: proc(x, y: f64) {
	is_mouse_down = false
	was_mouse_down = true
	mouse_up_now = true

	if frame_count != last_frame_count {
		last_mouse_pos = mouse_pos
		last_frame_count = frame_count
	}

	mouse_pos = Vec2{x, y}
}

mouse_moved :: proc(x, y: f64) {
	if frame_count != last_frame_count {
		last_mouse_pos = mouse_pos
		last_frame_count = frame_count
	}

	mouse_pos = Vec2{x, y}
}

mouse_scroll :: proc(y: f64) {
	y_dist := y * velocity_multiplier
	if ctrl_down {
		y_dist *= 10
	}
	scroll_val_y += y_dist
}

draw_rect :: proc(rects: ^[dynamic]DrawRect, rect: Rect, color: BVec4) {
	append(rects, DrawRect{FVec4{f32(rect.x), f32(rect.y), f32(rect.w), f32(rect.h)}, color, FVec2{-2, 0.0}})
}

draw_line :: proc(rects: ^[dynamic]DrawRect, start, end: Vec2, width: f64, color: BVec4) {
	start, end := start, end
	if start.x > end.x {
		end, start = start, end
	}

	append(rects, DrawRect{FVec4{f32(start.x), f32(start.y), f32(end.x), f32(end.y)}, color, FVec2{f32(width), -2}})
}

draw_rect_outline :: proc(rects: ^[dynamic]DrawRect, rect: Rect, width: f64, color: BVec4) {
	x1 := rect.x
	y1 := rect.y
	x2 := rect.x + rect.w
	y2 := rect.y + rect.h

	draw_line(rects, Vec2{x1, y1}, Vec2{x2, y1}, width, color)
	draw_line(rects, Vec2{x1, y1}, Vec2{x1, y2}, width, color)
	draw_line(rects, Vec2{x2, y1}, Vec2{x2, y2}, width, color)
	draw_line(rects, Vec2{x1, y2}, Vec2{x2, y2}, width, color)
}

draw_rect_inline :: proc(rects: ^[dynamic]DrawRect, rect: Rect, width: f64, color: BVec4) {
	x1 := rect.x + width
	y1 := rect.y + width
	x2 := rect.x + rect.w - width
	y2 := rect.y + rect.h - width

	draw_line(rects, Vec2{x1, y1}, Vec2{x2, y1}, width, color)
	draw_line(rects, Vec2{x1, y1}, Vec2{x1, y2}, width, color)
	draw_line(rects, Vec2{x2, y1}, Vec2{x2, y2}, width, color)
	draw_line(rects, Vec2{x1, y2}, Vec2{x2, y2}, width, color)
}

set_cursor :: proc(type: string) {
	switch type {
	case "auto":    SDL.SetCursor(default_cursor)
	case "pointer": SDL.SetCursor(pointer_cursor)
	case "text":    SDL.SetCursor(text_cursor)
	}
	is_hovering = true
}
reset_cursor :: proc() { 
	set_cursor("auto") 
	is_hovering = false
}


get_text_height :: proc(scale: FontSize, font: FontType) -> f64 { 
	#partial switch scale {
	case .PSize: return p_height
	case .H1Size: return h1_height
	case .H2Size: return h2_height
	}

	push_fatal(SpallError.Bug)
}

rm_text_cache :: proc(key: LRU_Key, value: LRU_Text, udata: rawptr) {
	handle := value.handle

	delete(key.str)
	gl.DeleteTextures(1, &handle)
}

cache_hits_this_frame := 0
cache_misses_this_frame := 0


font_map: [FontType.LastFont]stbtt.fontinfo
font_temp : [256*256]u8
font_size : [FontSize.LastSize]f32

alpha_blit :: proc(dst, src:IRect, srcStride:i32, output:[]u8, input:[]u8)
{
	for i :i32= 0; i < src.h; i += 1 {
		for j :i32= 0; j < src.w; j += 1 {
			output[(i+dst.y) * dst.w + (j+dst.x)] += input[(i+src.y) * srcStride + (j+src.x)]
		}
	}
}

get_text_cache :: proc(str: string, scale: FontSize, font_type: FontType) -> LRU_Text {
	text_blob, ok := lru.get(&lru_text_cache, LRU_Key{ scale, font_type, str })
	if !ok {
		//font := get_font(scale, font_type)
		long_str := strings.clone(str)

		width :i32= 0
		height :i32= 0
		pen := FVec2 {0, 0}
		pixel_height := font_size[scale]
		fontinfo := &font_map[font_type]

		sf := stbtt.ScaleForMappingEmToPixels(fontinfo, pixel_height)
		runes := utf8.string_to_runes(str)
		for ch, i in runes {
			adv, lsb : i32
			stbtt.GetCodepointHMetrics(fontinfo, ch, &adv, &lsb)
			x0, y0, x1, y1:i32
			stbtt.GetCodepointBox(fontinfo, ch, &x0, &y0, &x1, &y1)
			width += adv 
			if i < len(runes)-1 {
				width += stbtt.GetCodepointKernAdvance(fontinfo, ch, runes[i+1])
			}
		}
		width = cast(i32)(cast(f32)width * sf)
		width += 2

		ascent, descent, lineGap : i32
		stbtt.GetFontVMetrics(fontinfo, &ascent, &descent, &lineGap)
		height += cast(i32)(cast(f32)(ascent - descent) * sf + 2)

		baseline := cast(i32)(cast(f32)ascent * sf) + 1

		output := make([]u8, width * height)

		for ch, i in runes {
			adv, lsb : i32
			stbtt.GetCodepointHMetrics(fontinfo, ch, &adv, &lsb)

			subpixel := pen.x - math.floor(pen.x)

			ix0, iy0, ix1, iy1 : i32
			stbtt.GetCodepointBitmapBoxSubpixel(fontinfo, ch, sf, sf, subpixel, 0, &ix0, &iy0, &ix1, &iy1)
			x0, y0, x1, y1:i32
			stbtt.GetCodepointBox(fontinfo, ch, &x0, &y0, &x1, &y1)

			//stbtt.MakeCodepointBitmap(fontinfo, raw_data(font_temp[:]), ix1 - ix0, iy1 - iy0, 256, sf, sf, ch)
			stbtt.MakeGlyphBitmapSubpixel(fontinfo, raw_data(font_temp[:]), ix1-ix0, iy1-iy0, 256, sf, sf, subpixel, 0, stbtt.FindGlyphIndex(fontinfo, ch))

			src := IRect { 0, 0, ix1 - ix0, iy1 - iy0 }
			dst := IRect { cast(i32) (pen.x + cast(f32)(lsb) * sf), baseline + iy0, width, height }

			alpha_blit(dst, src, 256, output, font_temp[:])

			if i < len(runes)-1 {
				pen.x += sf * cast(f32)stbtt.GetCodepointKernAdvance(fontinfo, ch, runes[i+1])
			}

			pen.x += cast(f32)adv * sf
		}

		output32 := make([]u32, width * height)
		for i := 0; i < len(output); i += 1 {
			o := cast(u32)output[i]
			output32[i] = o << 24 | o << 8 | o << 16 | o
		}

		handle : u32 = 0
		gl.GenTextures(1, &handle)
		gl.ActiveTexture(gl.TEXTURE0)
		gl.BindTexture(gl.TEXTURE_2D, handle)
		gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR)
		gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR)
		gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE)
		gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE)
		gl.TexImage2D(gl.TEXTURE_2D, 0, gl.RGBA, width, height, 0, gl.RGBA, gl.UNSIGNED_BYTE, raw_data(output32))
		delete(output)
		delete(output32)
		//delete(pixels)

		text_blob = LRU_Text{ handle, width, height }
		lru.set(&lru_text_cache, LRU_Key{ scale, font_type, long_str }, text_blob)
		cache_misses_this_frame += 1
	} else {
		cache_hits_this_frame += 1
	}

	return text_blob
}

measure_text :: proc(str: string, scale: FontSize, font_type: FontType) -> f64 {
	if len(str) == 0 {
		return 0
	}

	text_blob := get_text_cache(str, scale, font_type)
	return f64(text_blob.width) / dpr
}

draw_text :: proc(rects: ^[dynamic]DrawRect, str: string, pos: Vec2, scale: FontSize, font_type: FontType, color: BVec4) {
	if len(str) == 0 {
		return
	}

	text_blob := get_text_cache(str, scale, font_type)
	gl.BindTexture(gl.TEXTURE_2D, text_blob.handle)

	x_pos := f32(math.round(pos.x))
	y_pos := f32(math.round(pos.y))
	w := f32(f64(text_blob.width) / dpr)
	h := f32(f64(text_blob.height) / dpr)
	append(rects, DrawRect{FVec4{x_pos, y_pos, w, h}, color, FVec2{0.0, 0.0}})
	flush_rects(rects)
}
batch_text :: proc(text_rects: ^[dynamic]TextRect, str: string, pos: Vec2, scale: FontSize, font_type: FontType, color: BVec4) {
	if len(str) == 0 {
		return
	}

	x_pos := f32(math.round(pos.x))
	y_pos := f32(math.round(pos.y))
	append(text_rects, TextRect{
		str = str,
		scale = scale,
		type = font_type,
		pos = FVec2{x_pos, y_pos},
		color = color,
	})
}

flush_text_batch :: proc(text_rects: ^[dynamic]TextRect) {
	for rect in text_rects {
		text_blob := get_text_cache(rect.str, rect.scale, rect.type)
		gl.BindTexture(gl.TEXTURE_2D, text_blob.handle)

		w := f32(f64(text_blob.width) / dpr)
		h := f32(f64(text_blob.height) / dpr)
		draw_rect := DrawRect{FVec4{rect.pos.x, rect.pos.y, w, h}, rect.color, FVec2{0.0, 0.0}}
		gl.BufferData(gl.ARRAY_BUFFER, size_of(draw_rect), &draw_rect, gl.DYNAMIC_DRAW)
		gl.DrawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, 1)
	}

	non_zero_resize(text_rects, 0)
}

flush_rects :: proc(rects: ^[dynamic]DrawRect) {
	gl.BufferData(gl.ARRAY_BUFFER, len(rects)*size_of(rects[0]), raw_data(rects[:]), gl.DYNAMIC_DRAW)
	gl.DrawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, i32(len(rects)))
	non_zero_resize(rects, 0)
}

get_system_color :: proc() -> bool { return false }
get_session_storage :: proc(key: string) { }
set_session_storage :: proc(key, val: string) { }

get_clipboard :: proc() -> string {
	return string(SDL.GetClipboardText())
}
set_clipboard :: proc(text: string) {
	cstr_text := strings.clone_to_cstring(text, context.temp_allocator)
	SDL.SetClipboardText(cstr_text)
}
