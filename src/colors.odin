package main

import "core:fmt"
import "core:mem"
import "core:hash"
import "core:math/rand"
import "core:math/linalg/glsl"

Colors :: struct {
	bg:          BVec4,
	bg2:         BVec4,
	text:        BVec4,
	text2:       BVec4,
	text3:       BVec4,
	subtext:     BVec4,
	hint_text:   BVec4,
	line:        BVec4,
	division:    BVec4,
	subdivision: BVec4,
	outline:     BVec4,
	xbar:        BVec4,
	error:       BVec4,

	subbar:       BVec4,
	subbar_split: BVec4,
	toolbar:      BVec4,
	toolbar_button: BVec4,
	toolbar_text:   BVec4,
	loading_block:  BVec4,
	tabbar:         BVec4,

	graph:              BVec4,
	highlight:          BVec4,
	shadow:             BVec4,
	wide_rect:          BVec4,
	wide_bg:            BVec4,
	rect_tooltip_stats: BVec4,
	test:               BVec4,
	grip:               BVec4,
}

ColorMode :: enum {
	Dark,
	Light,
	Auto,
}

default_colors :: proc "contextless" (pt: ^Platform_State, is_dark: bool) {
	colors := &pt.colors

	colors.loading_block  = BVec4{100, 194, 236, 255}

	colors.error = BVec4{0xFF, 0x3F, 0x83, 255}
	colors.test  = BVec4{255, 10, 10, 255}

	// dark mode
	if is_dark {
		colors.bg        = BVec4{15,   15,  15, 255}
		colors.bg2       = BVec4{0,     0,   0, 255}
		colors.text      = BVec4{255, 255, 255, 255}
		colors.text2     = BVec4{180, 180, 180, 255}
		colors.text3     = BVec4{0,     0,   0, 255}
		colors.subtext   = BVec4{120, 120, 120, 255}
		colors.hint_text = BVec4{60,   60,  60, 255}
		colors.line      = BVec4{0,     0,   0, 255}
		colors.outline   = BVec4{80,   80,  80, 255}

		colors.subbar         = BVec4{0x33, 0x33, 0x33, 255}
		colors.subbar_split   = BVec4{0x50, 0x50, 0x50, 255}
		colors.toolbar_button = BVec4{40, 40, 40, 255}
		colors.toolbar        = BVec4{0x00, 0x83, 0xb7, 255}
		colors.toolbar_text   = BVec4{0xF5, 0xF5, 0xF5, 255}
		colors.tabbar         = BVec4{0x3A, 0x3A, 0x3A, 255}

		colors.graph     = BVec4{180, 180, 180, 255}
		colors.highlight = BVec4{ 64,  64, 255,   7}
		colors.wide_rect = BVec4{  0, 255,   0,   0}
		colors.wide_bg   = BVec4{  0,   0,   0, 255}
		colors.shadow    = BVec4{  0,   0,   0, 120}

		colors.subdivision = BVec4{ 30,  30, 30, 255}
		colors.division    = BVec4{100, 100, 100, 255}
		colors.xbar        = BVec4{180, 180, 180, 255}
		colors.grip        = BVec4{40, 40, 40, 255}

		colors.rect_tooltip_stats = BVec4{80, 255, 80, 255}

	// light mode
	} else {
		colors.bg         = BVec4{254, 252, 248, 255}
		colors.bg2        = BVec4{255, 255, 255, 255}
		colors.text       = BVec4{20,   20,  20, 255}
		colors.text2      = BVec4{80,   80,  80, 255}
		colors.text3      = BVec4{0,     0,   0, 255}
		colors.subtext    = BVec4{40,   40,  40, 255}
		colors.hint_text  = BVec4{60,   60,  60, 255}
		colors.line       = BVec4{200, 200, 200, 255}
		colors.outline    = BVec4{219, 211, 205, 255}

		colors.subbar         = BVec4{235, 230, 225, 255}
		colors.subbar_split   = BVec4{150, 150, 150, 255}
		colors.tabbar         = BVec4{220, 215, 210, 255}
		colors.toolbar_button = BVec4{40, 40, 40, 255}
		colors.toolbar        = BVec4{0x00, 0x83, 0xb7, 255}
		colors.toolbar_text   = BVec4{0xF5, 0xF5, 0xF5, 255}

		colors.graph      = BVec4{69,   49,  34, 255}
		colors.highlight  = BVec4{255, 255,   0,  64}
		colors.wide_rect  = BVec4{  0, 255,   0,   0}
		colors.wide_bg    = BVec4{  0,  0,    0, 255}
		colors.shadow     = BVec4{  0,   0,   0,  30}

		colors.subdivision = BVec4{230, 230, 230, 255}
		colors.division    = BVec4{180, 180, 180, 255}
		colors.xbar        = BVec4{ 80,  80,  80, 255}
		colors.grip        = BVec4{180, 175, 170, 255}

		colors.rect_tooltip_stats = BVec4{20, 60, 20, 255}
	}
}

set_color_mode :: proc(pt: ^Platform_State, auto: bool, is_dark: bool) {
	default_colors(pt, is_dark)

	if auto {
		pt.colormode = ColorMode.Auto
	} else {
		pt.colormode = is_dark ? ColorMode.Dark : ColorMode.Light
	}
}

COLOR_CHOICES :: 64

// color_choices must be power of 2
name_color_idx :: proc(name_idx: u64) -> u64 {
	idx := name_idx
	k := transmute([]u8)([^]u64)(&idx)[:size_of(idx)]

	ret := #force_inline hash.murmur32(k)
	return u64(ret) & u64(COLOR_CHOICES - 1)
}

generate_color_choices :: proc(color_choices: []FVec3) {
	for i := 0; i < COLOR_CHOICES; i += 1 {

		h := rand.float32() * 0.5 + 0.5
		h *= h
		h *= h
		h *= h
		s := 0.5 + rand.float32() * 0.1
		v : f32 = 0.85

		color_choices[i] = hsv2rgb(FVec3{h, s, v}) * 255
	}
}

hsv2rgb :: proc(c: FVec3) -> FVec3 {
	K := glsl.vec3{1.0, 2.0 / 3.0, 1.0 / 3.0}
	sum := glsl.vec3{c.x, c.x, c.x} + K.xyz
	p := glsl.abs_vec3(glsl.fract(sum) * 6.0 - glsl.vec3{3,3,3})
	result := glsl.vec3{c.z, c.z, c.z} * glsl.mix(K.xxx, glsl.clamp(p - K.xxx, 0.0, 1.0), glsl.vec3{c.y, c.y, c.y})
	return FVec3{result.x, result.y, result.z}
}

hex_to_bvec :: proc "contextless" (v: u32) -> BVec4 {
	a := u8(v >> 24)
	r := u8(v >> 16)
	g := u8(v >> 8)
	b := u8(v >> 0)

	return BVec4{r, g, b, a}
}

bvec_to_flat_fvec4 :: proc "contextless" (c: BVec4) -> FVec4 {
	return FVec4{f32(c.x) / 255, f32(c.y) / 255, f32(c.z) / 255, f32(c.w) / 255}
}

bvec_to_fvec :: proc "contextless" (c: BVec4) -> FVec3 {
	return FVec3{f32(c.r), f32(c.g), f32(c.b)}
}

greyscale :: proc "contextless" (c: FVec3) -> FVec3 {
	return (c.x * 0.299) + (c.y * 0.587) + (c.z * 0.114)
}
