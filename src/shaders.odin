package main

VertAttrs :: enum u32 {
	IdxPos = 0,
	RectPos = 1,
	Color = 2,
	UV = 3,
}

rect_vert_src := `#version 330 core

// idx_pos  {x, y}
layout(location=0) in vec2 idx_pos;

// rect_pos {x, y, width, height}
layout(location=1) in vec4 in_rect_pos;
layout(location=2) in vec4 color;
layout(location=3) in vec2 uv;

uniform float u_dpr;
uniform vec2  u_resolution;

out vec4 v_color;
out vec2 v_uv;
out vec4 v_rect_pos;

void main() {
	vec4 rect_pos = in_rect_pos * u_dpr;

	// if line
	if (uv.y < 0) {
		float width = uv.x * u_dpr;
		vec2 a = rect_pos.xy;
		vec2 b = rect_pos.zw;
		vec2 center = mix(a, b, 0.5);
		vec2 fwd = normalize(b - a);
		vec2 norm = vec2(-fwd.y, fwd.x) * width;

		vec2 p0 = a - fwd + norm;
		vec2 p1 = b + fwd - norm;
		vec2 s = -2.0 * norm;
		vec2 t = p1 - p0 - s;

		vec2 xy = p0 + (idx_pos.x * s) + (idx_pos.y * t);
		gl_Position = vec4((xy / u_resolution) * 2.0 - 1.0, 0.0, 1.0);
		gl_Position.y = -gl_Position.y;

		v_rect_pos = rect_pos;

	// if rect
	} else {
		vec2 xy = vec2(rect_pos.x, rect_pos.y) + (idx_pos * vec2(rect_pos.z, rect_pos.w));

		gl_Position = vec4((xy / u_resolution) * 2.0 - 1.0, 0.0, 1.0);
		gl_Position.y = -gl_Position.y;
	}

	v_color = color;
	v_uv = uv;
}
`

rect_frag_src := `#version 330 core
in vec4 v_color;
in vec4 v_rect_pos;
in vec2 v_uv;
out vec4 out_color;

uniform float u_dpr;
uniform vec2  u_resolution;

float sdSegment(vec2 p, vec2 a, vec2 b) {
	vec2 pa = p-a, ba = b-a;
	float h = clamp(dot(pa, ba) / dot(ba, ba), 0.0, 1.0);
	return length(pa - (ba * h));
}

float sdOrientedBox( in vec2 p, in vec2 a, in vec2 b, float thick) {
    float l = length(b-a);
    vec2  d = (b-a)/l;
    vec2  q = p-(a+b)*0.5;
          q = mat2(d.x,-d.y,d.y,d.x)*q;
          q = abs(q)-vec2(l*0.5,thick);
    return length(max(q,0.0)) + min(max(q.x,q.y),0.0);    
}

void main() {
	// if line
	if (v_uv.y < 0) {
		float width = v_uv.x * u_dpr;
		vec2 a = v_rect_pos.xy;
		vec2 b = v_rect_pos.zw;

		vec2 pos = vec2(gl_FragCoord.x, u_resolution.y - gl_FragCoord.y);

		float d = sdOrientedBox(pos, a, b, width);
		float alpha = 1.0 - smoothstep(-min(2.0, width - 0.5), 0.0, d); 
		out_color = vec4(v_color.rgb, v_color.a * alpha);

	// if rect
	} else {
		out_color = v_color;
	}
}
`

text_frag_src := `#version 330 core
uniform sampler2D font_tex;

in vec4 v_color;
in vec2 v_uv;
out vec4 out_color;

void main() {
	out_color = vec4(v_color.rgb, (v_color.a * texture(font_tex, v_uv).r));
}
`
