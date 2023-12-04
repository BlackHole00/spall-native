package main

import "core:intrinsics"
import "core:mem"
import "core:math/rand"
import "core:math"
import "core:fmt"
import "core:c"
import "core:strings"
import "core:runtime"
import "core:os"

trap :: proc() -> ! {
	intrinsics.trap()
}

panic :: proc(fmt_in: string, args: ..any) -> ! {
	fmt.printf(fmt_in, ..args)
	intrinsics.trap()
}
post_error :: proc(trace: ^Trace, fmt_in: string, args: ..any) {
	fmt.eprintf(fmt_in, ..args)
	fmt.eprintf("\n")
	trace.error_message = fmt.bprintf(trace.error_storage[:], fmt_in, ..args)
}

@(cold)
push_fatal :: proc(err: SpallError) -> ! {
	fmt.eprintf("Error: %v\n", err)
	trap()
	// os.exit(1)
}

rand_int :: proc(min, max: int) -> int {
    return int(rand.int31()) % (max-min) + min
}

split_u64 :: proc(x: u64) -> (u32, u32) {
	lo := u32(x)
	hi := u32(x >> 32)
	return lo, hi
}

compose_u64 :: proc(lo, hi: u32) -> (u64) {
	return u64(hi) << 32 | u64(lo)
}

rescale :: proc(val, old_min, old_max, new_min, new_max: $T) -> T {
	old_range := old_max - old_min
	new_range := new_max - new_min
	return (((val - old_min) * new_range) / old_range) + new_min
}

i_round_down :: proc(x, align: $T) -> T {
	return x - (x %% align)
}

i_round_up :: proc(x, align: $T) -> T {
	return ((x + align - 1) / align) * align
}

div_ceil :: proc(x, y: $T) -> T {
	return ((x + y) - 1) / y
}

f_round_down :: proc(x, align: $T) -> T {
	return x - math.remainder(x, align)
}

val_in_range :: proc(val, start, end: $T) -> bool {
	return val >= start && val <= end
}
range_in_range :: proc(s1, e1, s2, e2: $T) -> bool {
	return s1 < e2 && e1 > s2
}

pt_in_rect :: proc(pt: Vec2, box: Rect) -> bool {
	x1 := box.x
	y1 := box.y
	x2 := box.x + box.w
	y2 := box.y + box.h

	return x1 <= pt.x && pt.x <= x2 && y1 <= pt.y && pt.y <= y2
}

rect_in_rect :: proc(a, b: Rect) -> bool {
	a_left := a.x
	a_right := a.x + a.w

	a_top := a.y
	a_bottom := a.y + a.h

	b_left := b.x
	b_right := b.x + b.w

	b_top := b.y
	b_bottom := b.y + b.h

	return !(b_left > a_right || a_left > b_right || a_top > b_bottom || b_top > a_bottom)
}

ease_in :: proc(t: f32) -> f32 {
	return 1 - math.cos((t * math.PI) / 2)
}
ease_in_out :: proc(t: f32) -> f32 {
    return -(math.cos(math.PI * t) - 1) / 2;
}

ONE_DAY    :: 1000 * 1000 * 1000 * 60 * 60 * 24
ONE_HOUR   :: 1000 * 1000 * 1000 * 60 * 60
ONE_MINUTE :: 1000 * 1000 * 1000 * 60
ONE_SECOND :: 1000 * 1000 * 1000
ONE_MILLI  :: 1000 * 1000
ONE_MICRO  :: 1000
ONE_NANO   :: 1

tens_fmt :: proc(x: u64, allocator := context.temp_allocator) -> string {
	val_buf := [32]u8{}
	chars := [?]u8{'0', '1', '2', '3', '4', '5' , '6', '7', '8', '9'}

	tmp := x
	pos := 0
	for tmp := x; tmp != 0; pos += 1 {
		val_buf[pos] = chars[tmp % 10]
		tmp /= 10
	}

	digit_count := pos
	skip_first := (digit_count % 3) == 0

	out_buf := [32]u8{}
	idx := 0
	for i := 0; i < digit_count; i += 1 {
		if (pos % 3) == 0 && !(i == 0 && skip_first) {
			out_buf[idx] = ','
			idx += 1
		}

		out_buf[idx] = val_buf[pos-1]

		pos -= 1
		idx += 1
	}

	return strings.clone_from_bytes(out_buf[:idx], allocator)
}

tooltip_fmt :: proc(time: f64) -> string {
	if time >= ONE_SECOND {
		cur_time := time / ONE_SECOND
		return fmt.tprintf("%.1f s ", cur_time)
	} else if time >= ONE_MILLI {
		cur_time := time / ONE_MILLI
		return fmt.tprintf("%.1f ms", cur_time)
	} else if time >= ONE_MICRO {
		cur_time := time / ONE_MICRO
		return fmt.tprintf("%.1f μs", cur_time)
	} else {
		return fmt.tprintf("%.0f ns", time)
	}
}

stat_fmt :: proc(time: f64) -> string {
	if time >= ONE_SECOND {
		cur_time := time / ONE_SECOND
		return fmt.tprintf("%.1f s ", cur_time)
	} else if time >= ONE_MILLI {
		cur_time := time / ONE_MILLI
		return fmt.tprintf("%.1f ms", cur_time)
	} else if time >= ONE_MICRO {
		cur_time := time / ONE_MICRO
		return fmt.tprintf("%.1f us", cur_time) // μs
	} else {
		return fmt.tprintf("%.1f ns", time)
	}
}

my_write_float :: proc(b: ^strings.Builder, f: f64, prec: int) -> (n: int) {
	return strings.write_float(b, f, 'f', prec, 8*size_of(f))
}

TimeUnits :: struct {
	unit: string,
	period: f64,
	digits: int,
}
time_unit_table := [?]TimeUnits{
	{"d", max(f64), 3},
	{"h",       24, 2},
	{"m",       60, 2},
	{"s",       60, 2},
	{"ms",    1000, 3},
	{"μs",    1000, 3},
	{"ns",    1000, 3},
	{"ps",    1000, 3},
}

get_div_clump_idx :: proc(divider: f64) -> (int, f64, f64) {
	div_clump_idx := 0

	time_fracts := [?]f64{
		divider / ONE_DAY,
		divider / ONE_HOUR,
		divider / ONE_MINUTE,
		divider / ONE_SECOND,
		divider / ONE_MILLI,
		divider / ONE_MICRO,
		divider,
		math.round(divider * 1000),
	}

	for fract, idx in time_fracts {
		tmp : f64 = 0

		tu := time_unit_table[idx]
		if idx == len(time_fracts) - 1 {
			tmp = f64(int(fract) % int(tu.period))
		} else {
			tmp = math.floor(math.mod(fract, tu.period))
		}

		if tmp != 0 {
			div_clump_idx = idx
		}
	}

	fract := time_fracts[div_clump_idx]
	tu    := time_unit_table[div_clump_idx]
	return div_clump_idx, fract, tu.period
}



// if bool is true, draw the top string
clump_time :: proc(time: f64, div_clump_idx: int) -> (string, string, f64) {
	start_b := strings.builder_make(context.temp_allocator)
	tick_b := strings.builder_make(context.temp_allocator)

	_time := time
	if time < 0 {
		_time = math.abs(time)
		return "", "", 0
	}

	// preserving precision as much as possible while getting the fractional bits
	picos := f64(i64(math.round(_time * 1000)) % 1000)
	nanos  := math.floor(math.mod(_time, 1000))
	micros := math.floor(math.mod(_time / ONE_MICRO, 1000))
	millis := math.floor(math.mod(_time / ONE_MILLI, 1000))
	secs   := math.floor(math.mod(_time / ONE_SECOND, 60))
	mins   := math.floor(math.mod(_time / ONE_MINUTE, 60))
	hours  := math.floor(math.mod(_time / ONE_HOUR,   24))
	days   := math.floor(_time / ONE_DAY)

	clumps := [?]f64{days, hours, mins, secs, millis, micros, nanos, picos}

	b := &start_b
	tick_val := 0.0
	last_val := false
	first_num := true
	for clump, idx in clumps {
		tu := time_unit_table[idx]

		if idx == div_clump_idx {
			b = &tick_b

			if idx > 0 {
				tick_val = clumps[idx - 1]
			}
			last_val = true
		}

		if !last_val && (clump <= 0 || clump >= tu.period) {
			continue
		}

		if !first_num && !last_val {
			strings.write_rune(b, ' ')
		}
		my_write_float(b, clump, 0)
		strings.write_string(b, tu.unit)

		if last_val {
			break
		}
		first_num = false
	}

	start_str := strings.to_string(start_b)
	if len(start_str) == 0 {
		if div_clump_idx > 0 {
			strings.write_string(&start_b, "0")
			strings.write_string(&start_b, time_unit_table[div_clump_idx - 1].unit)
		}
	}
	start_str = strings.to_string(start_b)
	tick_str := strings.to_string(tick_b)
	return start_str, tick_str, tick_val
}

time_fmt :: proc(time: f64) -> string {
	b := strings.builder_make(context.temp_allocator)

	if time == 0 {
		strings.write_string(&b, " 0ns")
		return strings.to_string(b)
	}

	_time := time
	if time < 0 {
		strings.write_rune(&b, '-')
		_time = math.abs(time)
	}


	// preserving precision as much as possible while getting the fractional bits
	picos := f64(i64(math.round(_time * 1000)) % 1000)

	nanos  := math.floor(math.mod(_time, 1000))
	micros := math.floor(math.mod(_time / ONE_MICRO, 1000))
	millis := math.floor(math.mod(_time / ONE_MILLI, 1000))
	secs   := math.floor(math.mod(_time / ONE_SECOND, 60))
	mins   := math.floor(math.mod(_time / ONE_MINUTE, 60))
	hours  := math.floor(math.mod(_time / ONE_HOUR,   24))
	days  := math.floor(_time / ONE_DAY)

	clumps := [?]f64{days, hours, mins, secs, millis, micros, nanos, picos}

	first_num := true
	for clump, idx in clumps {
		tu := time_unit_table[idx]
		if (clump <= 0 || clump >= tu.period) {
			continue
		}

		if !first_num {
			strings.write_rune(&b, ' ')
		}
		my_write_float(&b, clump, 0)
		strings.write_string(&b, tu.unit)
		first_num = false
	}

	return strings.to_string(b)
}


measure_fmt :: proc(time: f64) -> string {
	b := strings.builder_make(context.temp_allocator)

	// preserving precision as much as possible while getting the fractional bits
	picos := f64(i64(math.round(time * 1000)) % 1000)

	nanos  := math.floor(math.mod(time, 1000))
	micros := math.floor(math.mod(time / ONE_MICRO, 1000))
	millis := math.floor(math.mod(time / ONE_MILLI, 1000))
	secs   := math.floor(math.mod(time / ONE_SECOND, 60))
	mins   := math.floor(math.mod(time / ONE_MINUTE, 60))
	hours  := math.floor(math.mod(time / ONE_HOUR,   24))
	days  := math.floor(time / ONE_DAY)

	clumps := [?]f64{days, hours, mins, secs, millis, micros, nanos, picos}
	for clump, idx in clumps {
		tu := time_unit_table[idx]
		if (clump <= 0 || clump >= tu.period) {
			continue
		}

		if (strings.builder_len(b) > 0 && idx > 0) {
			strings.write_rune(&b, ' ')
		}

		digits := int(math.log10(clump) + 1)
		for ;digits < tu.digits; digits += 1 {
			strings.write_byte(&b, ' ')
		}

		my_write_float(&b, clump, 0)
		strings.write_string(&b, tu.unit)
	}

	return strings.to_string(b)
}

parse_u32 :: proc(str: string) -> (val: u32, ok: bool) {
	ret : u64 = 0

	s := transmute([]u8)str
	for ch in s {
		if ch < '0' || ch > '9' || ret > u64(c.UINT32_MAX) {
			return
		}
		ret = (ret * 10) + u64(ch & 0xf)
	}
	return u32(ret), true
}

hexdigits := []u8{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' }
u64_to_hexstr :: proc(buf: []byte, val: u64) -> string {
	i := 17
	x := val

	if val == 0 {
		buf[0] = '0'
		buf[1] = 'x'
		buf[2] = '0'
		return string(buf[:3])
	}

	for ; x != 0; x /= 16 {
		buf[i] = hexdigits[x % 16]
		i -= 1
	}
	buf[i] = 'x'; i -= 1
	buf[i] = '0'
	return string(buf[i:])
}

// this *shouldn't* be called with 0-len strings. 
// The current JSON parser enforces it due to the way primitives are parsed
// We reject NaNs, Infinities, and Exponents in this house.
parse_f64 :: proc(str: string) -> (ret: f64, ok: bool) #no_bounds_check {
	sign: f64 = 1

	i := 0
	if str[0] == '-' {
		sign = -1
		i += 1

		if len(str) == 1 {
			return 0, false
		}
	}

	val: f64 = 0
	for ; i < len(str); i += 1 {
		ch := str[i]

		if ch == '.' {
			break
		}

		if ch < '0' || ch > '9' {
			return 0, false
		}

		val = (val * 10) + f64(ch & 0xf)
	}

	if i < len(str) && str[i] == '.' {
		pow10: f64 = 10
		i += 1

		for ; i < len(str); i += 1 {
			ch := str[i]

			if ch < '0' || ch > '9' {
				return 0, false
			}

			val += f64(ch & 0xf) / pow10
			pow10 *= 10
		}
	}

	return sign * val, true
}

// This only works for positive doubles. Don't be a dummy and use negative doubles
squashy_downer : f64 = 1 / math.F64_EPSILON
ceil_f64 :: proc(x: f64) -> f64 {
	i := transmute(u64)x

	e := int((i >> 52) & 0x7FF)
	if e >= (0x3FF + 52) || x == 0 {
		return x
	}

	y := x + squashy_downer - squashy_downer - x
	if e <= 0x3FF - 1 { return 1.0 }
	if y < 0 {
		return x + y + 1
	}
	return x + y
}

distance :: proc(p1, p2: Vec2) -> f64 {
	dx := p2.x - p1.x
	dy := p2.y - p1.y
	return math.sqrt((dx * dx) + (dy * dy))
}

geomean :: proc(a, b: f64) -> f64 {
	return math.sqrt(a * b)
}

trunc_string :: proc(str: string, pad, max_width: f64) -> string {
	text_width := int(math.floor((max_width - (pad * 2)) / ch_width))
	max_chars := max(0, min(len(str), text_width))
	chopped_str := str[:max_chars]
	if max_chars != len(str) {
		chopped_str = fmt.tprintf("%s…", chopped_str[:len(chopped_str)-1])
	}

	return chopped_str
}

slice_to_type :: proc(buf: []u8, $T: typeid) -> (T, bool) #optional_ok {
    if len(buf) < size_of(T) {
        return {}, false
    }

    return intrinsics.unaligned_load((^T)(raw_data(buf))), true
}

disp_time :: proc(trace: ^Trace, ts: f64) -> f64 {
	return ceil_f64(ts * trace.stamp_scale)
}

create_subbuffer :: proc(buffer: []u8, offset: u64, size: u64) -> ([]u8, bool) {
	if offset > u64(len(buffer)) || offset+size > u64(len(buffer)) {
		return nil, false
	}
	return buffer[offset:offset+size], true
}

MAX_BYTES :: 10
read_uleb :: proc(buffer: []u8) -> (u64, int, bool) {
	val    : u64 = 0
	offset := 0
	size   := 1

	for i := 0; i < MAX_BYTES; i += 1 {
		b := buffer[i]

		val = val | u64(b & 0x7F) << u64(offset * 7)
		offset += 1

		if b < 128 {
			return val, size, true
		}

		size += 1
	}

	return 0, 0, false
}

read_ileb :: proc(buffer: []u8) -> (i64, int, bool) {
	val    : i64 = 0
	offset := 0
	size   := 1

	for i := 0; i < MAX_BYTES; i += 1 {
		b := buffer[i]

		val = val | i64(b & 0x7F) << u64(offset * 7)
		offset += 1

		if b < 128 {
			if (b & 0x40) == 0x40 {
				val |= max(i64) << u64(offset * 7)
			}

			return val, size, true
		}

		size += 1
	}

	return 0, 0, false
}

continuation_byte :: proc(b: u8) -> bool {
	return b >= 0x80 && b < 0xC0
}

step_left_rune :: proc(buffer: []u8, cur: int) -> int {
	pos := cur
	if pos > 0 {
		pos -= 1
		for pos >= 0 && continuation_byte(buffer[pos]) {
			pos -= 1
		}
	}
	return pos
}
step_right_rune :: proc(buffer: []u8, cur: int) -> int {
	pos := cur
	if pos < len(buffer) {
		pos += 1
		for pos < len(buffer) && continuation_byte(buffer[pos]) {
			pos += 1
		}
	}
	return pos
}

squash_table_1 := [9]u8{1, 1, 2, 4, 4, 8, 8, 8, 8}
delta_to_size :: proc(v: u64) -> int {
	v := max(1, v)
	set_bits  := 64 - intrinsics.count_leading_zeros(v)
	set_bytes := (set_bits + 7) >> 3

	return int(squash_table_1[set_bytes])
}

squash_table_2 := [9]u8{0, 0, 1, 2, 2, 3, 3, 3, 3}
size_to_bits :: #force_inline proc(size: int) -> u16 {
	return u16(squash_table_2[size])
}

pull_uval :: #force_inline proc(buffer: []u8, size: int) -> u64 {
    switch size {
    case 1: return u64(((^u8)(raw_data(buffer)))^)
    case 2: return u64(((^u16)(raw_data(buffer)))^)
    case 4: return u64(((^u32)(raw_data(buffer)))^)
    case 8: return u64(((^u64)(raw_data(buffer)))^)
    }
    return 0
}

// Internal Event Format
//      1            2               3             4 5           6 7              8 9              10 11          12 13
// [ has addr | has duration | has self time | [ts dt size] | [id dt size] | [args dt size] | [dur dt size] | [self dt size] ]

pack_begin_event :: proc(buffer: []u8, has_addr: bool, ts_dt, id_dt, args_dt: u64) -> int {
	ts_dt_size   := delta_to_size(ts_dt)
	id_dt_size   := delta_to_size(id_dt)
	args_dt_size := delta_to_size(args_dt)

	ev_tag : u16 = (
		(u16(has_addr) << 15) | (0 << 14) | (0 << 13) | 
		size_to_bits(ts_dt_size)   << 11 | 
		size_to_bits(id_dt_size)   <<  9 | 
		size_to_bits(args_dt_size) <<  7 | 0
	)

	ts_dt   := ts_dt
	id_dt   := id_dt
	args_dt := args_dt

	i := 0
	mem.copy(raw_data(buffer[i:]), &ev_tag,  size_of(u16)); i += size_of(u16)
	mem.copy(raw_data(buffer[i:]), &ts_dt,   ts_dt_size);   i += ts_dt_size
	mem.copy(raw_data(buffer[i:]), &id_dt,   id_dt_size);   i += id_dt_size
	mem.copy(raw_data(buffer[i:]), &args_dt, args_dt_size); i += args_dt_size
	return i
}

bump_arr_cap :: proc(array: ^[dynamic]u8, bump: int, loc := #caller_location) {
	if cap(array) < (len(array) + bump) {
		cap := 2 * cap(array) + max(8, bump)

		// do not 'or_return' here as it could be a partial success
		non_zero_reserve(array, cap, loc)
	}
	a := (^runtime.Raw_Dynamic_Array)(array)
	a.len += bump
	return
}

add_event :: proc(depth: ^Depth, has_addr: bool, ts: i64, id, args: u64) {
	dt_ts   := ts   - depth.last_ts
	dt_id   := id   ~ depth.last_id
	dt_args := args ~ depth.last_args

	bump_arr_cap(&depth.events, size_of(EventMax))
	pack_begin_event(depth.events[depth.event_cursor:], has_addr, u64(dt_ts), dt_id, dt_args)

	depth.last_ts   = ts
	depth.last_id   = id
	depth.last_args = args

	depth.accum_selftime = 0
}

update_event :: proc(depth: ^Depth, end_ts: i64) -> i64 {
	i := depth.event_cursor
	type_bytes := pull_uval(depth.events[i:], size_of(u16))

	has_addr   := bool((0b1000_0000_0000_0000 & type_bytes) >> 15)
	ts_dt_sz   := u64((0b0001_1000_0000_0000 & type_bytes) >> 11)
	id_dt_sz   := u64((0b0000_0110_0000_0000 & type_bytes) >>  9)
	args_dt_sz := u64((0b0000_0001_1000_0000 & type_bytes) >>  7)

	duration  := end_ts    - depth.last_ts
	dur_dt    := u64(duration  ~ depth.last_duration)
	self_time := duration  - depth.accum_selftime
	self_dt   := u64(self_time ~ depth.last_selftime)

	dur_dt_size  := delta_to_size(dur_dt)
	self_dt_size := delta_to_size(self_dt)
	has_self_time := self_time == 0

	new_type_bytes : u16 = (
		(u16(has_addr) << 15) | (1 << 14) | (u16(has_self_time) << 13) | 
		(u16(ts_dt_sz   << 11)) | 
		(u16(id_dt_sz   <<  9)) | 
		(u16(args_dt_sz <<  7)) |
		size_to_bits(dur_dt_size)  <<  5 |
		size_to_bits(self_dt_size) <<  3
	)

	dt_size   := 1 << ts_dt_sz
	id_size   := 1 << id_dt_sz
	args_size := 1 << args_dt_sz
	mem.copy(raw_data(depth.events[i:]), &new_type_bytes,  size_of(u16)); i += size_of(u16)
	i += i64(dt_size + id_size + args_size)

	mem.copy(raw_data(depth.events[i:]), &dur_dt,  dur_dt_size); i += i64(dur_dt_size)
	if has_self_time {
		mem.copy(raw_data(depth.events[i:]), &self_dt, self_dt_size); i += i64(self_dt_size)
	}

	depth.last_duration = duration
	depth.last_selftime = self_time
	depth.event_cursor  = i
	return duration
}
