#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include "dynarray.h"

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))

#define AUTO_MAGIC 0xABADF00D

typedef enum {
	Invalid = 0,
	Begin   = 1,
	End     = 2,
} Auto_Type;

#pragma pack(1)
typedef struct {
	uint64_t magic;
	uint64_t version;
	uint64_t ts_unit;
	uint64_t base_addr;
	uint16_t program_path_len;
} Auto_Header;

typedef struct {
	uint8_t type;
	uint64_t time;
	uint8_t name_len;
	uint8_t args_len;
} Auto_Begin_Max;

typedef struct {
	uint8_t type;
	uint64_t time;
} Auto_End_Max;

typedef struct {
	uint32_t size;
	uint32_t tid;
	uint64_t first_ts;
	uint32_t max_depth;
} Buffer_Header;
#pragma pack()

typedef struct {
	uint8_t *buffer;
	uint64_t buffer_len;

	uint64_t buffer_pos;
	uint64_t file_pos;

	int fd;
	uint64_t file_size;
} StreamContext;

typedef struct {
	uint8_t *buffer;
	uint64_t len;

	uint64_t idx;
} ParseContext;

typedef struct {
	DynArray(uint64_t) arr;
	int64_t len;
} Stack;

typedef struct {
	uint64_t timestamp;
	int64_t duration;
	uint64_t self_time;

	uint64_t addr;
	uint64_t caller;
} Event;

typedef struct {
	DynArray(Event) events;
} Depth;

typedef struct {
	uint64_t min_time;
	uint64_t max_time;
	int64_t current_depth;

	uint32_t id;

	DynArray(Depth) depths;
	Stack bande_q;
} Thread;

static ParseContext parser_init(uint8_t *buffer, uint64_t len) {
	ParseContext ctx;
	ctx.buffer = buffer;
	ctx.len = len;
	ctx.idx = 0;
	return ctx;
}

static void *parser_read(ParseContext *ctx, uint64_t size) {
	if (ctx->idx + size > ctx->len) {
		return NULL;
	}

	void *new_data = ctx->buffer + ctx->idx;
	ctx->idx += size;
	return new_data;
}

static uint64_t parser_read_uval(ParseContext *ctx, uint64_t size) {
	uint64_t ret;
	void *val = parser_read(ctx, size);

	switch (size) {
		case 8: {
			memcpy(&ret, val, 8);
		} break;
		case 4: {
			memcpy(&ret, val, 4);
		} break;
		case 2: {
			memcpy(&ret, val, 2);
		} break;
		case 1: {
			memcpy(&ret, val, 1);
		} break;
		default: {
			printf("Invalid size: %llx\n", size);
			exit(1);
		}
	}

	return ret;
}

uint64_t page_size = 0;
static void stream_init(StreamContext *ctx, char *filepath) {
	page_size = sysconf(_SC_PAGE_SIZE);

	uint8_t *buffer;
	int buffer_len = 4 * page_size * 1024;

	posix_memalign((void **)&buffer, page_size, buffer_len);

	int fd = open(filepath, O_RDONLY);
	if (fd < 0) {
		printf("Failed to open file: %s\n", filepath);
		exit(1);
	}
	//fcntl(fd, F_NOCACHE, 1);
	fcntl(fd, F_RDAHEAD, 1);

	uint64_t file_size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	ctx->fd = fd;
	ctx->file_size = file_size;

	ctx->buffer = buffer;
	ctx->buffer_len = buffer_len;
	ctx->buffer_pos = 0;
	ctx->file_pos = 0;

	pread(ctx->fd, ctx->buffer, buffer_len, 0);
}

static void *stream_skim(StreamContext *ctx, uint64_t size, uint64_t offset) {
	if (offset >= ctx->file_size) {
		return NULL;
	}

	pread(ctx->fd, ctx->buffer, size, offset);
	void *new_data = ctx->buffer;
	return new_data;
}

int read_count = 0;
static void *stream_read(StreamContext *ctx, uint64_t size) {
	if (size > ctx->buffer_len) {
		printf("Trying to read too much: %llu bytes\n", size);
		exit(1);
	}

	if (ctx->file_pos == ctx->file_size) {
		return NULL;
	}

	if (ctx->buffer_pos + size > ctx->buffer_len) {
		//printf("%d | pos: %llu, size: %llu\n", read_count++, ctx->file_pos, ctx->buffer_len);
		pread(ctx->fd, ctx->buffer, ctx->buffer_len, ctx->file_pos);
		ctx->buffer_pos = 0;
	}

	void *new_data = ctx->buffer + ctx->buffer_pos;

	ctx->buffer_pos += size;
	ctx->file_pos += size;
	
	return new_data;
}


static void stream_seek(StreamContext *ctx, uint64_t offset) {
	ctx->file_pos = offset;
	ctx->buffer_pos = 0;
	pread(ctx->fd, ctx->buffer, ctx->buffer_len, ctx->file_pos);
}

static void stack_push_back(Stack *s, uint64_t v) {
	if (s->len >= s->arr.capacity) {
		dyn_resize(&s->arr, s->len * 2);
	}

	s->arr.arr[s->len] = v;
	s->len += 1;
}
static uint64_t stack_pop_back(Stack *s) {
	s->len -= 1;
	return s->arr.arr[s->len];
}

static uint64_t stack_peek_back(Stack *s) {
	return s->arr.arr[s->len - 1];
}

int main(int argc, char **argv) {
	if (argc != 3) {
		printf("Expected stats <in_file> <out_file>\n");
		return 1;
	}

	char *in_file = argv[1];
	char *out_file = argv[2];
	StreamContext ctx;
	stream_init(&ctx, in_file);

	Auto_Header *hdr = stream_read(&ctx, sizeof(Auto_Header));
	if (hdr->magic != AUTO_MAGIC) {
		printf("Invalid spall-auto trace!\n");
		return 1;
	}
	if (hdr->version != 3) {
		printf("Invalid trace version!\n");
		return 1;
	}

	DynArray(Thread) threads;
	dyn_init(&threads, 8);

	uint64_t event_count = 0;

	char *program_path = stream_read(&ctx, hdr->program_path_len);
	uint64_t total_min_time = ~0;
	uint64_t total_max_time = 0;

	for (;;) {
		Buffer_Header *bhdr = stream_read(&ctx, sizeof(Buffer_Header));
		if (bhdr == NULL) {
			break;
		}

		Thread *thread = NULL;
		for (int i = 0; i < threads.size; i++) {
			Thread *t = &threads.arr[i];
			if (t->id == bhdr->tid) {
				thread = t;
			}
		}
		if (thread == NULL) {
			//printf("New thread: 0x%08x\n", bhdr->tid);
			Thread new_t;
			new_t.id = bhdr->tid;
			new_t.current_depth = 0;
			new_t.min_time = ~0;
			new_t.max_time = 0;
			dyn_init(&new_t.depths, 8);

			new_t.bande_q.len = 0;
			dyn_init(&new_t.bande_q.arr, 16);

			dyn_append(&threads, new_t);
			thread = &threads.arr[threads.size - 1];
		}

		while (thread->depths.size <= bhdr->max_depth) {
			Depth d;
			dyn_init(&d.events, 8);
			dyn_append(&thread->depths, d);
		}

		uint64_t current_time   = bhdr->first_ts;
		uint64_t current_addr   = 0;
		uint64_t current_caller = 0;
		uint64_t ev_end = ctx.file_pos + bhdr->size;

		uint64_t chunk_size = bhdr->size;
		uint8_t *chunk_buffer = stream_read(&ctx, chunk_size);
		ParseContext p_ctx = parser_init(chunk_buffer, chunk_size);
		while (p_ctx.idx < p_ctx.len) {
			uint8_t *type_ptr = parser_read(&p_ctx, sizeof(uint8_t));
			uint8_t type_byte = *type_ptr;
			uint8_t tag = type_byte >> 6;

			switch (tag) {
				case 0: { // MicroBegin
					uint8_t dt_size     = 1 << ((0x30 & type_byte) >> 4);
					uint8_t addr_size   = 1 << ((0x0C & type_byte) >> 2);
					uint8_t caller_size = 1 << (0x03 & type_byte);
					uint8_t ev_size = 1 + dt_size + addr_size + caller_size;

					uint64_t dt       = parser_read_uval(&p_ctx, dt_size);
					uint64_t d_addr   = parser_read_uval(&p_ctx, addr_size);
					uint64_t d_caller = parser_read_uval(&p_ctx, caller_size);

					current_time   = current_time   + dt;
					current_addr   = current_addr   ^ d_addr;
					current_caller = current_caller ^ d_caller;

					Event ev;
					ev.timestamp = current_time;
					ev.duration  = -1;
					ev.addr   = current_addr;
					ev.caller = current_caller;
					ev.self_time = 0;
					//printf("Event{timestamp: %lld, duration: %lld, addr: 0x%08llx, caller: 0x%08llx}\n", ev.timestamp, ev.duration, ev.addr, ev.caller);

					thread->min_time = min(thread->min_time, current_time);
					thread->max_time = current_time;

					total_min_time = min(total_min_time, current_time);
					total_max_time = max(total_max_time, current_time);

					Depth *d = &thread->depths.arr[thread->current_depth];
					thread->current_depth += 1;
					dyn_append(&d->events, ev);

					uint64_t ev_idx = d->events.size - 1;
					stack_push_back(&thread->bande_q, ev_idx);
					event_count += 1;

				} break;
				case 1: { // MicroEnd
					uint8_t dt_size = 1 << ((0x30 & type_byte) >> 4);
					uint8_t ev_size = 1 + dt_size;

					uint64_t dt  = parser_read_uval(&p_ctx, dt_size);
					current_time = current_time   + dt;

					if (thread->bande_q.len > 0) {
						uint64_t jev_idx = stack_pop_back(&thread->bande_q);
						thread->current_depth -= 1;

						Depth *d = &thread->depths.arr[thread->current_depth];
						Event *jev = &d->events.arr[jev_idx];
						jev->duration = current_time - jev->timestamp;
						jev->self_time = jev->duration - jev->self_time;

						thread->max_time = max(thread->max_time, jev->timestamp + jev->duration);
						total_max_time = max(total_max_time, jev->timestamp + jev->duration);

						if (thread->bande_q.len > 0) {
							Depth *parent = &thread->depths.arr[thread->current_depth - 1];
							uint64_t pev_idx = stack_peek_back(&thread->bande_q);
							Event *pev = &parent->events.arr[pev_idx];
							pev->self_time += jev->duration;
						}
					}
				} break;
				default: {
					printf("Unhandled event: %x\n", tag);
					exit(1);
				}
			}
		}
	}

	// Cleanup unfinished events
	for (int i = 0; i < threads.size; i++) {
		Thread *t = &threads.arr[i];
		assert(t->current_depth == t->bande_q.len);

		while (t->current_depth > 0) {
			uint64_t jev_idx = stack_pop_back(&t->bande_q);
			t->current_depth -= 1;
			uint64_t ev_depth = t->current_depth;

			Depth *depth = &t->depths.arr[ev_depth];
			Event *jev   = &depth->events.arr[jev_idx];

			uint64_t duration = jev->duration;
			if (duration == -1) {
				jev->duration = t->max_time - jev->timestamp;
			}

			jev->self_time = duration - jev->self_time;

			if (t->current_depth > 0) {
				Depth *parent = &t->depths.arr[ev_depth - 1];
				uint64_t pev_idx = stack_peek_back(&t->bande_q);
				Event *pev = &parent->events.arr[pev_idx];
				pev->self_time += duration;
			}
		}
	}

	//printf("Got %llu events\n", event_count);
}
