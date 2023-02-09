package main

import "core:thread"
import "core:sync"
import "core:fmt"

TaskProc :: proc(pool: ^Pool, data: rawptr)
Pool_Task :: struct {
	do_work: TaskProc,
	args: rawptr,
}

Pool_Thread :: struct {
	thread: ^thread.Thread,
	idx: int,

	queue: []Pool_Task,
	head_and_tail: u64,

	pool: ^Pool,
}

Pool :: struct {
	threads: []Pool_Thread,
	running: bool,

	tasks_available: sync.Futex,
	tasks_left: sync.Futex,
}

@(thread_local)
current_thread_idx: int

wait_until_success :: proc(f: ^sync.Futex, expected: u32) {
	for {
		sync.futex_wait(f, expected)
		v := sync.atomic_load(f)
		if u32(v) != expected {
			break
		}
	}
}

pool_thread_init :: proc(pool: ^Pool, thrd: ^Pool_Thread, idx: int) {
	max_work := 1 << 14 // must be a power of 2

	thrd^ = Pool_Thread{
		queue = make([]Pool_Task, max_work),
		pool = pool,
		idx = idx,
	}
}

pool_queue_push :: proc(thrd: ^Pool_Thread, task: Pool_Task) -> bool {
	capture : u64 = 0
	new_capture : u64 = 0

	for {
		capture = sync.atomic_load(&thrd.head_and_tail)

		mask := u64(len(thrd.queue)) - 1
		head := (capture >> 32) & mask
		tail := u64(u32(capture)) & mask

		new_head := (head + 1) & mask
		if new_head == tail {
			// Queue is full!
			return false
		}

		// We push into the queue here to avoid a potential race condition where we
		// no longer own the slot by the time we're assigning to it
		thrd.queue[head] = task

		new_capture = (new_head << 32) | tail
		_, ok := sync.atomic_compare_exchange_strong(&thrd.head_and_tail, capture, new_capture)
		if ok {
			break
		}
	}

	sync.atomic_add(&thrd.pool.tasks_left, 1)
	sync.atomic_add(&thrd.pool.tasks_available, 1)
	sync.futex_broadcast(&thrd.pool.tasks_available)
	return true
}

pool_queue_pop :: proc(thrd: ^Pool_Thread) -> (Pool_Task, bool) {
	capture : u64 = 0
	new_capture : u64 = 0

	ret_task := Pool_Task{}

	for {
		capture = sync.atomic_load(&thrd.head_and_tail)

		mask := u64(len(thrd.queue)) - 1
		head := (capture >> 32) & mask
		tail := u64(u32(capture)) & mask

		new_tail := (tail + 1) & mask
		if tail == head {
			// Queue is empty!
			return ret_task, false
		}

		// Copy the task before we bump the tail to avoid the same race condition mentioned above
		ret_task = thrd.queue[tail]

		new_capture = (head << 32) | new_tail
		_, ok := sync.atomic_compare_exchange_strong(&thrd.head_and_tail, capture, new_capture)
		if ok {
			break
		}
	}

	return ret_task, true
}

pool_worker :: proc(ptr: rawptr) {
	current_thread := cast(^Pool_Thread)ptr
	current_thread_idx = current_thread.idx
	pool := current_thread.pool

	work_start: for sync.atomic_load(&pool.running) {

		finished_tasks := 0
		for {
			task, ok := pool_queue_pop(current_thread)
			if !ok {
				break
			}

			task.do_work(pool, task.args)
			sync.atomic_sub(&pool.tasks_left, 1)

			finished_tasks += 1
		}
		if finished_tasks > 0 && sync.atomic_load(&pool.tasks_left) == 0 {
			sync.futex_signal(&pool.tasks_left)
		}

		remaining_tasks := sync.atomic_load(&pool.tasks_left)
		if remaining_tasks > 0 {
			idx := current_thread.idx
			for i := 0; i < len(pool.threads); i += 1 {
				if sync.atomic_load(&pool.tasks_left) == 0 {
					break
				}

				idx = (idx + 1) % len(pool.threads)
				thrd := &pool.threads[idx]

				task, ok := pool_queue_pop(thrd)
				if !ok {
					continue
				}

				task.do_work(pool, task.args)
				sync.atomic_sub(&pool.tasks_left, 1)

				if sync.atomic_load(&pool.tasks_left) == 0 {
					sync.futex_signal(&pool.tasks_left)
				}

				continue work_start
			}
		}

		state := sync.atomic_load(&pool.tasks_available)
		wait_until_success(&pool.tasks_available, u32(state))
	}
}

pool_add_task :: proc(pool: ^Pool, task: Pool_Task) {
	current_thread := &pool.threads[current_thread_idx]
	pool_queue_push(current_thread, task)
}

pool_wait :: proc(pool: ^Pool) {
	current_thread := &pool.threads[current_thread_idx]

	for sync.atomic_load(&pool.tasks_left) > 0 {
		for {
			task, ok := pool_queue_pop(current_thread)
			if !ok {
				break
			}

			task.do_work(pool, task.args)
			sync.atomic_sub(&pool.tasks_left, 1)
		}

		remaining_tasks := sync.atomic_load(&pool.tasks_left)
		if remaining_tasks == 0 {
			break
		}

		wait_until_success(&pool.tasks_left, u32(remaining_tasks))
	}
}

pool_init :: proc(pool: ^Pool, child_thread_count: int) {
	thread_count := child_thread_count + 1
	pool.threads = make([]Pool_Thread, thread_count)
	pool.running = true

	pool_thread_init(pool, &pool.threads[0], 0)
	current_thread_idx = 0

	fmt.printf("Spinning up %d threads!\n", thread_count)
	for i := 1; i < thread_count; i += 1 {
		pool_thread_init(pool, &pool.threads[i], i)
		pool.threads[i].thread = thread.create_and_start_with_data(&pool.threads[i], pool_worker)
	}
}
