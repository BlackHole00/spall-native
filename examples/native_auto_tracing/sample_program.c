#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

/*
	This is a single header C library, but we pay a price for that simplicity.

	The user must include the header to forward declare tracing functions wherever they get used, 
	and then again once in their code with a #define (SPALL_AUTO_IMPLEMENTATION) to add function definitions
*/
#include "../../spall_native_auto.h"

static void bar(void) {
    spall_auto_buffer_begin("jam", 3, "", 0);
    spall_auto_buffer_end();
}
static void foo(void) {
	bar();
}
static void wub() {
	printf("Foobar is terrible\n");
}

static void woz1() { }
static void woz2() { }
static void woz3() { }

void *run_work(void *ptr) {
	spall_auto_thread_init((uint32_t)(uint64_t)pthread_self(), SPALL_DEFAULT_BUFFER_SIZE);

    // Run some manual events
	for (int i = 0; i < 100; i++) {
		foo();
	}
 
    // Toggle off auto-instrumenting while running manual events
    spall_auto_set_thread_instrumenting(false);
	for (int i = 0; i < 100; i++) {
		foo();
	}
    spall_auto_set_thread_instrumenting(true);

    // Back to manual eventing
	for (int i = 0; i < 100; i++) {
		foo();
	}

	spall_auto_thread_quit();
	return NULL;
}

int main() {
	spall_auto_init((char *)"profile.spall");

	/*
		Ok, now init thread for main so we can trace from here out
		spall_auto_thread_init takes a TID and a buffer size. Each thread can have its own buffer size,
		if you have programs with slow, long running tasks that should flush regularly, 
		you can shrink their buffers accordingly, or manually flush them.

		Once thread_init runs, everything until the thread_quit is automatically logged to the trace file.
	*/
	int thread_id = 0;
	spall_auto_thread_init(thread_id, SPALL_DEFAULT_BUFFER_SIZE);

	pthread_t thread_1, thread_2;
	pthread_create(&thread_1, NULL, run_work, NULL);
	pthread_create(&thread_2, NULL, run_work, NULL);

	for (int i = 0; i < 1000; i++) {
		foo();
	}

	wub();

	pthread_join(thread_1, NULL);
	pthread_join(thread_2, NULL);

	spall_auto_thread_quit();
	spall_auto_quit();
}

#define SPALL_AUTO_IMPLEMENTATION
#include "../../spall_native_auto.h"
