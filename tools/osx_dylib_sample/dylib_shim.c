#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>

typedef char name_t[128];
extern kern_return_t bootstrap_look_up(mach_port_t bp, name_t service_name, mach_port_t *sp);

__attribute__((constructor))
static void load_same(int argc, const char **argv) {
	mach_port_t my_task = mach_task_self();

	mach_port_t send_port;
	kern_return_t err = mach_port_allocate(my_task, MACH_PORT_RIGHT_RECEIVE, &send_port);
	if (err != 0) {
		printf("Failed to init sampling!\n");
		exit(1);
	}

	mach_port_t right;
	mach_port_t acquired_right;
	err = mach_port_extract_right(my_task, send_port, MACH_MSG_TYPE_MAKE_SEND, &right, &acquired_right);
	if (err != 0) {
		printf("Failed to init sampling!\n");
		exit(1);
	}

	mach_port_t bootstrap_port;
	err = task_get_special_port(my_task, TASK_BOOTSTRAP_PORT, &bootstrap_port);
	if (err != 0) {
		printf("Failed to init sampling!\n");
		exit(1);
	}

	mach_port_t parent_port;
	err = bootstrap_look_up(bootstrap_port, "SAME_BOOTSTRAP", &parent_port);
	if (err != 0) {
		printf("Failed to init sampling!\n");
		exit(1);
	}

	struct {
		mach_msg_header_t             header;
		mach_msg_body_t                 body;
		mach_msg_port_descriptor_t task_port;
	} send_msg;

	send_msg.header.msgh_remote_port = parent_port;
	send_msg.header.msgh_local_port = MACH_PORT_NULL;
	send_msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
	send_msg.header.msgh_size = sizeof(send_msg);

	send_msg.body.msgh_descriptor_count = 1;
	send_msg.task_port.name = my_task;
	send_msg.task_port.disposition = MACH_MSG_TYPE_COPY_SEND;
	send_msg.task_port.type = MACH_MSG_PORT_DESCRIPTOR;

	err = mach_msg_send(&send_msg.header);
	if (err != 0) {
		printf("Failed to init sampling!\n");
		exit(1);
	}

	send_msg.task_port.name = send_port;
	err = mach_msg_send(&send_msg.header);
	if (err != 0) {
		printf("Failed to init sampling!\n");
		exit(1);
	}

	struct {
		mach_msg_header_t             header;
		mach_msg_body_t                 body;
		mach_msg_port_descriptor_t task_port;
		mach_msg_trailer_t           trailer;
	} recv_msg;
	err = mach_msg(&recv_msg.header, MACH_RCV_MSG, 0, sizeof(recv_msg), send_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	if (err != 0) {
		printf("Failed to init sampling!\n");
		exit(1);
	}
}
