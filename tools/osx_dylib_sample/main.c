#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>

#include <spawn.h>
#include <sys/wait.h>
#include <mach/mach.h>

typedef char name_t[128];
extern kern_return_t bootstrap_register2(mach_port_t bp, name_t service_name, mach_port_t sp, uint64_t flags);
extern kern_return_t mach_vm_remap(vm_map_t target_task, mach_vm_address_t *target_address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src_task, mach_vm_address_t src_address, boolean_t copy, vm_prot_t *cur_protection, vm_prot_t *max_protection, vm_inherit_t inheritance);

char **setup_envs(char *path, char **envp) {
	int env_len = 1;
	char **environ = envp;
	while (*environ) {
		env_len++;
		environ++;
	}

	char **envs = calloc(sizeof(char *), env_len + 1);
	int path_buffer_size = PATH_MAX + 1025;
	char *path_buffer = calloc(path_buffer_size, 1);
	snprintf(path_buffer, path_buffer_size, "DYLD_INSERT_LIBRARIES=%s/%s", path, "same.dylib");

	for (int i = 0; i < env_len; i++) {
		envs[i] = envp[i];
	}
	envs[env_len - 1] = path_buffer;
	return envs;
}

void sample_task(mach_port_t my_task, mach_port_t child_task) {
	task_suspend(child_task);

	thread_act_array_t thread_list;
	mach_msg_type_number_t thread_count;
	kern_return_t err = task_threads(child_task, &thread_list, &thread_count);
	if (err != 0) {
		return;
	}

	uint64_t saved_sp;
	printf("Sampling all threads\n");
	for (int i = 0; i < thread_count; i++) {
		thread_act_t thread = thread_list[i];

		x86_thread_state64_t state;
		mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;
		err = thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)&state, &state_count);
		if (err != 0) {
			return;
		}

		printf("RIP: 0x%08llx\n", state.__rip);
		printf("RSP: 0x%08llx\n", state.__rsp);
		printf("RAX: 0x%08llx\n", state.__rax);
		printf("RBX: 0x%08llx\n", state.__rbx);
		printf("RCX: 0x%08llx\n", state.__rcx);

		saved_sp = state.__rsp;

	}

	uint64_t stack_page = mach_vm_trunc_page(saved_sp);
	uint8_t *page = NULL;
	vm_prot_t cur_prot = VM_PROT_NONE;
	vm_prot_t max_prot = VM_PROT_NONE;
	err = mach_vm_remap(my_task, (uint64_t *)&page, PAGE_SIZE, 0, 1, child_task, saved_sp, 0, &cur_prot, &max_prot, VM_INHERIT_SHARE);

	uint64_t val = ((uint64_t *)page)[0];
	printf("top of stack page: 0x%08llx\n", val);

	task_resume(child_task);
}

int main(int argc, char **argv, char **envp) {
	if (argc < 2) {
		printf("Expected same <program>\n");
		return 1;
	}

	char my_path[PATH_MAX+1];
	if (getcwd(my_path, sizeof(my_path)) == NULL) {
		printf("Failed to get path of same\n");
		return 1;
	}
	char *program_name = argv[1];
	char **my_argv = argv + 1;

	char **envs = setup_envs(my_path, envp);

	mach_port_t recv_port;
	mach_port_t my_task = mach_task_self();
	kern_return_t err = mach_port_allocate(my_task, MACH_PORT_RIGHT_RECEIVE, &recv_port);
	if (err != 0) {
		printf("oops?\n");
		exit(1);
	}

	mach_port_t bootstrap_port;
	err = task_get_special_port(my_task, TASK_BOOTSTRAP_PORT, &bootstrap_port);
	if (err != 0) {
		printf("oops 2?\n");
		exit(1);
	}

	mach_port_t right;
	mach_port_t acquired_right;
	err = mach_port_extract_right(my_task, recv_port, MACH_MSG_TYPE_MAKE_SEND, &right, &acquired_right);
	if (err != 0) {
		printf("oops 3?\n");
		exit(1);
	}

	err = bootstrap_register2(bootstrap_port, "SAME_BOOTSTRAP", right, 0);
	if (err != 0) {
		printf("oops 4?\n");
		exit(1);
	}

	pid_t child_pid;
	int status = posix_spawn(&child_pid, program_name, NULL, NULL, my_argv, envs);
	if (status == 0) {
		printf("Child pid: %i\n", child_pid);
		struct {
			mach_msg_header_t             header;
			mach_msg_body_t                 body;
			mach_msg_port_descriptor_t task_port;
			mach_msg_trailer_t           trailer;
		} recv_msg;

		uint32_t initial_timeout = 500; // 500ms

		err = mach_msg(&recv_msg.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(recv_msg), recv_port, initial_timeout, MACH_PORT_NULL);
		if (err != 0) {
			printf("No response from child, we may not be able to hook this!\n");
			exit(1);
		}
		mach_port_t child_task = recv_msg.task_port.name;

		err = mach_msg(&recv_msg.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(recv_msg), recv_port, initial_timeout, MACH_PORT_NULL);
		if (err != 0) {
			printf("No response from child, we may not be able to hook this!\n");
			exit(1);
		}
		mach_port_t child_port = recv_msg.task_port.name;

		sample_task(my_task, child_task);

		struct {
			mach_msg_header_t             header;
			mach_msg_body_t                 body;
			mach_msg_port_descriptor_t task_port;
		} send_msg;

		send_msg.header.msgh_remote_port = child_port;
		send_msg.header.msgh_local_port = MACH_PORT_NULL;
		send_msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
		send_msg.header.msgh_size = sizeof(send_msg);

		send_msg.body.msgh_descriptor_count = 1;
		send_msg.task_port.name = my_task;
		send_msg.task_port.disposition = MACH_MSG_TYPE_COPY_SEND;
		send_msg.task_port.type = MACH_MSG_PORT_DESCRIPTOR;

		err = mach_msg_send(&send_msg.header);
		if (err != 0) {
			printf("Oops 6\n");
			exit(1);
		}

		do {
			if (waitpid(child_pid, &status, 0) != -1) {
				printf("Child status: %d\n", WEXITSTATUS(status));
			} else {
				perror("waitpid");
				return 1;
			}
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));
	} else {
		printf("posix_spawn: %s\n", strerror(status));
	}

	return 0;
}
