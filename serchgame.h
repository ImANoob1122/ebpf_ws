/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SERCHGAME_H
#define __SERCHGAME_H

#define TASK_COMM_LEN 16
#define PATH_MAX_LEN 256

enum event_type {
	EVENT_GPU_OPEN = 1,
	EVENT_GPU_IOCTL = 2,
	EVENT_PROCESS_EXEC = 3,
};

struct event {
	int pid;
	int ppid;
	unsigned int uid;
	enum event_type type;
	char comm[TASK_COMM_LEN];
	char filename[PATH_MAX_LEN];
	unsigned int ioctl_cmd;
	int exit_code;
};

#endif /* __SERCHGAME_H */
