/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __GAMEDETECT_H
#define __GAMEDETECT_H

#define TASK_COMM_LEN 16
#define PATH_MAX_LEN  256

enum game_event_type {
	GAME_EVENT_START = 1, /* Game process started */
	GAME_EVENT_EXIT = 2, /* Game process exited */
};

struct game_event {
	int pid;
	int ppid;
	unsigned int uid;
	enum game_event_type type;
	char comm[TASK_COMM_LEN];
	char filename[PATH_MAX_LEN];
	int exit_code;
};

#endif /* __GAMEDETECT_H */
