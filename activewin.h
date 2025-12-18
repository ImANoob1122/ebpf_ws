/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __ACTIVEWIN_H
#define __ACTIVEWIN_H

#define TASK_COMM_LEN 16
#define WINDOW_TITLE_LEN 128

struct window_event {
	unsigned long long timestamp_ns;
	unsigned int pid;
	unsigned int ppid;
	unsigned long long window_id;
	char comm[TASK_COMM_LEN];
	char title[WINDOW_TITLE_LEN];  // Filled by user-space
};

#endif /* __ACTIVEWIN_H */
