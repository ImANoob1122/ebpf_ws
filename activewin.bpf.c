// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "activewin.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Uprobe on XSetInputFocus
// Function signature: int XSetInputFocus(Display *display, Window focus, int revert_to, Time time)
// Arguments: PT_REGS_PARM1 = display*, PT_REGS_PARM2 = Window (focus), PT_REGS_PARM3 = revert_to, PT_REGS_PARM4 = time
SEC("uprobe")
int BPF_KPROBE(handle_set_input_focus, void *display, unsigned long window_id)
{
	struct window_event *e;
	struct task_struct *task;
	u64 pid_tgid;

	// Reserve space in ring buffer
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	// Get timestamp
	e->timestamp_ns = bpf_ktime_get_ns();

	// Get PID/PPID
	pid_tgid = bpf_get_current_pid_tgid();
	e->pid = pid_tgid >> 32;

	task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

	// Get process name
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// Get Window ID from function argument (second parameter)
	e->window_id = window_id;

	// Initialize title (will be filled by user-space)
	e->title[0] = '\0';

	// Submit event
	bpf_ringbuf_submit(e, 0);
	return 0;
}
