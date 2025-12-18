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

// Uprobe on XCB xcb_set_input_focus (used by KWin and modern X11 apps)
// Function signature: xcb_void_cookie_t xcb_set_input_focus(xcb_connection_t *c, uint8_t revert_to, xcb_window_t focus, xcb_timestamp_t time)
// Window ID is the THIRD parameter
SEC("uprobe")
int BPF_KPROBE(handle_xcb_set_input_focus, void *connection, unsigned char revert_to, unsigned int window_id)
{
	struct window_event *e;
	struct task_struct *task;
	u64 pid_tgid;

	// Debug: print all calls
	bpf_printk("xcb_set_input_focus called: window_id=0x%x, revert_to=%d, pid=%d\n",
	           window_id, revert_to, bpf_get_current_pid_tgid() >> 32);

	// Filter out window_id == 0 or 1 (root window / PointerRoot)
	if (window_id == 0 || window_id == 1)
		return 0;

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

	// Get Window ID from function argument (THIRD parameter for XCB)
	e->window_id = window_id;

	// Initialize title (will be filled by user-space)
	e->title[0] = '\0';

	// Submit event
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Also keep Xlib hook for compatibility with older apps
// Function signature: int XSetInputFocus(Display *display, Window focus, int revert_to, Time time)
SEC("uprobe")
int BPF_KPROBE(handle_xlib_set_input_focus, void *display, unsigned long window_id)
{
	struct window_event *e;
	struct task_struct *task;
	u64 pid_tgid;

	// Filter out window_id == 0 or 1 (root window / PointerRoot)
	if (window_id == 0 || window_id == 1)
		return 0;

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

	// Get Window ID from function argument (second parameter for Xlib)
	e->window_id = window_id;

	// Initialize title (will be filled by user-space)
	e->title[0] = '\0';

	// Submit event
	bpf_ringbuf_submit(e, 0);
	return 0;
}
