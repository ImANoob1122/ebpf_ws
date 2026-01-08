// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "serchgame.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

static __always_inline bool is_game_related_process(void)
{
	char comm[TASK_COMM_LEN];

	bpf_get_current_comm(&comm, sizeof(comm));

	// Check for wine, steam, proton, etc.
	if (comm[0] == 'w' && comm[1] == 'i' && comm[2] == 'n' && comm[3] == 'e')
		return true;
	if (comm[0] == 's' && comm[1] == 't' && comm[2] == 'e' && comm[3] == 'a' &&
	    comm[4] == 'm' && comm[5] == 'w' && comm[6] == 'e' && comm[7] == 'b')
		return false;
	if (comm[0] == 's' && comm[1] == 't' && comm[2] == 'e' && comm[3] == 'a' && comm[4] == 'm')
		return true;
	if (comm[0] == 'p' && comm[1] == 'r' && comm[2] == 'o' && comm[3] == 't' &&
	    comm[4] == 'o' && comm[5] == 'n')
		return true;

	return false;
}

static __always_inline bool is_gpu_device(const char *filename)
{
	char prefix[9];

	// Read first 8 chars to check for "/dev/dri"
	bpf_probe_read_user_str(&prefix, sizeof(prefix), filename);

	// Check if it starts with "/dev/dri"
	if (prefix[0] == '/' && prefix[1] == 'd' && prefix[2] == 'e' && prefix[3] == 'v' &&
	    prefix[4] == '/' && prefix[5] == 'd' && prefix[6] == 'r' && prefix[7] == 'i') {
		return true;
	}

	return false;
}

static __always_inline void fill_common_fields(struct event *e)
{
	struct task_struct *task;
	u64 uid_gid;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	uid_gid = bpf_get_current_uid_gid();
	e->uid = uid_gid;

	task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename = (const char *)ctx->args[1];
	struct event *e;

	// Filter: only track GPU device opens from game-related processes
	if (!is_game_related_process())
		return 0;

	if (!is_gpu_device(filename))
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_GPU_OPEN;
	fill_common_fields(e);
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);
	e->ioctl_cmd = 0;
	e->exit_code = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int handle_ioctl(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	unsigned int cmd = (unsigned int)ctx->args[1];

	// Filter: only track ioctls from game-related processes
	if (!is_game_related_process())
		return 0;

	// Filter for DRM ioctls (major number 0x64 'd')
	// DRM ioctl commands are in range 0x6400 - 0x64FF
	if ((cmd & 0xFF00) != 0x6400)
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_GPU_IOCTL;
	fill_common_fields(e);
	e->ioctl_cmd = cmd;
	e->filename[0] = '\0';
	e->exit_code = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	struct event *e;
	unsigned fname_off;

	// Filter for game-related process execution
	if (!is_game_related_process())
		return 0;

	task = (struct task_struct *)bpf_get_current_task();

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_PROCESS_EXEC;
	e->pid = BPF_CORE_READ(task, tgid);
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

	u64 uid_gid = bpf_get_current_uid_gid();
	e->uid = uid_gid;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// Get filename from tracepoint context using __data_loc_filename
	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	e->ioctl_cmd = 0;
	e->exit_code = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_poll")
int handle_poll(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	int nfds = (int)ctx->args[1];

	// Filter: only track poll from game-related processes
	if (!is_game_related_process())
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_POLL;
	fill_common_fields(e);
	e->nfds = nfds;
	e->filename[0] = '\0';
	e->ioctl_cmd = 0;
	e->exit_code = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ppoll")
int handle_ppoll(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	int nfds = (int)ctx->args[1];

	// Filter: only track ppoll from game-related processes
	if (!is_game_related_process())
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_POLL;
	fill_common_fields(e);
	e->nfds = nfds;
	e->filename[0] = '\0';
	e->ioctl_cmd = 0;
	e->exit_code = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_wait")
int handle_epoll_wait(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	int maxevents = (int)ctx->args[2];

	// Filter: only track epoll_wait from game-related processes
	if (!is_game_related_process())
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_EPOLL_WAIT;
	fill_common_fields(e);
	e->nfds = maxevents;
	e->filename[0] = '\0';
	e->ioctl_cmd = 0;
	e->exit_code = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_pwait")
int handle_epoll_pwait(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	int maxevents = (int)ctx->args[2];

	// Filter: only track epoll_pwait from game-related processes
	if (!is_game_related_process())
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_EPOLL_WAIT;
	fill_common_fields(e);
	e->nfds = maxevents;
	e->filename[0] = '\0';
	e->ioctl_cmd = 0;
	e->exit_code = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
