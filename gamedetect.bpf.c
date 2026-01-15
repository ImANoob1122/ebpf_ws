// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "gamedetect.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Hash map to track game-related PIDs */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, int);
	__type(value, int);
} game_pids SEC(".maps");

static __always_inline bool is_game_related_comm(const char *comm)
{
	// Check for wine, steam, proton, etc.
	// wine*
	if (comm[0] == 'w' && comm[1] == 'i' && comm[2] == 'n' && comm[3] == 'e')
		return true;

	// steamwebhelper - filter out (not a game)
	if (comm[0] == 's' && comm[1] == 't' && comm[2] == 'e' && comm[3] == 'a' &&
	    comm[4] == 'm' && comm[5] == 'w' && comm[6] == 'e' && comm[7] == 'b')
		return false;

	// steam*
	if (comm[0] == 's' && comm[1] == 't' && comm[2] == 'e' && comm[3] == 'a' && comm[4] == 'm')
		return true;

	// proton*
	if (comm[0] == 'p' && comm[1] == 'r' && comm[2] == 'o' && comm[3] == 't' &&
	    comm[4] == 'o' && comm[5] == 'n')
		return true;

	// gamescope*
	if (comm[0] == 'g' && comm[1] == 'a' && comm[2] == 'm' && comm[3] == 'e' &&
	    comm[4] == 's' && comm[5] == 'c' && comm[6] == 'o' && comm[7] == 'p' && comm[8] == 'e')
		return true;

	// reaper (Steam game process manager)
	if (comm[0] == 'r' && comm[1] == 'e' && comm[2] == 'a' && comm[3] == 'p' &&
	    comm[4] == 'e' && comm[5] == 'r')
		return true;

	return false;
}

static __always_inline bool check_parent_is_game(void)
{
	struct task_struct *task;
	int ppid;
	int *found;

	task = (struct task_struct *)bpf_get_current_task();
	ppid = BPF_CORE_READ(task, real_parent, tgid);

	found = bpf_map_lookup_elem(&game_pids, &ppid);
	return found != NULL;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	struct game_event *e;
	char comm[TASK_COMM_LEN];
	unsigned fname_off;
	int pid;
	int one = 1;

	bpf_get_current_comm(&comm, sizeof(comm));

	// Check if this is a game-related process or child of one
	bool is_game = is_game_related_comm(comm);
	bool parent_is_game = check_parent_is_game();

	if (!is_game && !parent_is_game)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();
	pid = BPF_CORE_READ(task, tgid);

	// Add this PID to our tracking map
	bpf_map_update_elem(&game_pids, &pid, &one, BPF_ANY);

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = GAME_EVENT_START;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

	u64 uid_gid = bpf_get_current_uid_gid();
	e->uid = uid_gid;

	__builtin_memcpy(e->comm, comm, TASK_COMM_LEN);

	// Get filename from tracepoint context using __data_loc_filename
	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	e->exit_code = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct task_struct *task;
	struct game_event *e;
	int tgid, tid;
	int *found;
	int exit_code;

	task = (struct task_struct *)bpf_get_current_task();
	tgid = BPF_CORE_READ(task, tgid); // Process ID (main thread)
	tid = BPF_CORE_READ(task, pid); // Thread ID

	// Only track main process exits, not thread exits
	// Thread exit: tid != tgid
	if (tid != tgid)
		return 0;

	// Check if this PID was tracked as a game process
	found = bpf_map_lookup_elem(&game_pids, &tgid);
	if (!found)
		return 0;

	// Remove from tracking map
	bpf_map_delete_elem(&game_pids, &tgid);

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = GAME_EVENT_EXIT;
	e->pid = tgid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

	u64 uid_gid = bpf_get_current_uid_gid();
	e->uid = uid_gid;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->filename[0] = '\0';

	exit_code = BPF_CORE_READ(task, exit_code);
	e->exit_code = exit_code >> 8; // Extract actual exit code

	bpf_ringbuf_submit(e, 0);
	return 0;
}
