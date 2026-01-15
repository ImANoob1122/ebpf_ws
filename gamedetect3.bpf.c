
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "gamedetect3.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * i915_request_add トレースポイントのデータ構造
 */
struct trace_i915_request_add_ctx {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	__u32 dev;
	char __pad[4];
	__u64 ctx;
	__u16 class;
	__u16 instance;
	__u32 seqno;
	__u32 tail;
};

/*
 * i915_gem_object_create トレースポイントのデータ構造
 */
struct trace_i915_gem_object_create_ctx {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	void *obj;
	__u64 size;
};

/* PIDごとのGPU統計（ユーザースペースから読み取る） */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PIDS);
	__type(key, int);
	__type(value, struct gpu_stats);
} pid_stats SEC(".maps");

SEC("tp/i915/i915_request_add")
int handle_request_add(struct trace_i915_request_add_ctx *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	struct gpu_stats *stats;
	struct gpu_stats new_stats = {};

	stats = bpf_map_lookup_elem(&pid_stats, &pid);
	if (!stats) {
		bpf_map_update_elem(&pid_stats, &pid, &new_stats, BPF_ANY);
		stats = bpf_map_lookup_elem(&pid_stats, &pid);
		if (!stats)
			return 0;
	}

	__sync_fetch_and_add(&stats->request_count, 1);
	return 0;
}

SEC("tp/i915/i915_gem_object_create")
int handle_gem_create(struct trace_i915_gem_object_create_ctx *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	struct gpu_stats *stats;
	struct gpu_stats new_stats = {};
	__u64 size = 0;

	stats = bpf_map_lookup_elem(&pid_stats, &pid);
	if (!stats) {
		bpf_map_update_elem(&pid_stats, &pid, &new_stats, BPF_ANY);
		stats = bpf_map_lookup_elem(&pid_stats, &pid);
		if (!stats)
			return 0;
	}

	bpf_probe_read_kernel(&size, sizeof(size), &ctx->size);

	__sync_fetch_and_add(&stats->gem_create_count, 1);
	__sync_fetch_and_add(&stats->gem_create_bytes, size);
	return 0;
}
