#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "gamedetect2.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * トレースポイントはdrm_vblank_event
 * メッセージ形式は次を確認: /sys/kernel/debug/tracing/events/drm/drm_vblank_event/format
 */
struct trace_event_raw_drm_vblank_event_ctx {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int crtc;
	unsigned int seq;
	long long time;
	unsigned char high_prec;
};

/* ユーザー空間送信用バッファ */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
} rb SEC(".maps");

/* 垂直同期カウンター */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__type(key, int);
	__type(value, __u64);
} vblank_count SEC(".maps");

/* バッファ */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__type(key, int);
	__type(value, __u64);
} last_sample_ts SEC(".maps");

/*
 * drm_vblank_event をトレースポイントとし、
 * flip頻度によってゲームであると判定する
 */
SEC("tp/drm/drm_vblank_event")
int handle_vblank(struct trace_event_raw_drm_vblank_event_ctx *ctx)
{
	struct vblank_event *e;
	int crtc;
	__u64 *count_ptr, *last_ts_ptr;
	__u64 now, count, elapsed;
	__u64 one = 1;

	crtc = ctx->crtc;
	now = bpf_ktime_get_ns();

	/* フリップカウンター */
	count_ptr = bpf_map_lookup_elem(&vblank_count, &crtc);
	if (count_ptr) {
		count = *count_ptr + 1;
		bpf_map_update_elem(&vblank_count, &crtc, &count, BPF_ANY);
	} else {
		bpf_map_update_elem(&vblank_count, &crtc, &one, BPF_ANY);
		bpf_map_update_elem(&last_sample_ts, &crtc, &now, BPF_ANY);
		return 0;
	}

	/* サンプルウィンドウの経過を確認 */
	last_ts_ptr = bpf_map_lookup_elem(&last_sample_ts, &crtc);
	if (!last_ts_ptr)
		return 0;

	elapsed = now - *last_ts_ptr;
	if (elapsed < SAMPLE_WINDOW_NS)
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->crtc = crtc;
	e->seq = count;
	e->timestamp_ns = now;

	bpf_ringbuf_submit(e, 0);

	/* Reset counters */
	__u64 zero = 0;
	bpf_map_update_elem(&vblank_count, &crtc, &zero, BPF_ANY);
	bpf_map_update_elem(&last_sample_ts, &crtc, &now, BPF_ANY);

	return 0;
}
