// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* gamedetect2 - Detect games via DRM vblank frequency monitoring */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "gamedetect2.h"
#include "gamedetect2.skel.h"

static struct env {
	bool verbose;
	int threshold;
} env = {
	.threshold = GAME_FPS_THRESHOLD,
};

const char *argp_program_version = "gamedetect2 1.0";
const char *argp_program_bug_address = "<your@email.com>";
const char argp_program_doc[] =
	"Game Detection via DRM vblank monitoring\n"
	"\n"
	"Detects high frame rate activity indicating game play by monitoring\n"
	"DRM vblank events. When FPS exceeds threshold, reports 'Game Running'.\n"
	"\n"
	"USAGE: sudo ./gamedetect2 [-v] [-t FPS]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "threshold", 't', "FPS", 0, "FPS threshold for game detection (default: 45)" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 't':
		env.threshold = atoi(arg);
		if (env.threshold <= 0)
			env.threshold = GAME_FPS_THRESHOLD;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static volatile sig_atomic_t exiting = 0;
static bool game_detected = false;
static time_t last_game_time = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void print_timestamp(void)
{
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("[%s] ", ts);
}

/* Handle ring buffer events from eBPF */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct vblank_event *e = data;
	int fps;
	time_t now;

	/* Calculate FPS (vblank count per second window) */
	fps = e->seq;

	if (env.verbose) {
		print_timestamp();
		printf("CRTC %d: %d vblanks/sec (FPS estimate: %d)\n", e->crtc, fps, fps);
	}

	time(&now);

	/* Detect game based on FPS threshold */
	if (fps >= env.threshold) {
		if (!game_detected) {
			game_detected = true;
			print_timestamp();
			printf("🎮 ゲーム起動中！ (FPS: %d, CRTC: %d)\n", fps, e->crtc);
		}
		last_game_time = now;
	} else {
		/* If FPS drops below threshold for 3 seconds, consider game stopped */
		if (game_detected && (now - last_game_time) >= 3) {
			game_detected = false;
			print_timestamp();
			printf("⏹️  ゲーム停止 (FPS: %d)\n", fps);
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct gamedetect2_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = gamedetect2_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = gamedetect2_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = gamedetect2_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton (DRM tracepoints available?)\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Set up signal handler */
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("🎮 gamedetect2 - DRM VBlank Monitor\n");
	printf("FPS threshold: %d\n", env.threshold);
	printf("Monitoring DRM vblank events... Press Ctrl-C to exit.\n");
	printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

	/* Main event loop */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

	print_timestamp();
	printf("終了: %s\n", game_detected ? "ゲーム実行中だった" : "ゲーム未検出");

cleanup:
	ring_buffer__free(rb);
	gamedetect2_bpf__destroy(skel);
	return -err;
}
