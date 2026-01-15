// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * gamedetect3 - PIDごとのGPU活動を監視（マップ直接読み取り版）
 */
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
#include <bpf/bpf.h>
#include "gamedetect3.h"
#include "gamedetect3.skel.h"

static struct env {
	bool verbose;
	int threshold;
} env = {
	.threshold = GPU_REQUEST_THRESHOLD,
};

const char *argp_program_version = "gamedetect3 1.0";
const char *argp_program_bug_address = "<your@email.com>";
const char argp_program_doc[] = "ゲーム検出 - PIDごとのGPU活動を監視\n"
				"\n"
				"使い方: sudo ./gamedetect3 [-v] [-t リクエスト数]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "詳細モード" },
	{ "threshold", 't', "REQUESTS", 0, "ゲーム判定閾値（デフォルト: 1000）" },
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
			env.threshold = GPU_REQUEST_THRESHOLD;
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

/* プロセス名を取得 */
static void get_process_name(int pid, char *name, size_t len)
{
	char path[64];
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/comm", pid);
	f = fopen(path, "r");
	if (f) {
		if (fgets(name, len, f)) {
			name[strcspn(name, "\n")] = 0;
		} else {
			snprintf(name, len, "pid=%d", pid);
		}
		fclose(f);
	} else {
		snprintf(name, len, "(終了)pid=%d", pid);
	}
}

/* バイト数をフォーマット */
static void format_bytes(unsigned long long bytes, char *buf, size_t len)
{
	if (bytes >= 1024 * 1024)
		snprintf(buf, len, "%.1f MB", (double)bytes / (1024 * 1024));
	else if (bytes >= 1024)
		snprintf(buf, len, "%.1f KB", (double)bytes / 1024);
	else
		snprintf(buf, len, "%llu B", bytes);
}

/* マップから全PIDの統計を読み取って表示 */
static void print_all_pid_stats(int map_fd)
{
	int pid = 0, next_pid;
	struct gpu_stats stats;
	struct gpu_stats zero_stats = {};
	char proc_name[64];
	char bytes_str[32];
	int count = 0;

	print_timestamp();
	printf("--- GPU Activity ---\n");

	while (bpf_map_get_next_key(map_fd, &pid, &next_pid) == 0) {
		if (bpf_map_lookup_elem(map_fd, &next_pid, &stats) == 0) {
			if (stats.request_count > 0 || stats.gem_create_count > 0) {
				get_process_name(next_pid, proc_name, sizeof(proc_name));
				format_bytes(stats.gem_create_bytes, bytes_str, sizeof(bytes_str));

				if ((int)stats.request_count >= env.threshold) {
					printf("  🎮 [%-20s] requests: %6u, mem: %4u (%s)\n",
					       proc_name, stats.request_count,
					       stats.gem_create_count, bytes_str);
				} else if (env.verbose || stats.request_count >= 10) {
					printf("     [%-20s] requests: %6u, mem: %4u (%s)\n",
					       proc_name, stats.request_count,
					       stats.gem_create_count, bytes_str);
				}
				count++;

				/* 統計をリセット */
				bpf_map_update_elem(map_fd, &next_pid, &zero_stats, BPF_ANY);
			}
		}
		pid = next_pid;
	}

	if (count == 0) {
		printf("  (GPU活動なし)\n");
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	struct gamedetect3_bpf *skel;
	int err;
	int map_fd;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	skel = gamedetect3_bpf__open();
	if (!skel) {
		fprintf(stderr, "エラー: eBPFプログラムを開けません\n");
		return 1;
	}

	err = gamedetect3_bpf__load(skel);
	if (err) {
		fprintf(stderr, "エラー: eBPFプログラムをロードできません\n");
		goto cleanup;
	}

	err = gamedetect3_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "エラー: i915トレースポイントにアタッチできません\n");
		goto cleanup;
	}

	map_fd = bpf_map__fd(skel->maps.pid_stats);

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "エラー: シグナルハンドラを設定できません\n");
		goto cleanup;
	}

	printf("🎮 gamedetect3 - PIDごとのGPU活動モニター\n");
	printf("ゲーム判定閾値: %d リクエスト/秒\n", env.threshold);
	printf("監視中... Ctrl+C で終了\n");
	printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

	/* 1秒ごとにマップを読み取って表示 */
	while (!exiting) {
		sleep(1);
		print_all_pid_stats(map_fd);
	}

	printf("\n終了\n");

cleanup:
	gamedetect3_bpf__destroy(skel);
	return -err;
}
