// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "inputfreq.h"
#include "inputfreq.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct inputfreq_bpf *skel;
	int err;
	int map_fd;
	__u32 key = 0;
	__u64 prev_count = 0, curr_count = 0;
	struct timespec sleep_time = {1, 0};  // 1 second

	// Set up libbpf errors and debug info callback
	libbpf_set_print(libbpf_print_fn);

	// Set up signal handlers
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// Open BPF application
	skel = inputfreq_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// Load & verify BPF programs
	err = inputfreq_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	// Attach tracepoints
	err = inputfreq_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// Get map file descriptor for reading counter
	map_fd = bpf_map__fd(skel->maps.event_counter);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to get map FD\n");
		err = -1;
		goto cleanup;
	}

	printf("Monitoring input device frequency... (Ctrl-C to exit)\n");
	printf("%-20s %10s %15s\n", "TIME", "EVENTS/SEC", "TOTAL");

	while (!exiting) {
		// Sleep for 1 second
		nanosleep(&sleep_time, NULL);

		// Read current counter value
		err = bpf_map_lookup_elem(map_fd, &key, &curr_count);
		if (err) {
			fprintf(stderr, "Failed to read counter from map\n");
			continue;
		}

		// Calculate events in last second
		__u64 events_per_sec = curr_count - prev_count;
		prev_count = curr_count;

		// Print summary with timestamp
		time_t t = time(NULL);
		struct tm *tm = localtime(&t);
		printf("%02d:%02d:%02d             %10llu %15llu\n",
		       tm->tm_hour, tm->tm_min, tm->tm_sec,
		       (unsigned long long)events_per_sec,
		       (unsigned long long)curr_count);
		fflush(stdout);
	}

	printf("\n");

cleanup:
	inputfreq_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
