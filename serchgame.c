// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "serchgame.h"
#include "serchgame.skel.h"

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

const char *argp_program_version = "serchgame 1.0";
const char *argp_program_bug_address = "<your@email.com>";
const char argp_program_doc[] =
"BPF serchgame - Detect game activity via GPU/graphics calls\n"
"\n"
"USAGE: ./serchgame [-v] [-d <min-duration-ms>]\n"
"\n"
"EXAMPLES:\n"
"    ./serchgame             # trace all GPU activity\n"
"    ./serchgame -v          # verbose output with libbpf debug\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum duration to trace in ms" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
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

static const char *event_type_str(enum event_type type)
{
	switch (type) {
	case EVENT_GPU_OPEN:
		return "GPU_OPEN";
	case EVENT_GPU_IOCTL:
		return "GPU_IOCTL";
	case EVENT_PROCESS_EXEC:
		return "PROC_EXEC";
	default:
		return "UNKNOWN";
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	switch (e->type) {
	case EVENT_GPU_OPEN:
		printf("%-8s %-10s %-7d %-7d %-16s %s\n",
		       ts, event_type_str(e->type), e->pid, e->ppid,
		       e->comm, e->filename);
		break;
	case EVENT_GPU_IOCTL:
		printf("%-8s %-10s %-7d %-7d %-16s ioctl_cmd=0x%x\n",
		       ts, event_type_str(e->type), e->pid, e->ppid,
		       e->comm, e->ioctl_cmd);
		break;
	case EVENT_PROCESS_EXEC:
		printf("%-8s %-10s %-7d %-7d %-16s %s\n",
		       ts, event_type_str(e->type), e->pid, e->ppid,
		       e->comm, e->filename);
		break;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct serchgame_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = serchgame_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with min_duration */
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	/* Load & verify BPF programs */
	err = serchgame_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = serchgame_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
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

	printf("Successfully started! Detecting game activity...\n");
	printf("%-8s %-10s %-7s %-7s %-16s %s\n",
	       "TIME", "EVENT", "PID", "PPID", "COMM", "DETAILS");

	/* Process events */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	serchgame_bpf__destroy(skel);
	return -err;
}
