// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Game detection program - combines eBPF process tracking with X11 window monitoring
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <X11/Xutil.h>
#include "gamedetect.h"
#include "gamedetect.skel.h"

#define MAX_GAME_PIDS 256

static struct env {
	bool verbose;
} env;

const char *argp_program_version = "gamedetect 1.0";
const char *argp_program_bug_address = "<your@email.com>";
const char argp_program_doc[] = "Game Detection - Detect active game playing via eBPF + X11\n"
				"\n"
				"USAGE: sudo ./gamedetect [-v]\n"
				"\n"
				"EXAMPLES:\n"
				"    sudo ./gamedetect      # detect game activity\n"
				"    sudo ./gamedetect -v   # verbose output\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
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

/* Game process tracking */
static int game_pids[MAX_GAME_PIDS];
static char game_names[MAX_GAME_PIDS][TASK_COMM_LEN];
static int num_game_pids = 0;

/* Current game state */
static bool is_playing = false;
static int current_game_pid = -1;
static char current_game_window[256] = "";

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

/* Add a game PID to tracking list */
static void add_game_pid(int pid, const char *comm)
{
	if (num_game_pids >= MAX_GAME_PIDS)
		return;

	/* Check if already exists */
	for (int i = 0; i < num_game_pids; i++) {
		if (game_pids[i] == pid)
			return;
	}

	game_pids[num_game_pids] = pid;
	strncpy(game_names[num_game_pids], comm, TASK_COMM_LEN - 1);
	game_names[num_game_pids][TASK_COMM_LEN - 1] = '\0';
	num_game_pids++;
}

/* Remove a game PID from tracking list */
static void remove_game_pid(int pid)
{
	for (int i = 0; i < num_game_pids; i++) {
		if (game_pids[i] == pid) {
			/* Shift remaining elements */
			for (int j = i; j < num_game_pids - 1; j++) {
				game_pids[j] = game_pids[j + 1];
				strncpy(game_names[j], game_names[j + 1], TASK_COMM_LEN);
			}
			num_game_pids--;
			return;
		}
	}
}

/* Check if PID is a game process */
static bool is_game_pid(int pid)
{
	for (int i = 0; i < num_game_pids; i++) {
		if (game_pids[i] == pid)
			return true;
	}
	return false;
}

/* Get game name for PID */
static const char *get_game_name(int pid)
{
	for (int i = 0; i < num_game_pids; i++) {
		if (game_pids[i] == pid)
			return game_names[i];
	}
	return "<unknown>";
}

/* Get window title with UTF-8 support */
static void get_window_title(Display *display, Window window, char *title, size_t max_len)
{
	Atom net_wm_name, utf8_string;
	Atom actual_type;
	int actual_format;
	unsigned long nitems, bytes_after;
	unsigned char *prop = NULL;
	char *name = NULL;

	net_wm_name = XInternAtom(display, "_NET_WM_NAME", False);
	utf8_string = XInternAtom(display, "UTF8_STRING", False);

	if (XGetWindowProperty(display, window, net_wm_name, 0, 1024, False, utf8_string,
			       &actual_type, &actual_format, &nitems, &bytes_after,
			       &prop) == Success &&
	    prop) {
		snprintf(title, max_len, "%s", (char *)prop);
		XFree(prop);
		return;
	}

	if (XFetchName(display, window, &name) && name) {
		snprintf(title, max_len, "%s", name);
		XFree(name);
		return;
	}

	snprintf(title, max_len, "<unknown 0x%lx>", window);
}

/* Get PID of window */
static int get_window_pid(Display *display, Window window)
{
	Atom net_wm_pid = XInternAtom(display, "_NET_WM_PID", False);
	Atom actual_type;
	int actual_format;
	unsigned long nitems, bytes_after;
	unsigned char *prop = NULL;
	int pid = -1;

	if (XGetWindowProperty(display, window, net_wm_pid, 0, 1, False, XA_CARDINAL, &actual_type,
			       &actual_format, &nitems, &bytes_after, &prop) == Success &&
	    prop) {
		pid = *((int *)prop);
		XFree(prop);
	}

	return pid;
}

/* Get active window */
static Window get_active_window(Display *display)
{
	Window root = DefaultRootWindow(display);
	Atom net_active_window = XInternAtom(display, "_NET_ACTIVE_WINDOW", False);
	Atom actual_type;
	int actual_format;
	unsigned long nitems, bytes_after;
	unsigned char *prop = NULL;
	Window active_window = 0;

	if (XGetWindowProperty(display, root, net_active_window, 0, 1, False, XA_WINDOW,
			       &actual_type, &actual_format, &nitems, &bytes_after,
			       &prop) == Success &&
	    prop) {
		active_window = *((Window *)prop);
		XFree(prop);
	}

	return active_window;
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

/* Handle eBPF events */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct game_event *e = data;

	print_timestamp();

	switch (e->type) {
	case GAME_EVENT_START:
		printf("GAME_START: pid=%d ppid=%d comm=%s filename=%s\n", e->pid, e->ppid, e->comm,
		       e->filename);
		add_game_pid(e->pid, e->comm);
		break;
	case GAME_EVENT_EXIT:
		printf("GAME_EXIT:  pid=%d comm=%s exit_code=%d\n", e->pid, e->comm, e->exit_code);
		remove_game_pid(e->pid);

		/* Check if current game exited */
		if (current_game_pid == e->pid) {
			is_playing = false;
			current_game_pid = -1;
			current_game_window[0] = '\0';
			print_timestamp();
			printf("STATUS: Not playing\n");
		}
		break;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct gamedetect_bpf *skel;
	Display *display = NULL;
	Window last_window = 0;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = gamedetect_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = gamedetect_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = gamedetect_bpf__attach(skel);
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

	/* Open X11 display */
	display = XOpenDisplay(NULL);
	if (!display) {
		fprintf(stderr, "Warning: Cannot open X display, window tracking disabled\n");
	}

	/* Set up signal handler */
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("🎮 Game Detection Started!\n");
	printf("Monitoring for game activity... Press Ctrl-C to exit.\n");
	printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

	/* Main event loop */
	while (!exiting) {
		/* Poll for eBPF events (non-blocking, 10ms timeout) */
		err = ring_buffer__poll(rb, 10);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}

		/* Check active window every ~100ms */
		if (display) {
			Window active_window = get_active_window(display);

			if (active_window != last_window && active_window != 0) {
				last_window = active_window;

				int window_pid = get_window_pid(display, active_window);
				char title[256];
				get_window_title(display, active_window, title, sizeof(title));

				bool now_playing = is_game_pid(window_pid);

				if (now_playing != is_playing ||
				    (now_playing && window_pid != current_game_pid)) {
					is_playing = now_playing;
					current_game_pid = now_playing ? window_pid : -1;

					print_timestamp();
					if (is_playing) {
						strncpy(current_game_window, title,
							sizeof(current_game_window) - 1);
						printf("STATUS: PLAYING! [%s] pid=%d window=\"%s\"\n",
						       get_game_name(window_pid), window_pid,
						       title);
					} else {
						current_game_window[0] = '\0';
						printf("STATUS: Not playing (active: pid=%d \"%s\")\n",
						       window_pid, title);
					}
				}
			}
		}

		/* Small delay to avoid busy waiting */
		usleep(90000); /* ~90ms + 10ms poll = ~100ms cycle */
	}

	printf("\nFinal Status: %s\n", is_playing ? "Was playing" : "Not playing");
	printf("Tracked %d game process(es)\n", num_game_pids);

cleanup:
	ring_buffer__free(rb);
	gamedetect_bpf__destroy(skel);
	if (display)
		XCloseDisplay(display);
	return -err;
}
