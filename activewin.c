// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include "activewin.h"
#include "activewin.skel.h"

static struct env {
	bool verbose;
} env;

const char *argp_program_version = "activewin 1.0";
const char *argp_program_bug_address = "<ryosuke1122@keio.jp>";
const char argp_program_doc[] =
"BPF activewin - Track X11 window focus changes\n"
"\n"
"USAGE: ./activewin [-v]\n"
"\n"
"EXAMPLES:\n"
"    ./activewin             # track all window focus changes\n"
"    ./activewin -v          # verbose output with libbpf debug\n";

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

// X11 display connection (persistent)
static Display *x_display = NULL;

// Custom X11 error handler to suppress errors for invalid windows
static int x11_error_handler(Display *dpy, XErrorEvent *error)
{
	// Silently ignore errors (window may have been destroyed)
	return 0;
}

// Retrieve window title from X11 server
static void get_window_title(unsigned long window_id, char *title, size_t max_len)
{
	char *name = NULL;

	if (!x_display) {
		snprintf(title, max_len, "<no X connection>");
		return;
	}

	// Try to fetch window name using WM_NAME
	if (XFetchName(x_display, (Window)window_id, &name) && name) {
		snprintf(title, max_len, "%s", name);
		XFree(name);
	} else {
		// Fallback: try _NET_WM_NAME for UTF-8 support
		Atom net_wm_name = XInternAtom(x_display, "_NET_WM_NAME", False);
		Atom utf8_string = XInternAtom(x_display, "UTF8_STRING", False);
		Atom actual_type;
		int actual_format;
		unsigned long nitems, bytes_after;
		unsigned char *prop = NULL;

		if (XGetWindowProperty(x_display, (Window)window_id, net_wm_name,
				      0, 1024, False, utf8_string,
				      &actual_type, &actual_format,
				      &nitems, &bytes_after, &prop) == Success && prop) {
			snprintf(title, max_len, "%s", (char *)prop);
			XFree(prop);
		} else {
			snprintf(title, max_len, "<unknown 0x%lx>", window_id);
		}
	}
}

// Handle events from ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct window_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	char title[WINDOW_TITLE_LEN];

	// Format timestamp
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	// Retrieve window title from X11
	get_window_title(e->window_id, title, sizeof(title));

	// Display event
	printf("%-8s %-16s %-7d %-7d 0x%08llx %s\n",
	       ts, e->comm, e->pid, e->ppid, e->window_id, title);

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct activewin_bpf *skel;
	int err;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open X11 display */
	x_display = XOpenDisplay(NULL);
	if (!x_display) {
		fprintf(stderr, "Warning: Cannot open X display. Window titles will not be available.\n");
		fprintf(stderr, "Make sure DISPLAY environment variable is set.\n");
	} else {
		// Set custom error handler to suppress errors for invalid windows
		XSetErrorHandler(x11_error_handler);
	}

	/* Load and verify BPF application */
	skel = activewin_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		err = 1;
		goto cleanup;
	}

	/* Attach uprobe to XSetInputFocus in libX11.so.6 */
	uprobe_opts.func_name = "XSetInputFocus";
	uprobe_opts.retprobe = false;

	skel->links.handle_set_input_focus = bpf_program__attach_uprobe_opts(
		skel->progs.handle_set_input_focus,
		-1,  // All processes (system-wide)
		"/lib/x86_64-linux-gnu/libX11.so.6",
		0,   // Offset (auto-resolved by function name)
		&uprobe_opts
	);

	if (!skel->links.handle_set_input_focus) {
		fprintf(stderr, "Failed to attach uprobe to XSetInputFocus\n");
		fprintf(stderr, "Make sure /lib/x86_64-linux-gnu/libX11.so.6 exists\n");
		err = 1;
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

	printf("Tracking X11 window focus changes... Press Ctrl-C to exit.\n");
	printf("%-8s %-16s %-7s %-7s %-10s %s\n",
	       "TIME", "PROCESS", "PID", "PPID", "WINDOW_ID", "TITLE");

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
	if (x_display)
		XCloseDisplay(x_display);
	ring_buffer__free(rb);
	activewin_bpf__destroy(skel);
	return -err;
}
