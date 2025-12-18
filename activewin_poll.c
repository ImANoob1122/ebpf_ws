// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Simple active window tracker using X11 property polling
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <X11/Xutil.h>

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

// Get window title with UTF-8 support
static void get_window_title(Display *display, Window window, char *title, size_t max_len)
{
	char *name = NULL;
	Atom net_wm_name, utf8_string;
	Atom actual_type;
	int actual_format;
	unsigned long nitems, bytes_after;
	unsigned char *prop = NULL;

	// Try _NET_WM_NAME first (UTF-8)
	net_wm_name = XInternAtom(display, "_NET_WM_NAME", False);
	utf8_string = XInternAtom(display, "UTF8_STRING", False);

	if (XGetWindowProperty(display, window, net_wm_name, 0, 1024, False,
	                      utf8_string, &actual_type, &actual_format,
	                      &nitems, &bytes_after, &prop) == Success && prop) {
		snprintf(title, max_len, "%s", (char *)prop);
		XFree(prop);
		return;
	}

	// Fallback to WM_NAME
	if (XFetchName(display, window, &name) && name) {
		snprintf(title, max_len, "%s", name);
		XFree(name);
		return;
	}

	snprintf(title, max_len, "<unknown 0x%lx>", window);
}

// Get PID of window
static int get_window_pid(Display *display, Window window)
{
	Atom net_wm_pid = XInternAtom(display, "_NET_WM_PID", False);
	Atom actual_type;
	int actual_format;
	unsigned long nitems, bytes_after;
	unsigned char *prop = NULL;
	int pid = -1;

	if (XGetWindowProperty(display, window, net_wm_pid, 0, 1, False,
	                      XA_CARDINAL, &actual_type, &actual_format,
	                      &nitems, &bytes_after, &prop) == Success && prop) {
		pid = *((int *)prop);
		XFree(prop);
	}

	return pid;
}

// Get process name from /proc
static void get_process_name(int pid, char *name, size_t max_len)
{
	char path[256];
	FILE *f;

	if (pid <= 0) {
		snprintf(name, max_len, "<unknown>");
		return;
	}

	snprintf(path, sizeof(path), "/proc/%d/comm", pid);
	f = fopen(path, "r");
	if (f) {
		if (fgets(name, max_len, f)) {
			// Remove trailing newline
			size_t len = strlen(name);
			if (len > 0 && name[len-1] == '\n')
				name[len-1] = '\0';
		} else {
			snprintf(name, max_len, "<unknown>");
		}
		fclose(f);
	} else {
		snprintf(name, max_len, "<unknown>");
	}
}

int main(int argc, char **argv)
{
	Display *display;
	Window root, active_window = 0, last_window = 0;
	Atom net_active_window;
	Atom actual_type;
	int actual_format;
	unsigned long nitems, bytes_after;
	unsigned char *prop = NULL;
	struct tm *tm;
	char ts[32];
	time_t t;
	char title[256];
	char proc_name[256];
	int pid;

	// Set up signal handler
	signal(SIGINT, sig_int);

	// Open X11 display
	display = XOpenDisplay(NULL);
	if (!display) {
		fprintf(stderr, "Cannot open X display\n");
		return 1;
	}

	root = DefaultRootWindow(display);
	net_active_window = XInternAtom(display, "_NET_ACTIVE_WINDOW", False);

	printf("Tracking active window changes... Press Ctrl-C to exit.\n");
	printf("%-8s %-16s %-7s %-10s %s\n",
	       "TIME", "PROCESS", "PID", "WINDOW_ID", "TITLE");

	while (!exiting) {
		// Get _NET_ACTIVE_WINDOW property
		if (XGetWindowProperty(display, root, net_active_window, 0, 1, False,
		                      XA_WINDOW, &actual_type, &actual_format,
		                      &nitems, &bytes_after, &prop) == Success && prop) {
			active_window = *((Window *)prop);
			XFree(prop);

			// Only print if window changed
			if (active_window != last_window && active_window != 0) {
				last_window = active_window;

				// Get timestamp
				time(&t);
				tm = localtime(&t);
				strftime(ts, sizeof(ts), "%H:%M:%S", tm);

				// Get window info
				get_window_title(display, active_window, title, sizeof(title));
				pid = get_window_pid(display, active_window);
				get_process_name(pid, proc_name, sizeof(proc_name));

				// Print event
				printf("%-8s %-16s %-7d 0x%08lx %s\n",
				       ts, proc_name, pid, active_window, title);
				fflush(stdout);
			}
		}

		// Poll every 100ms
		usleep(100000);
	}

	XCloseDisplay(display);
	return 0;
}
