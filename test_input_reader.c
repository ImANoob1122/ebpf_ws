// Simple program to read from an input device for testing inputfreq
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/input.h>

int main(int argc, char *argv[])
{
	const char *device = "/dev/input/event3";  // Keyboard device
	struct input_event ev;
	int fd;
	int count = 0;

	if (argc > 1) {
		device = argv[1];
	}

	printf("Opening %s...\n", device);
	fd = open(device, O_RDONLY);
	if (fd < 0) {
		perror("Failed to open device");
		printf("Try: sudo %s /dev/input/event3\n", argv[0]);
		return 1;
	}

	printf("Reading input events from %s...\n", device);
	printf("Press keys or move mouse. Press Ctrl+C to stop.\n\n");

	while (1) {
		ssize_t n = read(fd, &ev, sizeof(ev));
		if (n == sizeof(ev)) {
			count++;
			printf("Event %d: type=%d code=%d value=%d\n",
			       count, ev.type, ev.code, ev.value);
		} else if (n < 0) {
			perror("read");
			break;
		}
	}

	close(fd);
	return 0;
}
