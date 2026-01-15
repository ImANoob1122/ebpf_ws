#ifndef __GAMEDETECT2_H
#define __GAMEDETECT2_H

#define TASK_COMM_LEN 16

/* VBlank event data */
struct vblank_event {
	int crtc; /* CRTC index */
	unsigned int seq; /* sequence number */
	unsigned long long timestamp_ns; /* timestamp */
};

/* magic number */
#define GAME_FPS_THRESHOLD 30 /* FPS above this = game */
#define SAMPLE_WINDOW_NS   1000000000ULL /* 1 second */

#endif /* __GAMEDETECT2_H */
