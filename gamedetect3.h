#ifndef __GAMEDETECT3_H
#define __GAMEDETECT3_H

/*
 * PIDごとのGPU統計データ
 */
struct gpu_stats {
	unsigned int request_count; /* GPUリクエスト数 */
	unsigned int gem_create_count; /* メモリ割り当て回数 */
	unsigned long long gem_create_bytes; /* 割り当てた合計バイト数 */
};

/*
 * ユーザー空間に送信するイベントデータ（PIDごと）
 */
struct gpu_event {
	int pid; /* プロセスID */
	unsigned int request_count; /* GPUリクエスト数/秒 */
	unsigned int gem_create_count; /* メモリ割り当て回数/秒 */
	unsigned long long gem_create_bytes; /* 割り当てバイト数/秒 */
	unsigned long long timestamp_ns; /* タイムスタンプ（ナノ秒） */
};

/*
 * ゲーム検出の閾値
 */
#define GPU_REQUEST_THRESHOLD 1000
#define SAMPLE_WINDOW_NS      1000000000ULL
#define MAX_PIDS	      64 /* 追跡するPIDの最大数 */

#endif /* __GAMEDETECT3_H */
