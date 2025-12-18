// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "inputfreq.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// BPF map to store the event counter
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} event_counter SEC(".maps");

// Per-thread map to track FD from sys_enter to sys_exit
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);   // thread ID
	__type(value, u32); // file descriptor
} read_enter SEC(".maps");

// Helper function to get struct file* from file descriptor
static __always_inline struct file *get_file_from_fd(struct task_struct *task, unsigned int fd)
{
	struct files_struct *files;
	struct fdtable *fdt;
	struct file **fd_array;
	struct file *file;
	unsigned int max_fds;

	files = BPF_CORE_READ(task, files);
	if (!files)
		return NULL;

	fdt = BPF_CORE_READ(files, fdt);
	if (!fdt)
		return NULL;

	max_fds = BPF_CORE_READ(fdt, max_fds);

	// Bounds check required by BPF verifier
	if (fd >= max_fds)
		return NULL;

	fd_array = BPF_CORE_READ(fdt, fd);
	if (!fd_array)
		return NULL;

	// Read the file pointer at index fd using pointer arithmetic
	bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
	return file;
}

// Helper function to check if a file is an input device
static __always_inline bool is_input_device(struct file *file)
{
	struct inode *inode;
	dev_t dev;
	unsigned int major, minor;

	if (!file)
		return false;

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return false;

	dev = BPF_CORE_READ(inode, i_rdev);

	// Extract major and minor numbers
	// Linux uses: major = (dev >> 20) | ((dev >> 8) & 0xfff)
	//             minor = (dev & 0xff) | ((dev >> 12) & 0xfff00)
	// For simplicity, try the standard encoding
	major = (dev >> 8) & 0xff;
	minor = dev & 0xff;

	// Debug: print major/minor for character devices
	if (dev != 0) {
		bpf_printk("Device: major=%u minor=%u dev=0x%x", major, minor, dev);
	}

	// Input devices have major number 13 (INPUT_MAJOR)
	return major == 13;
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
	u64 tid = bpf_get_current_pid_tgid();
	u32 fd = (u32)ctx->args[0];  // First argument is file descriptor

	// Store FD for this thread
	bpf_map_update_elem(&read_enter, &tid, &fd, BPF_ANY);

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
	struct task_struct *task;
	struct file *file;
	u64 tid;
	u32 *fd_ptr;
	unsigned int fd;
	long bytes_read;
	u64 num_events;
	u32 key = 0;
	u64 *counter;

	// Get thread ID
	tid = bpf_get_current_pid_tgid();

	// Retrieve the FD we stored in sys_enter
	fd_ptr = bpf_map_lookup_elem(&read_enter, &tid);
	if (!fd_ptr)
		return 0;

	fd = *fd_ptr;

	// Clean up the map entry
	bpf_map_delete_elem(&read_enter, &tid);

	// Get return value (bytes read)
	bytes_read = ctx->ret;

	// Only process successful reads with data
	if (bytes_read <= 0)
		return 0;

	// Get current task
	task = (struct task_struct *)bpf_get_current_task();
	if (!task)
		return 0;

	// Get file structure for this FD
	file = get_file_from_fd(task, fd);
	if (!file)
		return 0;

	// Check if it's an input device
	if (!is_input_device(file))
		return 0;

	// Calculate number of input events
	// Each input_event structure is INPUT_EVENT_SIZE bytes
	num_events = bytes_read / INPUT_EVENT_SIZE;

	if (num_events == 0)
		return 0;

	// Update counter atomically
	counter = bpf_map_lookup_elem(&event_counter, &key);
	if (counter)
		__sync_fetch_and_add(counter, num_events);

	return 0;
}
