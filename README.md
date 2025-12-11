# serchgame - Game Activity Detection via eBPF

An eBPF-based program to detect when games are being played on your Linux system by monitoring GPU and graphics-related system calls.

## How It Works

Since DirectX is Windows-specific, Linux games typically use:
- **Wine/Proton** - DirectX compatibility layers
- **DXVK/VKD3D** - DirectX to Vulkan translation
- **Native Vulkan/OpenGL** - Direct graphics APIs

This program detects gaming activity by monitoring:

1. **GPU Device Opens** - When processes open `/dev/dri/card*` or `/dev/dri/renderD*`
2. **DRM ioctl Calls** - Graphics API calls (DirectX → Vulkan → DRM ioctls)
3. **Game Process Execution** - Wine, Steam, Proton processes starting

## Build

```bash
make
```

## Usage

The program requires root privileges (or CAP_BPF capability):

```bash
# Basic usage
sudo ./serchgame

# Verbose output with libbpf debug info
sudo ./serchgame -v
```

## Example Output

```
Successfully started! Detecting game activity...
TIME     EVENT      PID     PPID    COMM             DETAILS
14:23:15 PROC_EXEC  12345   1234    steam            /usr/bin/steam
14:23:16 GPU_OPEN   12456   12345   wine64           /dev/dri/renderD128
14:23:16 GPU_IOCTL  12456   12345   wine64           ioctl_cmd=0x6400
14:23:17 GPU_IOCTL  12456   12345   wine64           ioctl_cmd=0x6402
```

## Event Types

- **GPU_OPEN** - A process opened a GPU device file
- **GPU_IOCTL** - A process made a DRM ioctl call (graphics command)
- **PROC_EXEC** - A game-related process was started

## Customization

You can modify filtering in `serchgame.bpf.c`:

### Add More Game Process Names
Edit lines 113-118 to add more process names to detect:
```c
// Example: Add detection for "lutris"
else if (comm[0] == 'l' && comm[1] == 'u' && comm[2] == 't' && comm[3] == 'r' && comm[4] == 'i' && comm[5] == 's')
    is_game_related = true;
```

### Remove Process Filtering
To track ALL GPU activity (not just games), set `is_game_related = true;` at line 110 instead of doing the checks.

### Modify ioctl Filtering
Edit line 54 in `serchgame.bpf.c` to change which ioctl commands are captured.

After making changes, rebuild with `make`.

## Stop the Program

Press `Ctrl+C` to gracefully stop monitoring.

## Technical Details

- **Kernel-Space**: [serchgame.bpf.c](serchgame.bpf.c) - BPF program running in the kernel
- **User-Space**: [serchgame.c](serchgame.c) - Application that loads the BPF program and displays output
- **Shared Headers**: [serchgame.h](serchgame.h) - Data structures shared between kernel and user-space

The program uses:
- Tracepoints: `sys_enter_openat`, `sys_enter_ioctl`, `sched_process_exec`
- Ring buffer for efficient data transfer from kernel to user-space
- BPF CO-RE (Compile Once - Run Everywhere) for portability
