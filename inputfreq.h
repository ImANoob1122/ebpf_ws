/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __INPUTFREQ_H
#define __INPUTFREQ_H

// Size of struct input_event on most 64-bit architectures
// struct input_event {
//     struct timeval time;  // 16 bytes on 64-bit
//     __u16 type;           // 2 bytes
//     __u16 code;           // 2 bytes
//     __s32 value;          // 4 bytes
// };
#define INPUT_EVENT_SIZE 24

#endif /* __INPUTFREQ_H */
