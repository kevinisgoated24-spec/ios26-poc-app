#ifndef Bridging_h
#define Bridging_h
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <aio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/event.h>
#include <sys/types.h>
extern int proc_pidfdinfo(int pid, int fd, int flavor, void *buffer, int buffersize);
#define PROC_PIDFDKQUEUE_EXTINFO 9
#define EVFILT_AIO (-3)
uint64_t    cve_84530_leak(void);
const char *cve_84530_leak_str(void);
#endif
