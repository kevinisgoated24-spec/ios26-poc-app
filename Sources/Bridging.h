#ifndef Bridging_h
#define Bridging_h
#include <stdint.h>
extern int proc_pidfdinfo(int pid, int fd, int flavor, void *buffer, int buffersize);
uint64_t    cve_84530_leak(void);
const char *cve_84530_leak_str(void);
#endif
