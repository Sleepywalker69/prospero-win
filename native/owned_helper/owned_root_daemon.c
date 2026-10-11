/* Cooperative daemon: native root ownership and guarded elevation.
 * A HELD state deliberately retains every process whose directory ownership
 * may be ambiguous. Only FW 12.02 has completed console validation. */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "owned_identity.h"
#include "donor_transaction.h"
#include "lapy_elevation_protocol.h"
#include "owned_helper_control.h"
#include <poll.h>
#include "vnode_ref_probe.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <ps5/kernel.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern intptr_t kernel_get_ucred_prison(pid_t pid);

#ifndef TARGET_TITLE
#define TARGET_TITLE "PPSA99994"
#endif
#ifndef LAPY_SERVICE
#define LAPY_SERVICE 0
#endif
#ifndef LAPY_REQUIRE_CLIENT_RESULT
#define LAPY_REQUIRE_CLIENT_RESULT 1
#endif
#ifndef LAPY_MAX_REQUESTS
#define LAPY_MAX_REQUESTS 0
#endif
#ifndef LAPY_ELF_HELPER
#define LAPY_ELF_HELPER 0
#endif
#define TITLE_PREFIX TARGET_TITLE "_"
#define SANDBOX_BASE "/mnt/sandbox"
#define REQUEST_SUFFIX "/download0/elevate_proc"
#define ROOT_HOLD 0x1bcu
#define ROOT_USE 0x1c0u
#define PROC_PID_OFFSET 0xbcu
#define PROC_THREADS_HEAD 0x10u
#define PROC_SUSPCOUNT 0x3a0u
#define THREAD_PROC 0x08u
#define THREAD_NEXT 0x10u
#define FD_CDIR 0x08u
#define FD_REFCNT 0x34u
#define UCRED_REF 0x00u
#define UCRED_NGROUPS 0x10u
#define MAX_THREADS 256u
#define ROOT_LAYOUT_MAX_ATTEMPTS 3u
#define ROOT_LAYOUT_RETRY_DELAY_US 100000u
#define PTRACE_AUTHID UINT64_C(0x4800000000010003)
#define SYSTEM_AUTHID UINT64_C(0x4801000000000013)

struct child {
    pid_t pid;
    intptr_t proc, fd;
    int stopped, reaped;
    /* Private record produced only by start_child, never a caller-supplied
     * capability or protection against arbitrary in-process memory forgery.
     * A PID is usable only while this helper owns the unreaped child. */
    pid_t creator_pid;
    uint64_t transaction_id;
    unsigned created, identity_refused;
};

struct snapshot {
    intptr_t proc, fd, ucred, prison, root, jail, cwd;
    intptr_t threads[MAX_THREADS];
    unsigned count, suspended;
    uint32_t fd_refs, cred_refs;
};

struct credentials {
    uid_t uid, ruid, svuid;
    gid_t rgid, svgid;
    uint32_t ngroups;
    uint64_t authid;
    uint8_t attrs[32];
    uint8_t caps[16];
};

/* One single-threaded transaction. No recovery listener or added authority. */
#if LAPY_ELF_HELPER
static struct lapy_helper_control helper_control;
static struct lapy_elevation_message helper_initial_request;
static unsigned helper_initial_bound, helper_initial_cancel, helper_response_attempted;
/* Only locally proved no-work/settled boundaries may admit self termination. */
static unsigned helper_exit_ready;
static int control_clock(void *unused, uint64_t *out)
{
    (void)unused;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0 ||
        (uint64_t)now.tv_sec > (UINT64_MAX - 999) / 1000) return -1;
    *out = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
    return 0;
}
static int control_wait(void *unused, int writing, unsigned milliseconds)
{
    (void)unused;
    struct pollfd p = {writing ? STDOUT_FILENO : STDIN_FILENO,
                        writing ? POLLOUT : POLLIN, 0};
    int rc = poll(&p, 1, (int)milliseconds);
    if (rc < 0) return errno == EINTR ? 0 : -1;
    if (!rc) return 0;
    if (p.revents & (POLLERR | POLLNVAL)) return -1;
    return (p.revents & (writing ? POLLOUT : (POLLIN | POLLHUP))) ? 1 : -1;
}
static long control_read(void *unused, void *bytes, size_t size)
{ (void)unused; return (long)read(STDIN_FILENO, bytes, size); }
static long control_write(void *unused, const void *bytes, size_t size)
{ (void)unused; return (long)write(STDOUT_FILENO, bytes, size); }
#endif
#if LAPY_ELF_HELPER
static int helper_cancel_requires_hold(int cancellation, int target_involved)
{
    return cancellation != LAPY_CTL_CONTINUE && target_involved != 0;
}
#endif

static int helper_checkpoint(const char *stage, pid_t target,
                              const struct child *first,
                              const struct child *second,
                              int roots_touched, int roots_moved,
                              int target_involved)
{
#if LAPY_ELF_HELPER
    /* Caller invokes only at a boundary where CANCEL is the sole optional
     * next frame; never while waiting for an expected PREPARED frame. */
    enum lapy_control_result result = helper_control.bound ?
        lapy_control_checkpoint(&helper_control) : LAPY_CTL_PROTOCOL;
    ps5log_printf(result ? PS5LOG_ERR : PS5LOG_MARK,
        "helper_inventory build=%s transaction=%llu helper_pid=%d target_pid=%d stage=%s cancel=%u roots_touched=%d roots_moved=%d first_pid=%d first_reaped=%d second_pid=%d second_reaped=%d",
        LAPY_OWNED_ID, (unsigned long long)helper_control.request.transaction_id,
        getpid(), target, stage, result, roots_touched, roots_moved,
        first ? first->pid : -1, first ? first->reaped : 0,
        second ? second->pid : -1, second ? second->reaped : 0);
    if (helper_cancel_requires_hold(result, target_involved)) {
        ps5log_printf(PS5LOG_ERR,
            "helper_held build=%s transaction=%llu helper_pid=%d target_pid=%d stage=%s reason=cancel_after_target_involvement cancel=%u",
            LAPY_OWNED_ID, (unsigned long long)helper_control.request.transaction_id,
            getpid(), target, stage, result);
        for (;;) sleep(1);
    }
    return result ? ECANCELED : 0;
#else
    (void)stage; (void)target; (void)first; (void)second;
    (void)roots_touched; (void)roots_moved; (void)target_involved;
    return 0;
#endif
}

static int read_ptr(void *unused, intptr_t address, intptr_t *value)
{
    (void)unused;
    return kernel_copyout(address, value, sizeof(*value)) ? EFAULT : 0;
}

static int write_ptr(void *unused, intptr_t address, intptr_t value)
{
    (void)unused;
    return kernel_copyin(&value, address, sizeof(value)) ? EFAULT : 0;
}

static int read_root_counts(intptr_t root,
                            struct lapy_vnode_ref_counts *out)
{
    if (kernel_copyout(root + ROOT_HOLD, &out->hold, sizeof(out->hold)) ||
        kernel_copyout(root + ROOT_USE, &out->use, sizeof(out->use)))
        return EFAULT;
    return 0;
}

static int sample_root(intptr_t root, const char *phase,
                       struct lapy_vnode_ref_counts *out)
{
    int error = read_root_counts(root, out);
    if (error) return error;
    ps5log_printf(PS5LOG_MARK,
                  "root_sample build=%s phase=%s hold=%u use=%u",
                  LAPY_OWNED_ID, phase, out->hold, out->use);
    return 0;
}

static int snapshot(pid_t pid, struct snapshot *out)
{
    pid_t observed = 0;
    intptr_t current = 0, owner = 0, next = 0;
    memset(out, 0, sizeof(*out));
    out->proc = kernel_get_proc(pid);
    if (!out->proc || kernel_copyout(out->proc + PROC_PID_OFFSET,
                                     &observed, sizeof(observed)) ||
        observed != pid) return ESRCH;
    out->fd = kernel_get_proc_filedesc(pid);
    out->ucred = kernel_get_proc_ucred(pid);
    out->prison = kernel_get_ucred_prison(pid);
    if (!out->fd || !out->ucred || !out->prison ||
        kernel_copyout(out->fd + FD_REFCNT, &out->fd_refs,
                       sizeof(out->fd_refs)) ||
        kernel_copyout(out->ucred + UCRED_REF, &out->cred_refs,
                       sizeof(out->cred_refs)) ||
        kernel_copyout(out->proc + PROC_SUSPCOUNT, &out->suspended,
                       sizeof(out->suspended)) ||
        read_ptr(0, out->fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
                 &out->root) ||
        read_ptr(0, out->fd + KERNEL_OFFSET_FILEDESC_FD_JDIR,
                 &out->jail) ||
        read_ptr(0, out->fd + FD_CDIR, &out->cwd) ||
        read_ptr(0, out->proc + PROC_THREADS_HEAD, &current))
        return EFAULT;
    while (current) {
        if (out->count >= MAX_THREADS) return EOVERFLOW;
        for (unsigned i = 0; i < out->count; ++i)
            if (out->threads[i] == current) return ELOOP;
        out->threads[out->count++] = current;
        if (read_ptr(0, current + THREAD_PROC, &owner) ||
            read_ptr(0, current + THREAD_NEXT, &next) ||
            owner != out->proc) return EFAULT;
        current = next;
    }
    return out->count ? 0 : EPROTO;
}

static int same_stop(const struct snapshot *a, const struct snapshot *b)
{
    return a->proc == b->proc && a->fd == b->fd &&
           a->ucred == b->ucred && a->prison == b->prison &&
           a->root == b->root &&
           a->jail == b->jail && a->cwd == b->cwd &&
           a->fd_refs == 1 && b->fd_refs == 1 &&
           a->cred_refs == b->cred_refs &&
           a->count == b->count && a->count == a->suspended &&
           b->count == b->suspended &&
           !memcmp(a->threads, b->threads,
                   a->count * sizeof(a->threads[0]));
}

static int find_thread_credential_slot(const struct snapshot *state,
                                       size_t *offset)
{
    if (state->count != 1 || state->cred_refs != 2) return EBUSY;
    unsigned matches = 0;
    for (size_t at = 0x20; at < 0x400; at += sizeof(intptr_t)) {
        intptr_t pointer = 0;
        if (read_ptr(0, state->threads[0] + at, &pointer)) return EFAULT;
        if (pointer == state->ucred) {
            *offset = at;
            ++matches;
        }
    }
    return matches == 1 ? 0 : EPROTO;
}

static int private_process_credential(const struct snapshot *state,
                                      size_t thread_credential_offset)
{
    intptr_t thread_credential = 0;
    return state->count == 1 && state->cred_refs == 2 &&
           !read_ptr(0, state->threads[0] + thread_credential_offset,
                     &thread_credential) &&
           thread_credential == state->ucred;
}

#if !LAPY_ELF_HELPER
static pid_t parse_pid(const char *message)
{
    const char *p = strstr(message, "\"PID\"");
    if (!p || !(p = strchr(p, ':'))) return -1;
    ++p;
    while (*p == ' ' || *p == '\t' || *p == '"') ++p;
    errno = 0;
    char *end = 0;
    long value = strtol(p, &end, 10);
    return errno || end == p || value <= 1 || value > INT_MAX ?
           -1 : (pid_t)value;
}

static int find_request(char path[512], pid_t *pid, time_t started)
{
    DIR *directory = opendir(SANDBOX_BASE);
    if (!directory) return errno == ENOENT ? 0 : -(errno ? errno : EIO);
    struct dirent *entry;
    int result = 0;
    while ((entry = readdir(directory))) {
        if (TARGET_TITLE[0] == '*' && TARGET_TITLE[1] == 0) {
            if (strlen(entry->d_name) < 10 ||
                strncmp(entry->d_name, "PPSA", 4) ||
                entry->d_name[9] != '_') continue;
            int valid = 1;
            for (int i = 4; i < 9; ++i)
                if (entry->d_name[i] < '0' || entry->d_name[i] > '9')
                    valid = 0;
            if (!valid) continue;
        } else if (strncmp(entry->d_name, TITLE_PREFIX,
                           sizeof(TITLE_PREFIX) - 1)) continue;
        int length = snprintf(path, 512, "%s/%s%s", SANDBOX_BASE,
                              entry->d_name, REQUEST_SUFFIX);
        if (length <= 0 || length >= 512) continue;
        struct stat st;
        if (stat(path, &st) || st.st_size <= 0 || st.st_mtime < started)
            continue;
        FILE *file = fopen(path, "r");
        if (!file) { result = -(errno ? errno : EIO); break; }
        char message[512];
        size_t size = fread(message, 1, sizeof(message) - 1, file);
        int read_error = ferror(file);
        fclose(file);
        if (read_error || !size) { result = -EIO; break; }
        message[size] = 0;
        *pid = parse_pid(message);
        result = *pid > 1 ? 1 : -EINVAL;
        break;
    }
    closedir(directory);
    return result;
}

#if !LAPY_SERVICE || LAPY_REQUIRE_CLIENT_RESULT
static int client_result_path(const char *request, char result[512])
{
    size_t length = strlen(request), suffix = strlen(REQUEST_SUFFIX);
    if (length <= suffix || strcmp(request + length - suffix, REQUEST_SUFFIX))
        return EINVAL;
    int written = snprintf(result, 512, "%.*s/download0/lapy_owned_result",
                           (int)(length - suffix), request);
    return written > 0 && written < 512 ? 0 : ENAMETOOLONG;
}

static int await_client_result(const char *path)
{
    for (unsigned i = 0; i < 100; ++i) {
        FILE *file = fopen(path, "r");
        if (file) {
            int data_ok = -1, open_errno = -1;
            int parsed = fscanf(file, "DATA_OK=%d OPEN_ERRNO=%d",
                                &data_ok, &open_errno);
            fclose(file);
            if (parsed != 2) {
                usleep(100000);
                continue;
            }
            if (unlink(path)) return errno ? errno : EIO;
            ps5log_printf(data_ok == 1 ? PS5LOG_MARK : PS5LOG_ERR,
                          "client_result build=%s data_rw=%d open_errno=%d",
                          LAPY_OWNED_ID, data_ok, open_errno);
            return data_ok == 1 ? 0 : EACCES;
        }
        if (errno != ENOENT) return errno ? errno : EIO;
        usleep(100000);
    }
    return ETIMEDOUT;
}
#endif
#endif /* !LAPY_ELF_HELPER */

static void child_main(void)
{
    /* waitpid(WUNTRACED) is the readiness acknowledgement. */
    if (kill(getpid(), SIGSTOP)) _exit(2);
    for (;;) pause();
}

/* Read-only admission checks; never alter SIGCHLD disposition. The helper's
 * existing single-thread preflight and exclusive wait ownership are required.
 * Firmware support for native zombie retention remains a target-validation gate. */
static int child_retention_ready(void)
{
#ifdef SA_NOCLDWAIT
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    if (sigaction(SIGCHLD, NULL, &action)) return errno ? errno : EIO;
    if (action.sa_handler != SIG_DFL || (action.sa_flags & SA_NOCLDWAIT))
        return ENOTSUP;
    return 0;
#else
    return ENOTSUP;
#endif
}

static uint64_t helper_transaction_for_log(void)
{
#if LAPY_ELF_HELPER
    return helper_control.bound ? helper_control.request.transaction_id : 0;
#else
    return 0;
#endif
}

static int child_empty(const struct child *self)
{
    return self && self->pid == -1 && !self->proc && !self->fd &&
           !self->stopped && !self->reaped && !self->creator_pid &&
           !self->transaction_id && !self->created && !self->identity_refused;
}

static int child_scope_matches(const struct child *self)
{
    if (!self) return ECHILD;
    if (self->identity_refused) return EPROTO;
    if (self->created != 1 || self->pid <= 1 ||
        (self->stopped != 0 && self->stopped != 1) ||
        (self->reaped != 0 && self->reaped != 1) ||
        self->creator_pid != getpid()) return ECHILD;
#if LAPY_ELF_HELPER
    if (!helper_control.bound || !self->transaction_id ||
        self->transaction_id != helper_control.request.transaction_id)
        return EPROTO;
#else
    if (self->transaction_id) return EPROTO;
#endif
    return 0;
}

static int child_operation_ready(const struct child *self)
{
    int error = child_scope_matches(self);
    if (error) return error;
    if (self->reaped) return ECHILD;
    return child_retention_ready();
}

static int owned_child_live(struct child *self);

static int start_child(struct child *self)
{
    if (!child_empty(self)) return EBUSY;
#if LAPY_ELF_HELPER
    if (!helper_control.bound || !helper_control.request.transaction_id)
        return EPROTO;
#endif
    int error = child_retention_ready();
    if (error) return error;
    pid_t creator = getpid();
    uint64_t transaction = helper_transaction_for_log();
    self->pid = rfork(RFPROC | RFFDG);
    if (self->pid == 0) child_main();
    if (self->pid < 0) return errno ? errno : EIO;
    if (self->pid <= 1) return EPROTO;
    self->creator_pid = creator;
    self->transaction_id = transaction;
    self->created = 1;
    for (unsigned i = 0; i < 100; ++i) {
        int status = 0;
        if ((error = child_operation_ready(self))) return error;
        pid_t result = waitpid(self->pid, &status, WNOHANG | WUNTRACED);
        if (result == self->pid) {
            if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
                if (WIFEXITED(status) || WIFSIGNALED(status))
                    self->reaped = 1;
                return EPROTO;
            }
            if ((error = child_operation_ready(self))) return error;
            if (kill(self->pid, SIGCONT)) return errno ? errno : EIO;
            for (unsigned resumed = 0; resumed < 100; ++resumed) {
                struct snapshot state;
                if (!snapshot(self->pid, &state) && !state.suspended)
                    return 0;
                usleep(10000);
            }
            return ETIMEDOUT;
        }
        if (result > 0) { self->identity_refused = 1; return EPROTO; }
        if (result < 0) return errno ? errno : ECHILD;
        usleep(50000);
    }
    return ETIMEDOUT;
}

static int stop_child(struct child *self, intptr_t root)
{
    struct snapshot first, second;
    int admission_error = owned_child_live(self);
    if (admission_error) return admission_error;
    if (kill(self->pid, SIGSTOP)) return errno ? errno : EIO;
    self->stopped = 1;
    for (unsigned i = 0; i < 100; ++i) {
        int error = snapshot(self->pid, &first);
        if (error) return error;
        if (first.proc != self->proc || first.fd != self->fd) {
            self->identity_refused = 1;
            return ESRCH;
        }
        if (first.fd_refs != 1 || first.root != root || first.jail ||
            first.cwd != root || first.count != 1) return EPROTO;
        if (first.suspended == 1) {
            usleep(50000);
            if ((error = snapshot(self->pid, &second))) return error;
            if (second.proc != self->proc || second.fd != self->fd) {
                self->identity_refused = 1;
                return ESRCH;
            }
            if (same_stop(&first, &second)) return 0;
        }
        usleep(50000);
    }
    return ETIMEDOUT;
}

static int owned_child_live(struct child *self)
{
    int status = 0;
    int error = child_operation_ready(self);
    if (error) return error;
    pid_t result = waitpid(self->pid, &status, WNOHANG);
    if (result == self->pid) {
        if (WIFEXITED(status) || WIFSIGNALED(status)) self->reaped = 1;
        return EPROTO; /* Unexpected pre-signal exit is not a successful reap. */
    }
    if (result > 0) { self->identity_refused = 1; return EPROTO; }
    if (result < 0) return errno ? errno : ECHILD;
    if (self->proc && (kernel_get_proc(self->pid) != self->proc ||
                      kernel_get_proc_filedesc(self->pid) != self->fd)) {
        self->identity_refused = 1;
        return ESRCH;
    }
    return 0;
}
static int release_child(struct child *self)
{
    int error = owned_child_live(self), status = 0;
    if (error) return error;
    if (self->stopped) {
        if (kill(self->pid, SIGCONT)) return errno ? errno : EIO;
        self->stopped = 0;
    }
    if ((error = owned_child_live(self))) return error;
    /* Positive creation provenance, default/no-auto-reap SIGCHLD and the
     * single exclusive waiter retain this child identity until terminal wait.
     * If it exits between this guard and signal, its PID remains unreaped. */
    if (kill(self->pid, SIGKILL)) return errno ? errno : EIO;
    for (unsigned i = 0; i < 100; ++i) {
        if ((error = child_operation_ready(self))) return error;
        pid_t result = waitpid(self->pid, &status, WNOHANG);
        if (result == self->pid) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) self->reaped = 1;
            return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL ? 0 : EPROTO;
        }
        if (result > 0) { self->identity_refused = 1; return EPROTO; }
        if (result < 0) return errno ? errno : ECHILD;
        usleep(50000);
    }
    return ETIMEDOUT;
}
static int cleanup_child(struct child *self)
{
    if (child_empty(self)) return 0;
    int error = child_scope_matches(self);
    if (error) return error;
    if (self->reaped) return 0;
    return release_child(self); /* bounded; errors never certify settlement */
}

/* The SDK resolves rootvnode per firmware, but does not expose these vnode
 * counter offsets. Check the assumed layout using a disposable native
 * RFPROC|RFFDG child before any target credential or directory write. */
static int validate_root_reference_layout_once(intptr_t root,
                                               intptr_t self_fd,
                                               unsigned attempt,
                                               int *retryable)
{
    struct child donor = {.pid = -1};
    struct snapshot observed;
    struct lapy_vnode_ref_counts before = {0}, during = {0}, after = {0};
    *retryable = 0;
    int error = sample_root(root, "layout_before", &before);
    if (error) return error;
    if (!before.hold || !before.use ||
        before.hold > 1000000 || before.use > 1000000)
        return EPROTO;
    if ((error = start_child(&donor))) goto done;
    if ((error = snapshot(donor.pid, &observed))) goto done;
    if (observed.fd == self_fd || observed.fd_refs != 1 ||
        observed.root != root || observed.jail || observed.cwd != root ||
        observed.count != 1 || observed.suspended) {
        error = EPROTO; goto done;
    }
    if ((error = sample_root(root, "layout_donor", &during))) goto done;
    if (!lapy_vnode_ref_probe_added_two(&before, &during)) {
        /* The counters are global. A concurrent vnode release can hide the
         * donor's +2 even when its private filedesc snapshot is correct. */
        error = EPROTO;
        *retryable = 1;
    }
    if ((error = release_child(&donor))) {
        *retryable = 0;
        goto done;
    }
    if ((error = sample_root(root, "layout_released", &after))) {
        *retryable = 0;
        goto done;
    }
    if (!lapy_vnode_ref_probe_returned_to_baseline(&before, &after)) {
        error = EPROTO;
        *retryable = 1;
    } else if (!*retryable) {
        error = 0;
    }
done:
    {
        int cleanup_error = cleanup_child(&donor);
        if (cleanup_error) {
            error = cleanup_error;
            *retryable = 0;
            ps5log_printf(PS5LOG_ERR,
                "daemon_held build=%s transaction=%llu stage=layout_donor_cleanup reason=owned_donor_cleanup_unproved error=%d first_pid=%d first_reaped=%d",
                LAPY_OWNED_ID, (unsigned long long)helper_transaction_for_log(),
                error, donor.pid, donor.reaped);
            for (;;) sleep(1);
        }
    }
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "root_layout_probe build=%s attempt=%u valid=%d error=%d retryable=%d before_hold=%u before_use=%u donor_hold=%u donor_use=%u released_hold=%u released_use=%u",
                  LAPY_OWNED_ID, attempt, error == 0, error, *retryable,
                  before.hold, before.use, during.hold, during.use,
                  after.hold, after.use);
    return error;
}

static int validate_root_reference_layout(intptr_t root, intptr_t self_fd)
{
    unsigned attempts = 0;
    int error = EPROTO;
    for (unsigned attempt = 1; attempt <= ROOT_LAYOUT_MAX_ATTEMPTS;
         ++attempt) {
        int retryable = 0;
        attempts = attempt;
        error = validate_root_reference_layout_once(root, self_fd, attempt,
                                                     &retryable);
        if (!error || !retryable)
            break;
        ps5log_printf(PS5LOG_MARK,
                      "root_layout_retry build=%s attempt=%u next=%u error=%d",
                      LAPY_OWNED_ID, attempt, attempt + 1, error);
        if (attempt < ROOT_LAYOUT_MAX_ATTEMPTS)
            usleep(ROOT_LAYOUT_RETRY_DELAY_US);
    }
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "root_layout build=%s valid=%d error=%d attempts=%u",
                  LAPY_OWNED_ID, error == 0, error, attempts);
    return error;
}

static int validate_group_layout(intptr_t ucred)
{
    uint32_t stored = UINT32_MAX;
    int native = getgroups(0, 0);
    int error = native < 0 ? (errno ? errno : EIO) : 0;
    if (!error && kernel_copyout(ucred + UCRED_NGROUPS,
                                 &stored, sizeof(stored)))
        error = EFAULT;
    if (!error && stored != (uint32_t)native)
        error = EPROTO;
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "group_layout build=%s valid=%d error=%d",
                  LAPY_OWNED_ID, error == 0, error);
    return error;
}

static int save_credentials(pid_t pid, intptr_t ucred,
                            struct credentials *out)
{
    out->uid = kernel_get_ucred_uid(pid);
    out->ruid = kernel_get_ucred_ruid(pid);
    out->svuid = kernel_get_ucred_svuid(pid);
    out->rgid = kernel_get_ucred_rgid(pid);
    out->svgid = kernel_get_ucred_svgid(pid);
    out->authid = kernel_get_ucred_authid(pid);
    return kernel_get_ucred_attrs(pid, out->attrs) ||
           kernel_get_ucred_caps(pid, out->caps) ||
           kernel_copyout(ucred + UCRED_NGROUPS, &out->ngroups,
                          sizeof(out->ngroups)) ? EFAULT : 0;
}

static int credentials_match(pid_t pid, const struct credentials *expected,
                             intptr_t ucred)
{
    struct credentials found;
    return !save_credentials(pid, ucred, &found) &&
           found.uid == expected->uid &&
           found.ruid == expected->ruid &&
           found.svuid == expected->svuid &&
           found.rgid == expected->rgid &&
           found.svgid == expected->svgid &&
           found.ngroups == expected->ngroups &&
           found.authid == expected->authid &&
           !memcmp(found.attrs, expected->attrs, sizeof(found.attrs)) &&
           !memcmp(found.caps, expected->caps, sizeof(found.caps));
}

static int target_identity_matches(pid_t pid, const struct snapshot *expected)
{
    struct snapshot found;
    return !snapshot(pid, &found) && found.proc == expected->proc &&
           found.fd == expected->fd && found.ucred == expected->ucred &&
           found.prison == expected->prison && found.fd_refs == 1 &&
           found.cred_refs == expected->cred_refs && found.cred_refs == 2 &&
           found.root == expected->root && found.jail == expected->jail &&
           found.cwd == expected->cwd &&
           found.count == expected->count && found.count == found.suspended &&
           !memcmp(found.threads, expected->threads,
                   found.count * sizeof(found.threads[0]));
}
static int set_credentials(pid_t pid, const struct snapshot *expected,
                           const struct credentials *value)
{
    /* Keep the original traced target quiescent. A failed identity check
     * prevents subsequent writes; never resolve a replacement PID's ucred. */
#define GUARDED_WRITE(call) do { \
    if (!target_identity_matches(pid, expected)) return ESRCH; \
    if ((call)) return EIO; \
} while (0)
    GUARDED_WRITE(kernel_set_ucred_uid(pid, value->uid));
    GUARDED_WRITE(kernel_set_ucred_ruid(pid, value->ruid));
    GUARDED_WRITE(kernel_set_ucred_svuid(pid, value->svuid));
    GUARDED_WRITE(kernel_set_ucred_rgid(pid, value->rgid));
    GUARDED_WRITE(kernel_set_ucred_svgid(pid, value->svgid));
    GUARDED_WRITE(kernel_copyin(&value->ngroups, expected->ucred + UCRED_NGROUPS,
                                sizeof(value->ngroups)));
    GUARDED_WRITE(kernel_set_ucred_authid(pid, value->authid));
    GUARDED_WRITE(kernel_set_ucred_caps(pid, value->caps));
    GUARDED_WRITE(kernel_set_ucred_attrs(pid, value->attrs));
#undef GUARDED_WRITE
    return target_identity_matches(pid, expected) &&
           credentials_match(pid, value, expected->ucred) ? 0 : EIO;
}

static int await_target_stop(pid_t pid, const struct snapshot *before,
                             struct snapshot *stopped)
{
    int status = 0;
    for (unsigned i = 0; i < 100; ++i) {
        pid_t result = waitpid(pid, &status, WNOHANG | WUNTRACED);
        if (result == pid) {
            if (!WIFSTOPPED(status)) return EPROTO;
            break;
        }
        if (result < 0) return errno ? errno : ECHILD;
        if (i == 99) return ETIMEDOUT;
        usleep(50000);
    }
    struct snapshot first;
    int error = snapshot(pid, &first);
    if (error) return error;
    usleep(50000);
    if ((error = snapshot(pid, stopped))) return error;
    return first.proc == before->proc && first.fd == before->fd &&
           first.ucred == before->ucred &&
           first.prison == before->prison &&
           first.cred_refs == 2 &&
           same_stop(&first, stopped) ? 0 : EBUSY;
}

/* A traced title can be killed by its launcher while we prepare donors.
 * Only loss of the original proc identity proves that its credentials and
 * ptrace attachment no longer need restoring. Root transfer additionally
 * needs proof that both donors exited and the root counts settled. */
static int original_target_gone(pid_t pid, intptr_t original_proc)
{
    for (unsigned i = 0; i < 20; ++i) {
        if (kernel_get_proc(pid) != original_proc) {
            usleep(10000);
            if (kernel_get_proc(pid) != original_proc) return 1;
        }
        usleep(50000);
    }
    return 0;
}

static int transferred_target_gone(pid_t pid, intptr_t original_proc,
                                   const struct child *first,
                                   const struct child *second,
                                   intptr_t system_root,
                                   const struct lapy_vnode_ref_counts *baseline)
{
    struct lapy_vnode_ref_counts current;
    if (!first->reaped || !second->reaped ||
        !original_target_gone(pid, original_proc)) return 0;
    for (unsigned i = 0; i < 20; ++i) {
        if (!read_root_counts(system_root, &current) &&
            current.hold == baseline->hold &&
            current.use == baseline->use) {
            usleep(50000);
            if (kernel_get_proc(pid) != original_proc &&
                !read_root_counts(system_root, &current) &&
                current.hold == baseline->hold &&
                current.use == baseline->use) return 1;
        }
        usleep(50000);
    }
    return 0;
}

static int run_one(pid_t pid, intptr_t system_root,
                   const struct lapy_vnode_ref_counts *baseline,
                   size_t thread_credential_offset)
{
    struct child first = {.pid = -1};
    struct child second = {.pid = -1};
    struct snapshot before, stopped, confirmed, donor;
    struct credentials original, elevated;
    struct lapy_slot_io io = {read_ptr, write_ptr, 0};
    struct lapy_vnode_ref_counts sample;
    uint64_t self_authid = 0;
    int error = 0, attached = 0, stopped_target = 0;
    int auth_changed = 0, cred_changed = 0, moved = 0, detached = 0;
    int roots_touched = 0, target_involved = 0;
    const char *stage = "target_preflight";

    if ((error = snapshot(pid, &before))) goto done;
    ps5log_printf(PS5LOG_MARK,
                  "target_state build=%s pid=%d fd_refs=%u cred_refs=%u threads=%u suspended=%u root_old=%d jail_old=%d prison0=%d",
                  LAPY_OWNED_ID, pid, before.fd_refs, before.cred_refs,
                  before.count, before.suspended,
                  before.root && before.root != system_root,
                  before.jail && before.jail != system_root,
                  before.prison == KERNEL_ADDRESS_PRISON0);
    if (before.fd_refs != 1 ||
        before.suspended || !before.root || !before.jail ||
        before.root == system_root || before.jail == system_root ||
        before.prison != KERNEL_ADDRESS_PRISON0 ||
        !private_process_credential(&before, thread_credential_offset)) {
        error = EBUSY; goto done;
    }
    if ((error = save_credentials(pid, before.ucred, &original))) goto done;
    ps5log_printf(PS5LOG_MARK,
                  "target_preflight build=%s pid=%d private_fd=1 private_cred=1 threads=%u root_jail_alias=%d cwd_old=%d",
                  LAPY_OWNED_ID, pid, before.count,
                  before.root == before.jail,
                  before.cwd == before.root);
    if ((error = helper_checkpoint("before_attach", pid, &first, &second, 0, 0, 0))) goto done;
    stage = "tracer_authority";
    self_authid = kernel_get_ucred_authid(getpid());
    if (!self_authid) { error = EACCES; goto done; }
    auth_changed = 1; /* latch BEFORE a possibly applied write/readback failure */
    if (kernel_set_ucred_authid(getpid(), PTRACE_AUTHID) ||
        kernel_get_ucred_authid(getpid()) != PTRACE_AUTHID) {
        error = EACCES; goto done;
    }
    auth_changed = 1;
    stage = "ptrace_attach";
    /* Cancellation must not drive any operation on this non-created target. */
    target_involved = 1;
    if (ptrace(PT_ATTACH, pid, 0, 0)) {
        error = errno ? errno : EIO; goto done;
    }
    attached = 1;
    stage = "target_stop";
    if ((error = await_target_stop(pid, &before, &stopped))) {
        if (original_target_gone(pid, before.proc)) goto target_gone;
        goto held;
    }
    stopped_target = 1;
    ps5log_printf(PS5LOG_MARK,
                  "target_stopped build=%s pid=%d threads=%u private_fd=1 private_cred=1",
                  LAPY_OWNED_ID, pid, stopped.count);
    if (!private_process_credential(&stopped,
                                    thread_credential_offset)) {
        error = EBUSY; goto done;
    }
    if ((error = helper_checkpoint("target_stopped", pid, &first, &second, 0, 0, target_involved))) goto done;
    stage = "credentials";
    elevated = original;
    elevated.uid = elevated.ruid = elevated.svuid = 0;
    elevated.rgid = elevated.svgid = 0;
    elevated.ngroups = 0;
    elevated.authid = SYSTEM_AUTHID;
    memset(elevated.caps, 0xff, sizeof(elevated.caps));
    /* The old scalar SDK API began at ucred+0x83; the array begins at
     * ucred+0x80. Preserve every other attribute for verification/rollback. */
    elevated.attrs[3] |= 0x80;
    cred_changed = 1;
    if ((error = set_credentials(pid, &stopped, &elevated))) {
        (void)helper_checkpoint("before_inline_target_restore", pid, &first,
                                &second, roots_touched, moved, target_involved);
        if (set_credentials(pid, &stopped, &original)) {
            if (original_target_gone(pid, before.proc)) goto target_gone;
            goto held;
        }
        cred_changed = 0;
        goto done;
    }
    ps5log_printf(PS5LOG_MARK,
                  "credentials_applied build=%s private_cred=1 uid_zero=1 sony_full=1",
                  LAPY_OWNED_ID);
    if ((error = helper_checkpoint("credentials_applied", pid, &first, &second, 0, 0, target_involved))) goto rollback;
    stage = "first_donor";
    if ((error = start_child(&first)) ||
        (error = snapshot(first.pid, &donor))) goto rollback;
    first.proc = donor.proc; first.fd = donor.fd;
    if (donor.fd_refs != 1 || donor.root != system_root || donor.jail ||
        donor.cwd != system_root || donor.count != 1 || donor.suspended) {
        error = EPROTO; goto rollback;
    }
    if ((error = stop_child(&first, system_root))) goto rollback;
    if ((error = helper_checkpoint("first_donor_ready", pid, &first, &second, 0, 0, target_involved))) goto rollback;
    stage = "second_donor";
    if ((error = start_child(&second)) ||
        (error = snapshot(second.pid, &donor))) goto rollback;
    second.proc = donor.proc; second.fd = donor.fd;
    if (donor.fd_refs != 1 || donor.root != system_root || donor.jail ||
        donor.cwd != system_root || donor.count != 1 || donor.suspended) {
        error = EPROTO; goto rollback;
    }
    if ((error = stop_child(&second, system_root))) goto rollback;
    int snapshot_error = snapshot(pid, &confirmed);
    if (snapshot_error || !same_stop(&stopped, &confirmed)) {
        ps5log_printf(PS5LOG_ERR,
                      "target_drift build=%s pid=%d snapshot_error=%d proc_same=%d fd_same=%d cred_same=%d prison_same=%d root_same=%d jail_same=%d cwd_same=%d threads_same=%d fd_refs=%u cred_refs=%u cred_refs_before=%u threads=%u threads_before=%u suspended=%u suspended_before=%u",
                      LAPY_OWNED_ID, pid, snapshot_error,
                      !snapshot_error && confirmed.proc == stopped.proc,
                      !snapshot_error && confirmed.fd == stopped.fd,
                      !snapshot_error && confirmed.ucred == stopped.ucred,
                      !snapshot_error && confirmed.prison == stopped.prison,
                      !snapshot_error && confirmed.root == stopped.root,
                      !snapshot_error && confirmed.jail == stopped.jail,
                      !snapshot_error && confirmed.cwd == stopped.cwd,
                      !snapshot_error && confirmed.count == stopped.count &&
                          !memcmp(confirmed.threads, stopped.threads,
                                  confirmed.count * sizeof(confirmed.threads[0])),
                      snapshot_error ? 0 : confirmed.fd_refs,
                      snapshot_error ? 0 : confirmed.cred_refs,
                      stopped.cred_refs,
                      snapshot_error ? 0 : confirmed.count,
                      stopped.count,
                      snapshot_error ? 0 : confirmed.suspended,
                      stopped.suspended);
        error = snapshot_error ? snapshot_error : EBUSY;
        goto rollback;
    }
    if ((error = sample_root(system_root, "donors_ready", &sample)))
        goto rollback;
    if ((error = helper_checkpoint("before_root_transfer", pid, &first, &second, 0, 0, target_involved))) goto rollback;
    stage = "root_transfer";
    roots_touched = 1;
    enum lapy_replace_result result = lapy_replace_two_roots(
        &io, first.fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
        second.fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
        stopped.fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
        stopped.fd + KERNEL_OFFSET_FILEDESC_FD_JDIR,
        first.fd + KERNEL_OFFSET_FILEDESC_FD_JDIR,
        second.fd + KERNEL_OFFSET_FILEDESC_FD_JDIR,
        system_root, stopped.root, stopped.jail);
    if (result == LAPY_REPLACE_HELD) goto held;
    if (result != LAPY_REPLACE_COMPLETE) {
        error = EPROTO; goto rollback;
    }
    moved = 1;
    if ((error = snapshot(pid, &confirmed)) ||
        confirmed.proc != stopped.proc || confirmed.fd != stopped.fd ||
        confirmed.root != system_root || confirmed.jail != system_root ||
        confirmed.count != confirmed.suspended ||
        (error = snapshot(first.pid, &donor)) || donor.root ||
        donor.jail != stopped.root ||
        (error = snapshot(second.pid, &donor)) || donor.root ||
        donor.jail != stopped.jail) {
        error = EPROTO; goto held;
    }
    ps5log_printf(PS5LOG_MARK,
                  "roots_committed build=%s pid=%d two_native_refs=1 old_roots_received=1",
                  LAPY_OWNED_ID, pid);
    /* This target was not created by the helper. Observed cancellation
     * now holds; it never drives donor release, rollback or target detach. */
    (void)helper_checkpoint("roots_committed", pid, &first, &second, 1, 1, target_involved);
    stage = "donor_release";
    if ((error = release_child(&first)) ||
        (error = release_child(&second))) goto held;
    if ((error = sample_root(system_root, "donors_reaped", &sample)))
        goto held;
    ps5log_printf(PS5LOG_MARK,
                  "donor_balance build=%s expected_two=%d",
                  LAPY_OWNED_ID,
                  sample.hold == baseline->hold + 2 &&
                  sample.use == baseline->use + 2);
    stage = "detach";
    /* confirmed is the post-commit snapshot, whose directory owner map is
     * intentionally different from the pre-transfer stopped snapshot. */
    if (!target_identity_matches(pid, &confirmed)) {
        if (transferred_target_gone(pid, before.proc, &first, &second,
                                    system_root, baseline)) {
            attached = 0; cred_changed = 0;
            stage = "target_gone_posttransfer"; error = ESRCH; goto done;
        }
        error = ESRCH; goto held;
    }
    (void)helper_checkpoint("before_committed_target_detach", pid, &first,
                            &second, roots_touched, moved, target_involved);
    if (ptrace(PT_DETACH, pid, (caddr_t)1, 0)) {
        error = errno ? errno : EIO;
        if (transferred_target_gone(pid, before.proc, &first, &second,
                                    system_root, baseline)) {
            ps5log_printf(PS5LOG_MARK,
                          "target_gone_posttransfer build=%s pid=%d detach_error=%d donors_reaped=1 root_balanced=1",
                          LAPY_OWNED_ID, pid, error);
            attached = 0;
            cred_changed = 0;
            stage = "target_gone_posttransfer";
            error = ESRCH;
            goto done;
        }
        goto held;
    }
    attached = 0;
    detached = 1;
    /* PT_DETACH resumes the traced process; no PID-only follow-up signal. */
    stage = "complete";
    goto done;
rollback:
    (void)helper_checkpoint("before_target_rollback", pid, &first, &second,
                            roots_touched, moved, target_involved);
    if (!roots_touched && original_target_gone(pid, before.proc))
        goto target_gone;
    if (cred_changed && set_credentials(pid, &stopped, &original)) {
        ps5log_printf(PS5LOG_ERR,
                      "credential_restore_failed build=%s stage=%s pid=%d original_proc_current=%d",
                      LAPY_OWNED_ID, stage, pid,
                      kernel_get_proc(pid) == before.proc);
        if (!roots_touched && original_target_gone(pid, before.proc))
            goto target_gone;
        goto held;
    }
    cred_changed = 0;
done:
    if (target_involved)
        (void)helper_checkpoint("before_target_cleanup", pid, &first, &second,
                                roots_touched, moved, target_involved);
    if (attached) {
        if (!stopped_target) {
            if (!roots_touched && original_target_gone(pid, before.proc))
                goto target_gone;
            goto held;
        }
        if (!target_identity_matches(pid, &stopped)) {
            if (!roots_touched && original_target_gone(pid, before.proc)) goto target_gone;
            error = ESRCH; goto held;
        }
        if (ptrace(PT_DETACH, pid, (caddr_t)1, 0)) {
            if (!roots_touched && original_target_gone(pid, before.proc))
                goto target_gone;
            goto held;
        }
        attached = 0;
        detached = 1;
        /* PT_DETACH already resumed the original traced target. */
    }
    {
        int second_error = cleanup_child(&second);
        int first_error = cleanup_child(&first);
        if (second_error || first_error) {
            error = second_error ? second_error : first_error;
            goto held;
        }
    }
    if (auth_changed &&
        (kernel_set_ucred_authid(getpid(), self_authid) ||
         kernel_get_ucred_authid(getpid()) != self_authid))
        goto held;
    if (!error) error = helper_checkpoint("settled", pid, &first, &second,
                                          roots_touched, moved, target_involved);
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "request_result build=%s stage=%s error=%d pid=%d roots_moved=%d cred_changed=%d detached=%d donors_reaped=%d",
                  LAPY_OWNED_ID, stage, error, pid, moved, cred_changed,
                  detached, first.reaped && second.reaped);
    return error ? error : 0;
target_gone:
    if (roots_touched) goto held;
    ps5log_printf(PS5LOG_MARK,
                  "target_gone_pretransfer build=%s stage=%s pid=%d roots_touched=0",
                  LAPY_OWNED_ID, stage, pid);
    error = ESRCH;
    attached = 0;
    cred_changed = 0;
    goto done;
held:
    ps5log_printf(PS5LOG_ERR,
                  "daemon_held build=%s transaction=%llu stage=%s reason=ownership_or_cleanup_unproved error=%d pid=%d attached=%d target_stopped=%d roots_moved=%d first_pid=%d second_pid=%d",
                  LAPY_OWNED_ID, (unsigned long long)helper_transaction_for_log(),
                  stage, error, pid, attached,
                  stopped_target, moved, first.pid, second.pid);
    for (;;) sleep(1);
}

#if LAPY_ELF_HELPER
struct helper_app_info {
    uint32_t app_id;
    uint64_t unknown1;
    char title_id[14];
    char unknown2[0x3c];
};
extern int sceKernelGetAppInfo(pid_t pid, struct helper_app_info *info);

static int helper_transfer(int fd, void *buffer, size_t size, int writing)
{
    if (fd != (writing ? STDOUT_FILENO : STDIN_FILENO)) return EINVAL;
    enum lapy_control_result rc = lapy_control_transfer(&helper_control, buffer, size, writing);
    return rc ? (rc == LAPY_CTL_TIMEOUT ? ETIMEDOUT : EIO) : 0;
}
static int helper_message_matches(const struct lapy_elevation_message *m,
                                  const struct lapy_elevation_message *r,
                                  uint32_t kind)
{ return lapy_control_matches(m, r, kind); }

static int helper_target_title_matches(pid_t pid)
{
    struct helper_app_info info;
    memset(&info, 0, sizeof(info));
    return sceKernelGetAppInfo(pid, &info) == 0 &&
           !memcmp(info.title_id, TARGET_TITLE, sizeof(TARGET_TITLE));
}

static uint32_t helper_status_for_error(int error)
{
    if (error == ECANCELED) {
        if (helper_control.cancellation == LAPY_CTL_PROTOCOL)
            return LAPY_ELEVATION_PROTOCOL_ERROR;
        if (helper_control.cancellation == LAPY_CTL_CANCELLED)
            return LAPY_ELEVATION_CANCELLED;
        return LAPY_ELEVATION_TRANSPORT_ERROR;
    }
    if (error == ESRCH) return LAPY_ELEVATION_TARGET_MISMATCH;
    if (error == EFAULT || error == ENOTSUP) return LAPY_ELEVATION_UNAVAILABLE;
    return LAPY_ELEVATION_APPLY_FAILED;
}

static int helper_respond(uint32_t status)
{
    if (!helper_initial_bound || helper_response_attempted) return 1;
    helper_response_attempted = 1; /* Never retry a possibly partial response. */
    struct lapy_elevation_message response = helper_initial_request;
    response.kind = LAPY_ELEVATION_RESPONSE;
    response.status = status;
    if (helper_transfer(STDOUT_FILENO, &response, sizeof(response), 1)) return 1;
    return status == LAPY_ELEVATION_OK ? 0 : 1;
}
/* Bind identity before preflight can create a layout-probe donor. An initial
 * CANCEL closes this newly uploaded helper without any target or donor work. */
static int helper_receive_initial(void)
{
    struct lapy_elevation_message request = {0};
    if (helper_transfer(STDIN_FILENO, &request, sizeof(request), 0)) return EIO;
    if (request.magic != LAPY_ELEVATION_MAGIC ||
        request.version != LAPY_ELEVATION_VERSION ||
        request.size != sizeof(request) ||
        (request.kind != LAPY_ELEVATION_REQUEST && request.kind != LAPY_ELEVATION_CANCEL) ||
        request.pid <= 1 || request.capability != LAPY_ELEVATION_FILESYSTEM ||
        request.status || !request.transaction_id) return EPROTO;
    helper_initial_request = request;
    helper_initial_cancel = request.kind == LAPY_ELEVATION_CANCEL;
    request.kind = LAPY_ELEVATION_REQUEST; /* canonical immutable tuple */
    if (lapy_control_bind(&helper_control, &request)) return EPROTO;
    helper_initial_bound = 1;
    if (helper_initial_cancel) helper_control.cancellation = LAPY_CTL_CANCELLED;
    return 0;
}
static int run_helper_request(intptr_t root,
                              size_t thread_credential_offset)
{
    struct lapy_elevation_message request = helper_control.request, prepare, prepared = {0};
    struct lapy_vnode_ref_counts baseline;
    int error = 0;
    uint32_t status = LAPY_ELEVATION_OK;
    if (!helper_initial_bound || helper_initial_cancel) return 1;
    if (helper_checkpoint("preflight_complete", (pid_t)request.pid, NULL, NULL, 0, 0, 0)) {
        status = helper_status_for_error(ECANCELED); goto respond;
    }
    if (!helper_target_title_matches((pid_t)request.pid)) {
        status = LAPY_ELEVATION_TARGET_MISMATCH; goto respond;
    }
    prepare = request;
    prepare.kind = LAPY_ELEVATION_PREPARE;
    prepare.status = LAPY_ELEVATION_OK;
    if ((error = helper_transfer(STDOUT_FILENO, &prepare, sizeof(prepare), 1)))
        return 1;

    if ((error = helper_transfer(STDIN_FILENO, &prepared, sizeof(prepared), 0))) {
        status = LAPY_ELEVATION_TRANSPORT_ERROR;
        goto respond;
    }
    if (helper_message_matches(&prepared, &request, LAPY_ELEVATION_CANCEL) &&
        prepared.status == LAPY_ELEVATION_OK) {
        helper_control.prepared = 1;
        helper_control.cancellation = LAPY_CTL_CANCELLED;
        status = LAPY_ELEVATION_CANCELLED; goto respond;
    }
    if (!helper_message_matches(&prepared, &request, LAPY_ELEVATION_PREPARED)) {
        status = LAPY_ELEVATION_PROTOCOL_ERROR;
        goto respond;
    }
    if (prepared.status != LAPY_ELEVATION_OK) {
        status = LAPY_ELEVATION_PREPARE_FAILED;
        goto respond;
    }
    helper_control.prepared = 1;
    if (helper_checkpoint("prepared", (pid_t)request.pid, NULL, NULL, 0, 0, 0)) {
        status = helper_status_for_error(ECANCELED); goto respond;
    }
    /* Recheck the PID/title after the cooperative credential clone. */
    if (!helper_target_title_matches((pid_t)request.pid)) {
        status = LAPY_ELEVATION_TARGET_MISMATCH;
        goto respond;
    }
    if ((error = sample_root(root, "helper_before", &baseline))) {
        status = LAPY_ELEVATION_UNAVAILABLE;
        goto respond;
    }
    error = run_one((pid_t)request.pid, root, &baseline,
                    thread_credential_offset);
    status = error ? helper_status_for_error(error) : LAPY_ELEVATION_OK;

respond:
    /* Only pre-target work or a fully settled run_one returns here. */
    return helper_respond(status);
}
/* The guarded epilogue performs no optional logging on its admitted path.
 * A failed/partial receipt does not revoke already proved local settlement.
 * _exit terminates only this helper; it never returns to the payload host CRT. */
static _Noreturn void helper_finish(int exit_status, int error)
{
    if (helper_exit_ready != 1) {
        ps5log_printf(PS5LOG_ERR,
            "helper_held build=%s reason=exit_admission_unproved admission=%u",
            LAPY_OWNED_ID, helper_exit_ready);
        for (;;) sleep(1);
    }
    if (helper_initial_bound && !helper_response_attempted) {
        uint32_t status = error ? helper_status_for_error(error) : LAPY_ELEVATION_OK;
        (void)helper_respond(status);
    }
    _exit(exit_status);
}

/* Initial commands are handled before optional logging or native preflight.
 * A canonical REQUEST alone may continue into the existing workflow. */
static void helper_begin(void)
{
    int error = helper_receive_initial();
    if (error) helper_finish(1, error);
    if (helper_initial_cancel) helper_finish(1, ECANCELED);
}
#endif

int main(void)
{
#if LAPY_ELF_HELPER
    helper_exit_ready = 1; /* No donor or target operation has occurred. */
    uint64_t begun;
    const struct lapy_control_io control_io = {
        NULL, control_clock, control_wait, control_read, control_write};
    if (control_clock(NULL, &begun) || begun > UINT64_MAX - 120000 ||
        lapy_control_init(&helper_control, &control_io, begun + 120000))
        helper_finish(2, EIO);
#endif
#if !LAPY_ELF_HELPER
    char path[512] = {0};
#endif
#if !LAPY_SERVICE || LAPY_REQUIRE_CLIENT_RESULT
#if !LAPY_ELF_HELPER
    char result_path[512] = {0};
#endif
#endif
#if !LAPY_ELF_HELPER
    pid_t pid = -1;
    time_t started = time(NULL);
#endif
    intptr_t root = 0;
    struct snapshot self;
#if !LAPY_ELF_HELPER
    struct lapy_vnode_ref_counts baseline = {0}, final = {0};
#endif
    intptr_t self_cred_before = 0;
    size_t thread_credential_offset = 0;
    int error = 0;
#if !LAPY_ELF_HELPER
    int acknowledged = 0;
#endif
    const char *stage = "preflight";
#if LAPY_ELF_HELPER
    (void)stage;
    stage = "helper_initial";
    helper_begin();
#endif
    int logging_ready = ps5log_init_default("LAPYOWN", "lapy-owned-root-daemon") == 0;
#if !LAPY_ELF_HELPER
    if (!logging_ready) return 2;
#else
    (void)logging_ready;
#endif
    ps5log_printf(PS5LOG_MARK,
                  "daemon_start build=%s firmware=%08x title=%s service=%d require_client_result=%d max_requests=%d",
                  LAPY_OWNED_ID, kernel_get_fw_version(), TARGET_TITLE,
                  LAPY_SERVICE, LAPY_REQUIRE_CLIENT_RESULT,
                  LAPY_MAX_REQUESTS);
#if LAPY_ELF_HELPER
    if ((error = helper_checkpoint("before_helper_preflight",
             (pid_t)helper_control.request.pid, NULL, NULL, 0, 0, 0))) goto done;
#endif
    if (!kernel_get_fw_version() ||
        KERNEL_OFFSET_PROC_P_PID != PROC_PID_OFFSET ||
        !KERNEL_ADDRESS_PRISON0 ||
        !KERNEL_OFFSET_FILEDESC_FD_RDIR ||
        !KERNEL_OFFSET_FILEDESC_FD_JDIR) {
        error = ENOTSUP; goto done;
    }
    root = KERNEL_ADDRESS_ROOTVNODE ? kernel_get_root_vnode() : 0;
    if (!root) {
        intptr_t init_fd = kernel_get_proc_filedesc(1);
        if (init_fd)
            read_ptr(0, init_fd + KERNEL_OFFSET_FILEDESC_FD_RDIR, &root);
    }
    stage = "self_directory";
    if (!root || (error = snapshot(getpid(), &self))) {
        if (!error) error = EPROTO;
        goto done;
    }
    ps5log_printf(PS5LOG_MARK,
                  "self_directory build=%s private_fd=%d root_system=%d jail_null=%d cwd_root=%d cred_refs=%u threads=%u",
                  LAPY_OWNED_ID, self.fd_refs == 1, self.root == root,
                  self.jail == 0, self.cwd == root, self.cred_refs,
                  self.count);
    if (self.fd_refs != 1 || self.root != root || self.jail ||
        self.cwd != root) {
        if (!error) error = EPROTO;
        goto done;
    }
    self_cred_before = self.ucred;
    stage = "self_credential";
    if (seteuid(geteuid())) {
        error = errno ? errno : EIO;
        goto done;
    }
    if ((error = snapshot(getpid(), &self))) goto done;
    ps5log_printf(PS5LOG_MARK,
                  "self_credential_state build=%s native_clone=%d private_cred=%d cred_refs=%u",
                  LAPY_OWNED_ID, self.ucred != self_cred_before,
                  self.cred_refs == 2, self.cred_refs);
    if (
        !self.ucred || self.ucred == self_cred_before ||
        self.cred_refs != 2) {
        if (!error) error = EPROTO;
        goto done;
    }
    ps5log_printf(PS5LOG_MARK,
                  "self_credential build=%s native_clone=1 refs=2",
                  LAPY_OWNED_ID);
    stage = "group_layout";
    if ((error = validate_group_layout(self.ucred)))
        goto done;
    stage = "thread_credential_slot";
    if ((error = find_thread_credential_slot(&self,
                                             &thread_credential_offset)))
        goto done;
    ps5log_printf(PS5LOG_MARK,
                  "thread_credential_slot build=%s offset=%zu",
                  LAPY_OWNED_ID, thread_credential_offset);
    stage = "root_layout";
#if LAPY_ELF_HELPER
    if ((error = helper_checkpoint("before_layout_probe",
             (pid_t)helper_control.request.pid, NULL, NULL, 0, 0, 0))) goto done;
#endif
#if LAPY_ELF_HELPER
    helper_exit_ready = 0;
#endif
    error = validate_root_reference_layout(root, self.fd);
#if LAPY_ELF_HELPER
    /* An unresolved layout donor holds inside validation and never returns. */
    helper_exit_ready = 1;
#endif
    if (error) goto done;
#if LAPY_ELF_HELPER
    stage = "helper_request";
    helper_exit_ready = 0;
    error = run_helper_request(root, thread_credential_offset) ? EIO : 0;
    /* The request returns only pre-target or after its settled native boundary. */
    helper_exit_ready = 1;
#elif LAPY_SERVICE
    for (unsigned completed = 0;;) {
        path[0] = 0;
        pid = -1;
        acknowledged = 0;
        stage = "find_request";
        int found = 0;
        for (unsigned polls = 0; polls < 600; ++polls) {
            found = find_request(path, &pid, started);
            if (found < 0) { error = -found; goto done; }
            if (found) break;
            usleep(100000);
        }
        if (!found) continue;
        stage = "request_baseline";
        if ((error = sample_root(root, "before_request", &baseline)))
            goto done;
        error = run_one(pid, root, &baseline,
                        thread_credential_offset);
        if (path[0] && !unlink(path)) acknowledged = 1;
        else if (error == ESRCH && errno == ENOENT) acknowledged = 1;
        else if (!error) error = errno ? errno : EIO;
        ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                      "service_request build=%s pid=%d completed=%u error=%d acknowledged=%d",
                      LAPY_OWNED_ID, pid, completed, error, acknowledged);
        if (!acknowledged) goto done;
        if (error == EBUSY || error == ESRCH) {
            error = 0;
            continue;
        }
        if (error) goto done;
        ++completed;
#if LAPY_REQUIRE_CLIENT_RESULT
        stage = "client_result";
        if ((error = client_result_path(path, result_path))) goto done;
        if ((error = await_client_result(result_path))) goto done;
#endif
        if (LAPY_MAX_REQUESTS && completed >= LAPY_MAX_REQUESTS) {
            stage = "service_limit";
            goto done;
        }
    }
#else
    if ((error = sample_root(root, "baseline", &baseline))) goto done;
    stage = "find_request";
    for (unsigned polls = 0; polls < 600; ++polls) {
        int found = find_request(path, &pid, started);
        if (found < 0) { error = -found; goto done; }
        if (found) break;
        if (polls == 599) { error = ETIMEDOUT; goto done; }
        usleep(100000);
    }
    stage = "request";
    if ((error = client_result_path(path, result_path))) goto done;
    error = run_one(pid, root, &baseline, thread_credential_offset);
    if (path[0] && !unlink(path)) acknowledged = 1;
    else if (!error) error = errno ? errno : EIO;
    if (error) goto done;
    stage = "client_result";
    if ((error = await_client_result(result_path))) goto done;
    stage = "wait_title_exit";
    int title_gone = 0, root_settled = 0;
    for (unsigned i = 0; i < 600; ++i) {
        if (!title_gone) {
            errno = 0;
            title_gone = kill(pid, 0) < 0 && errno == ESRCH;
        }
        if (title_gone) {
            if ((error = read_root_counts(root, &final))) goto done;
            if (final.hold == baseline.hold &&
                final.use == baseline.use) {
                root_settled = 1;
                break;
            }
        }
        usleep(100000);
    }
    if ((error = sample_root(root, root_settled ? "title_exited" :
                            "exit_timeout", &final))) goto done;
    if (!root_settled) { error = ETIMEDOUT; goto done; }
    stage = "complete";
#endif
done:
#if LAPY_ELF_HELPER
    /* Guard, one optional terminal attempt, then self _exit. No final logger. */
    helper_finish(error ? 1 : 0, error);
#else
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "daemon_result build=%s stage=%s error=%d pid=%d acknowledged=%d root_balanced=%d",
                  LAPY_OWNED_ID, stage, error, pid, acknowledged,
                  !error && final.hold == baseline.hold &&
                  final.use == baseline.use);
    if (logging_ready)
        ps5log_close(error ? "daemon-failed" : "daemon-complete");
    return error ? 1 : 0;
#endif
}
