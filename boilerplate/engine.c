#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

#define STACK_SIZE (1024 * 1024)
#define CONTAINER_ID_LEN 32
#define CONTROL_PATH "/tmp/mini_runtime.sock"
#define LOG_DIR "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN 256
#define LOG_CHUNK_SIZE 4096
#define LOG_BUFFER_CAPACITY 128
#define DEFAULT_SOFT_LIMIT (40UL << 20)
#define DEFAULT_HARD_LIMIT (64UL << 20)

typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_HARD_LIMIT_KILLED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    size_t length;
    char data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t items[LOG_BUFFER_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} bounded_buffer_t;

typedef struct container_record {
    char id[CONTAINER_ID_LEN];
    pid_t host_pid;
    time_t started_at;
    container_state_t state;
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int exit_code;
    int exit_signal;
    int stop_requested;
    int force_kill_requested;
    int pipe_read_fd;
    pthread_t producer_thread;
    int producer_started;
    int producer_joined;
    char rootfs[PATH_MAX];
    char log_path[PATH_MAX];
    struct container_record *next;
} container_record_t;

typedef struct {
    command_kind_t kind;
    char container_id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int nice_value;
} control_request_t;

typedef struct {
    int status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int nice_value;
    int log_write_fd;
} child_config_t;

typedef struct {
    int server_fd;
    int monitor_fd;
    int should_stop;
    pthread_t logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t metadata_lock;
    pthread_cond_t metadata_cv;
    container_record_t *containers;
} supervisor_ctx_t;

typedef struct {
    supervisor_ctx_t *ctx;
    int client_fd;
} client_worker_arg_t;

typedef struct {
    supervisor_ctx_t *ctx;
    int pipe_fd;
    char container_id[CONTAINER_ID_LEN];
} log_producer_arg_t;

static volatile sig_atomic_t g_supervisor_stop = 0;
static volatile sig_atomic_t g_got_sigchld = 0;

static volatile sig_atomic_t g_run_interrupted = 0;

static void join_finished_producers(supervisor_ctx_t *ctx);

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static void supervisor_signal_handler(int signo)
{
    if (signo == SIGCHLD)
        g_got_sigchld = 1;
    else if (signo == SIGINT || signo == SIGTERM)
        g_supervisor_stop = 1;
}

static void run_client_signal_handler(int signo)
{
    if (signo == SIGINT || signo == SIGTERM)
        g_run_interrupted = 1;
}

static int write_full(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t done = 0;

    while (done < len) {
        ssize_t n = write(fd, p + done, len - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        done += (size_t)n;
    }

    return 0;
}

static int read_full(int fd, void *buf, size_t len)
{
    char *p = (char *)buf;
    size_t done = 0;

    while (done < len) {
        ssize_t n = read(fd, p + done, len - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        done += (size_t)n;
    }

    return 0;
}

static int bounded_buffer_init(bounded_buffer_t *buffer)
{
    int rc;

    memset(buffer, 0, sizeof(*buffer));

    rc = pthread_mutex_init(&buffer->mutex, NULL);
    if (rc != 0)
        return rc;

    rc = pthread_cond_init(&buffer->not_empty, NULL);
    if (rc != 0) {
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    rc = pthread_cond_init(&buffer->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&buffer->not_empty);
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    return 0;
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buffer)
{
    pthread_mutex_lock(&buffer->mutex);
    buffer->shutting_down = 1;
    pthread_cond_broadcast(&buffer->not_empty);
    pthread_cond_broadcast(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
}

static void bounded_buffer_destroy(bounded_buffer_t *buffer)
{
    pthread_cond_destroy(&buffer->not_full);
    pthread_cond_destroy(&buffer->not_empty);
    pthread_mutex_destroy(&buffer->mutex);
}

static int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    while (buffer->count == LOG_BUFFER_CAPACITY && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_full, &buffer->mutex);

    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }

    buffer->items[buffer->tail] = *item;
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;

    pthread_cond_signal(&buffer->not_empty);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

static int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    while (buffer->count == 0 && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_empty, &buffer->mutex);

    if (buffer->count == 0 && buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return 1;
    }

    *item = buffer->items[buffer->head];
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;

    pthread_cond_signal(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

static int parse_mib_flag(const char *flag,
                          const char *value,
                          unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;

    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }

    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s is too large: %s\n", flag, value);
        return -1;
    }

    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req,
                                int argc,
                                char *argv[],
                                int start_index)
{
    int i;

    for (i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long nice_value;

        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }

        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i + 1], &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i + 1], &req->hard_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i + 1], &end, 10);
            if (errno != 0 || end == argv[i + 1] || *end != '\0' ||
                nice_value < -20 || nice_value > 19) {
                fprintf(stderr,
                        "Invalid value for --nice (expected -20..19): %s\n",
                        argv[i + 1]);
                return -1;
            }
            req->nice_value = (int)nice_value;
            continue;
        }

        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }

    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "Invalid limits: soft limit cannot exceed hard limit\n");
        return -1;
    }

    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING:
        return "starting";
    case CONTAINER_RUNNING:
        return "running";
    case CONTAINER_STOPPED:
        return "stopped";
    case CONTAINER_HARD_LIMIT_KILLED:
        return "hard_limit_killed";
    case CONTAINER_KILLED:
        return "killed";
    case CONTAINER_EXITED:
        return "exited";
    default:
        return "unknown";
    }
}

static int is_active_state(container_state_t state)
{
    return state == CONTAINER_STARTING || state == CONTAINER_RUNNING;
}

static void purge_inactive_records_by_id_locked(supervisor_ctx_t *ctx, const char *id)
{
    container_record_t *cur = ctx->containers;
    container_record_t *prev = NULL;

    while (cur != NULL) {
        if (strncmp(cur->id, id, CONTAINER_ID_LEN) == 0 && !is_active_state(cur->state)) {
            container_record_t *dead = cur;
            if (prev == NULL)
                ctx->containers = cur->next;
            else
                prev->next = cur->next;
            cur = cur->next;
            free(dead);
            continue;
        }

        prev = cur;
        cur = cur->next;
    }
}

static container_record_t *find_container_by_id(supervisor_ctx_t *ctx, const char *id)
{
    container_record_t *cur = ctx->containers;

    while (cur != NULL) {
        if (strncmp(cur->id, id, CONTAINER_ID_LEN) == 0)
            return cur;
        cur = cur->next;
    }

    return NULL;
}

static container_record_t *find_container_by_pid(supervisor_ctx_t *ctx, pid_t pid)
{
    container_record_t *cur = ctx->containers;

    while (cur != NULL) {
        if (cur->host_pid == pid)
            return cur;
        cur = cur->next;
    }

    return NULL;
}

static int rootfs_in_use(supervisor_ctx_t *ctx, const char *rootfs)
{
    container_record_t *cur = ctx->containers;

    while (cur != NULL) {
        if (is_active_state(cur->state) && strcmp(cur->rootfs, rootfs) == 0)
            return 1;
        cur = cur->next;
    }

    return 0;
}

static int send_response(int fd, int status, const char *message)
{
    control_response_t resp;

    memset(&resp, 0, sizeof(resp));
    resp.status = status;
    if (message != NULL)
        snprintf(resp.message, sizeof(resp.message), "%s", message);

    return write_full(fd, &resp, sizeof(resp));
}

static int send_text(int fd, const char *text)
{
    size_t len;

    if (text == NULL)
        return 0;

    len = strlen(text);
    if (len == 0)
        return 0;

    return write_full(fd, text, len);
}

static void format_time(time_t t, char *out, size_t out_len)
{
    struct tm tm_info;

    if (localtime_r(&t, &tm_info) == NULL) {
        snprintf(out, out_len, "-");
        return;
    }

    if (strftime(out, out_len, "%Y-%m-%d %H:%M:%S", &tm_info) == 0)
        snprintf(out, out_len, "-");
}

static int lookup_log_path(supervisor_ctx_t *ctx,
                           const char *container_id,
                           char *out,
                           size_t out_len)
{
    container_record_t *rec;

    pthread_mutex_lock(&ctx->metadata_lock);
    rec = find_container_by_id(ctx, container_id);
    if (rec == NULL) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        return -1;
    }

    snprintf(out, out_len, "%s", rec->log_path);
    pthread_mutex_unlock(&ctx->metadata_lock);
    return 0;
}

static int append_log_chunk(const char *path, const char *data, size_t len)
{
    int fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0)
        return -1;

    if (write_full(fd, data, len) != 0) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;

    for (;;) {
        char log_path[PATH_MAX];
        int rc = bounded_buffer_pop(&ctx->log_buffer, &item);
        if (rc == 1)
            break;
        if (rc != 0)
            continue;

        if (lookup_log_path(ctx, item.container_id, log_path, sizeof(log_path)) != 0)
            continue;

        if (append_log_chunk(log_path, item.data, item.length) != 0) {
            fprintf(stderr,
                    "warning: failed to append logs for %s: %s\n",
                    item.container_id,
                    strerror(errno));
        }
    }

    return NULL;
}

static void *producer_thread_fn(void *arg)
{
    log_producer_arg_t *parg = (log_producer_arg_t *)arg;
    supervisor_ctx_t *ctx = parg->ctx;
    log_item_t item;

    memset(&item, 0, sizeof(item));
    snprintf(item.container_id, sizeof(item.container_id), "%s", parg->container_id);

    for (;;) {
        ssize_t n = read(parg->pipe_fd, item.data, sizeof(item.data));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (n == 0)
            break;

        item.length = (size_t)n;
        if (bounded_buffer_push(&ctx->log_buffer, &item) != 0)
            break;
    }

    close(parg->pipe_fd);
    free(parg);
    return NULL;
}

static int register_with_monitor(int monitor_fd,
                                 const char *container_id,
                                 pid_t host_pid,
                                 unsigned long soft_limit_bytes,
                                 unsigned long hard_limit_bytes)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    req.soft_limit_bytes = soft_limit_bytes;
    req.hard_limit_bytes = hard_limit_bytes;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;

    return 0;
}

static int unregister_from_monitor(int monitor_fd, const char *container_id, pid_t host_pid)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;

    return 0;
}

static int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;

    if (sethostname(cfg->id, strnlen(cfg->id, sizeof(cfg->id))) != 0) {
        perror("sethostname");
        return 1;
    }

    if (setpriority(PRIO_PROCESS, 0, cfg->nice_value) != 0) {
        perror("setpriority");
        return 1;
    }

    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        perror("mount(MS_PRIVATE)");
        return 1;
    }

    if (chdir(cfg->rootfs) != 0) {
        perror("chdir(rootfs)");
        return 1;
    }

    if (chroot(".") != 0) {
        perror("chroot");
        return 1;
    }

    if (chdir("/") != 0) {
        perror("chdir(/)");
        return 1;
    }

    if (mkdir("/proc", 0555) != 0 && errno != EEXIST) {
        perror("mkdir(/proc)");
        return 1;
    }

    if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
        perror("mount(/proc)");
        return 1;
    }

    if (dup2(cfg->log_write_fd, STDOUT_FILENO) < 0) {
        perror("dup2(stdout)");
        return 1;
    }

    if (dup2(cfg->log_write_fd, STDERR_FILENO) < 0) {
        perror("dup2(stderr)");
        return 1;
    }

    close(cfg->log_write_fd);

    execl("/bin/sh", "sh", "-c", cfg->command, (char *)NULL);
    perror("execl");
    return 127;
}

static int launch_container(supervisor_ctx_t *ctx,
                            const control_request_t *req,
                            pid_t *new_pid,
                            char *errbuf,
                            size_t errbuf_len)
{
    container_record_t *rec = NULL;
    child_config_t *cfg = NULL;
    log_producer_arg_t *parg = NULL;
    void *stack = NULL;
    int log_pipe[2] = {-1, -1};
    int flags = CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWPID | SIGCHLD;
    pid_t pid;

    if (req->container_id[0] == '\0') {
        snprintf(errbuf, errbuf_len, "container id cannot be empty");
        return -1;
    }

    if (req->rootfs[0] == '\0') {
        snprintf(errbuf, errbuf_len, "container rootfs cannot be empty");
        return -1;
    }

    if (access(req->rootfs, F_OK) != 0) {
        snprintf(errbuf, errbuf_len, "rootfs does not exist: %s", req->rootfs);
        return -1;
    }

    pthread_mutex_lock(&ctx->metadata_lock);

    {
        container_record_t *existing = find_container_by_id(ctx, req->container_id);
        if (existing != NULL && is_active_state(existing->state)) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            snprintf(errbuf, errbuf_len, "container id already exists: %s", req->container_id);
            return -1;
        }
    }

    purge_inactive_records_by_id_locked(ctx, req->container_id);

    if (find_container_by_id(ctx, req->container_id) != NULL) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        snprintf(errbuf, errbuf_len, "container id already exists: %s", req->container_id);
        return -1;
    }

    if (rootfs_in_use(ctx, req->rootfs)) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        snprintf(errbuf, errbuf_len, "rootfs already in use by a running container: %s", req->rootfs);
        return -1;
    }

    rec = (container_record_t *)calloc(1, sizeof(*rec));
    if (rec == NULL) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        snprintf(errbuf, errbuf_len, "calloc failed");
        return -1;
    }

    strncpy(rec->id, req->container_id, sizeof(rec->id) - 1);
    strncpy(rec->rootfs, req->rootfs, sizeof(rec->rootfs) - 1);
    snprintf(rec->log_path, sizeof(rec->log_path), "%s/%s.log", LOG_DIR, rec->id);
    rec->state = CONTAINER_STARTING;
    rec->started_at = time(NULL);
    rec->soft_limit_bytes = req->soft_limit_bytes;
    rec->hard_limit_bytes = req->hard_limit_bytes;
    rec->exit_code = -1;
    rec->exit_signal = -1;
    rec->pipe_read_fd = -1;

    rec->next = ctx->containers;
    ctx->containers = rec;

    pthread_mutex_unlock(&ctx->metadata_lock);

    {
        int fd = open(rec->log_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd < 0) {
            snprintf(errbuf, errbuf_len, "failed to open log file: %s", strerror(errno));
            goto fail;
        }
        close(fd);
    }

    if (pipe(log_pipe) != 0) {
        snprintf(errbuf, errbuf_len, "failed to create log pipe: %s", strerror(errno));
        goto fail;
    }

    parg = (log_producer_arg_t *)calloc(1, sizeof(*parg));
    if (parg == NULL) {
        snprintf(errbuf, errbuf_len, "calloc failed");
        goto fail;
    }
    parg->ctx = ctx;
    parg->pipe_fd = log_pipe[0];
    snprintf(parg->container_id, sizeof(parg->container_id), "%s", req->container_id);

    if (pthread_create(&rec->producer_thread, NULL, producer_thread_fn, parg) != 0) {
        snprintf(errbuf, errbuf_len, "failed to start producer thread");
        goto fail;
    }
    rec->producer_started = 1;
    rec->pipe_read_fd = log_pipe[0];
    parg = NULL;

    cfg = (child_config_t *)calloc(1, sizeof(*cfg));
    if (cfg == NULL) {
        snprintf(errbuf, errbuf_len, "calloc failed");
        goto fail;
    }

    strncpy(cfg->id, req->container_id, sizeof(cfg->id) - 1);
    strncpy(cfg->rootfs, req->rootfs, sizeof(cfg->rootfs) - 1);
    strncpy(cfg->command, req->command, sizeof(cfg->command) - 1);
    cfg->nice_value = req->nice_value;
    cfg->log_write_fd = log_pipe[1];

    stack = malloc(STACK_SIZE);
    if (stack == NULL) {
        snprintf(errbuf, errbuf_len, "malloc stack failed");
        goto fail;
    }

    pid = clone(child_fn, (char *)stack + STACK_SIZE, flags, cfg);
    if (pid < 0) {
        snprintf(errbuf, errbuf_len, "clone failed: %s", strerror(errno));
        goto fail;
    }

    close(log_pipe[1]);
    log_pipe[1] = -1;

    pthread_mutex_lock(&ctx->metadata_lock);
    rec->host_pid = pid;
    rec->state = CONTAINER_RUNNING;
    pthread_cond_broadcast(&ctx->metadata_cv);
    pthread_mutex_unlock(&ctx->metadata_lock);

    if (ctx->monitor_fd >= 0) {
        if (register_with_monitor(ctx->monitor_fd,
                                  rec->id,
                                  rec->host_pid,
                                  rec->soft_limit_bytes,
                                  rec->hard_limit_bytes) != 0) {
            fprintf(stderr,
                    "warning: monitor register failed for %s (pid=%d): %s\n",
                    rec->id,
                    (int)rec->host_pid,
                    strerror(errno));
        }
    }

    free(stack);
    free(cfg);
    *new_pid = pid;
    return 0;

fail:
    if (log_pipe[0] >= 0)
        close(log_pipe[0]);
    if (log_pipe[1] >= 0)
        close(log_pipe[1]);

    free(stack);
    free(cfg);
    free(parg);

    if (rec != NULL && rec->producer_started && !rec->producer_joined) {
        rec->producer_joined = 1;
        pthread_join(rec->producer_thread, NULL);
    }

    pthread_mutex_lock(&ctx->metadata_lock);
    if (ctx->containers == rec) {
        ctx->containers = rec->next;
    } else {
        container_record_t *cur = ctx->containers;
        while (cur != NULL && cur->next != rec)
            cur = cur->next;
        if (cur != NULL)
            cur->next = rec->next;
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    free(rec);
    return -1;
}

static void reap_children(supervisor_ctx_t *ctx)
{
    int status;
    pid_t pid;

    for (;;) {
        pid = waitpid(-1, &status, WNOHANG);
        if (pid <= 0)
            break;

        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *rec = find_container_by_pid(ctx, pid);
        if (rec != NULL) {
            if (WIFEXITED(status)) {
                if (rec->stop_requested)
                    rec->state = CONTAINER_STOPPED;
                else
                    rec->state = CONTAINER_EXITED;
                rec->exit_code = WEXITSTATUS(status);
                rec->exit_signal = 0;
            } else if (WIFSIGNALED(status)) {
                if (rec->stop_requested && !rec->force_kill_requested)
                    rec->state = CONTAINER_STOPPED;
                else if (!rec->stop_requested && WTERMSIG(status) == SIGKILL)
                    rec->state = CONTAINER_HARD_LIMIT_KILLED;
                else
                    rec->state = CONTAINER_KILLED;
                rec->exit_code = -1;
                rec->exit_signal = WTERMSIG(status);
            }

            if (ctx->monitor_fd >= 0)
                (void)unregister_from_monitor(ctx->monitor_fd, rec->id, rec->host_pid);
        }
        pthread_cond_broadcast(&ctx->metadata_cv);
        pthread_mutex_unlock(&ctx->metadata_lock);
    }

    join_finished_producers(ctx);
}

static int wait_for_container_inactive(supervisor_ctx_t *ctx,
                                       const char *id,
                                       int timeout_ms)
{
    int waited_ms = 0;

    while (waited_ms < timeout_ms) {
        container_record_t *rec;
        int active = 0;

        pthread_mutex_lock(&ctx->metadata_lock);
        rec = find_container_by_id(ctx, id);
        if (rec != NULL)
            active = is_active_state(rec->state);
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (!active)
            return 0;

        reap_children(ctx);
        join_finished_producers(ctx);
        usleep(100000);
        waited_ms += 100;
    }

    reap_children(ctx);
    join_finished_producers(ctx);

    pthread_mutex_lock(&ctx->metadata_lock);
    container_record_t *rec = find_container_by_id(ctx, id);
    int active = (rec != NULL && is_active_state(rec->state));
    pthread_mutex_unlock(&ctx->metadata_lock);

    return active ? -1 : 0;
}

static void join_finished_producers(supervisor_ctx_t *ctx)
{
    for (;;) {
        container_record_t *rec = NULL;
        pthread_t tid;
        int have_tid = 0;

        pthread_mutex_lock(&ctx->metadata_lock);
        for (rec = ctx->containers; rec != NULL; rec = rec->next) {
            if (rec->producer_started && !rec->producer_joined && !is_active_state(rec->state)) {
                rec->producer_joined = 1;
                tid = rec->producer_thread;
                have_tid = 1;
                break;
            }
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (!have_tid)
            break;

        pthread_join(tid, NULL);
    }
}

static void join_all_producers(supervisor_ctx_t *ctx)
{
    for (;;) {
        container_record_t *rec = NULL;
        pthread_t tid;
        int have_tid = 0;

        pthread_mutex_lock(&ctx->metadata_lock);
        for (rec = ctx->containers; rec != NULL; rec = rec->next) {
            if (rec->producer_started && !rec->producer_joined) {
                rec->producer_joined = 1;
                tid = rec->producer_thread;
                have_tid = 1;
                break;
            }
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (!have_tid)
            break;

        pthread_join(tid, NULL);
    }
}

static int stop_container(supervisor_ctx_t *ctx,
                          const char *id,
                          int force_after_timeout,
                          char *msg,
                          size_t msg_len)
{
    container_record_t *rec;
    pid_t pid;

    pthread_mutex_lock(&ctx->metadata_lock);

    rec = find_container_by_id(ctx, id);
    if (rec == NULL) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        snprintf(msg, msg_len, "no such container: %s", id);
        return -1;
    }

    if (!is_active_state(rec->state)) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        snprintf(msg, msg_len, "container is not running: %s", id);
        return -1;
    }

    rec->stop_requested = 1;
    pid = rec->host_pid;

    if (kill(pid, SIGTERM) != 0) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        snprintf(msg, msg_len, "failed to signal container: %s", strerror(errno));
        return -1;
    }

    pthread_mutex_unlock(&ctx->metadata_lock);

    if (wait_for_container_inactive(ctx, id, 2000) != 0 && force_after_timeout) {
        pthread_mutex_lock(&ctx->metadata_lock);
        rec = find_container_by_id(ctx, id);
        if (rec == NULL || !is_active_state(rec->state)) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            snprintf(msg, msg_len, "stop requested for %s", id);
            return 0;
        }

        rec->force_kill_requested = 1;
        pid = rec->host_pid;
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (kill(pid, SIGKILL) != 0) {
            snprintf(msg, msg_len, "failed to force kill container: %s", strerror(errno));
            return -1;
        }
    }

    if (wait_for_container_inactive(ctx, id, 2000) != 0) {
        snprintf(msg, msg_len, "container did not stop in time: %s", id);
        return -1;
    }

    snprintf(msg, msg_len, "stop requested for %s", id);
    return 0;
}

static int handle_cmd_ps(supervisor_ctx_t *ctx, int client_fd)
{
    container_record_t *cur;
    char row[512];
    char tbuf[64];

    if (send_response(client_fd, 0, "ok") != 0)
        return -1;

    if (send_text(client_fd, "ID\tPID\tSTATE\tSTARTED_AT\tSOFT_MIB\tHARD_MIB\tEXIT\tROOTFS\n") != 0)
        return -1;

    pthread_mutex_lock(&ctx->metadata_lock);
    cur = ctx->containers;
    while (cur != NULL) {
        if (!is_active_state(cur->state)) {
            cur = cur->next;
            continue;
        }

        format_time(cur->started_at, tbuf, sizeof(tbuf));
        if (cur->exit_signal > 0) {
            snprintf(row,
                     sizeof(row),
                     "%s\t%d\t%s\t%s\t%lu\t%lu\tsig:%d\t%s\n",
                     cur->id,
                     (int)cur->host_pid,
                     state_to_string(cur->state),
                     tbuf,
                     cur->soft_limit_bytes >> 20,
                     cur->hard_limit_bytes >> 20,
                     cur->exit_signal,
                     cur->rootfs);
        } else if (cur->exit_code >= 0) {
            snprintf(row,
                     sizeof(row),
                     "%s\t%d\t%s\t%s\t%lu\t%lu\texit:%d\t%s\n",
                     cur->id,
                     (int)cur->host_pid,
                     state_to_string(cur->state),
                     tbuf,
                     cur->soft_limit_bytes >> 20,
                     cur->hard_limit_bytes >> 20,
                     cur->exit_code,
                     cur->rootfs);
        } else {
            snprintf(row,
                     sizeof(row),
                     "%s\t%d\t%s\t%s\t%lu\t%lu\t-\t%s\n",
                     cur->id,
                     (int)cur->host_pid,
                     state_to_string(cur->state),
                     tbuf,
                     cur->soft_limit_bytes >> 20,
                     cur->hard_limit_bytes >> 20,
                     cur->rootfs);
        }

        if (send_text(client_fd, row) != 0) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            return -1;
        }

        cur = cur->next;
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    return 0;
}

static int handle_cmd_logs(supervisor_ctx_t *ctx,
                           int client_fd,
                           const char *container_id)
{
    container_record_t *rec;
    char log_path[PATH_MAX];
    char buf[4096];
    int fd;

    pthread_mutex_lock(&ctx->metadata_lock);
    rec = find_container_by_id(ctx, container_id);
    if (rec == NULL) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        return send_response(client_fd, 1, "container not found");
    }
    snprintf(log_path, sizeof(log_path), "%s", rec->log_path);
    pthread_mutex_unlock(&ctx->metadata_lock);

    fd = open(log_path, O_RDONLY);
    if (fd < 0)
        return send_response(client_fd, 1, "failed to open log file");

    if (send_response(client_fd, 0, "ok") != 0) {
        close(fd);
        return -1;
    }

    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        if (n == 0)
            break;
        if (write_full(client_fd, buf, (size_t)n) != 0) {
            close(fd);
            return -1;
        }
    }

    close(fd);
    return 0;
}

static int handle_cmd_start_or_run(supervisor_ctx_t *ctx,
                                   int client_fd,
                                   const control_request_t *req,
                                   int wait_for_exit)
{
    pid_t pid;
    char err[CONTROL_MESSAGE_LEN];

    memset(err, 0, sizeof(err));

    if (launch_container(ctx, req, &pid, err, sizeof(err)) != 0)
        return send_response(client_fd, 1, err);

    if (!wait_for_exit) {
        char msg[CONTROL_MESSAGE_LEN];
        snprintf(msg, sizeof(msg), "started %s (pid=%d)", req->container_id, (int)pid);
        return send_response(client_fd, 0, msg);
    }

    while (wait_for_container_inactive(ctx, req->container_id, 200) != 0) {
        continue;
    }

    pthread_mutex_lock(&ctx->metadata_lock);
    container_record_t *rec = find_container_by_id(ctx, req->container_id);
    if (rec == NULL) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        return send_response(client_fd, 1, "container vanished from metadata");
    }

    int run_status;
    if (rec->exit_signal > 0)
        run_status = 128 + rec->exit_signal;
    else if (rec->exit_code >= 0)
        run_status = rec->exit_code;
    else
        run_status = 1;

    char msg[CONTROL_MESSAGE_LEN];
    snprintf(msg,
             sizeof(msg),
             "%s finished: state=%s status=%d",
             rec->id,
             state_to_string(rec->state),
             run_status);

    pthread_mutex_unlock(&ctx->metadata_lock);
    return send_response(client_fd, run_status, msg);
}

static void *client_worker(void *arg)
{
    client_worker_arg_t *w = (client_worker_arg_t *)arg;
    supervisor_ctx_t *ctx = w->ctx;
    int cfd = w->client_fd;
    control_request_t req;

    memset(&req, 0, sizeof(req));

    if (read_full(cfd, &req, sizeof(req)) != 0) {
        close(cfd);
        free(w);
        return NULL;
    }

    switch (req.kind) {
    case CMD_START:
        (void)handle_cmd_start_or_run(ctx, cfd, &req, 0);
        break;
    case CMD_RUN:
        (void)handle_cmd_start_or_run(ctx, cfd, &req, 1);
        break;
    case CMD_PS:
        (void)handle_cmd_ps(ctx, cfd);
        break;
    case CMD_LOGS:
        (void)handle_cmd_logs(ctx, cfd, req.container_id);
        break;
    case CMD_STOP: {
        char msg[CONTROL_MESSAGE_LEN];
        int rc = stop_container(ctx, req.container_id, 1, msg, sizeof(msg));
        (void)send_response(cfd, rc == 0 ? 0 : 1, msg);
        break;
    }
    default:
        (void)send_response(cfd, 1, "unknown command");
        break;
    }

    close(cfd);
    free(w);
    return NULL;
}

static void free_container_list(container_record_t *head)
{
    while (head != NULL) {
        container_record_t *next = head->next;
        free(head);
        head = next;
    }
}

static void stop_all_running(supervisor_ctx_t *ctx)
{
    for (;;) {
        container_record_t *cur;
        char id[CONTAINER_ID_LEN] = {0};
        char msg[CONTROL_MESSAGE_LEN];

        pthread_mutex_lock(&ctx->metadata_lock);
        for (cur = ctx->containers; cur != NULL; cur = cur->next) {
            if (is_active_state(cur->state)) {
                snprintf(id, sizeof(id), "%s", cur->id);
                break;
            }
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (id[0] == '\0')
            break;

        (void)stop_container(ctx, id, 1, msg, sizeof(msg));
    }
}

static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    struct sockaddr_un addr;
    struct sigaction sa;

    (void)rootfs;

    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd = -1;
    ctx.monitor_fd = -1;

    if (mkdir(LOG_DIR, 0755) != 0 && errno != EEXIST) {
        perror("mkdir logs");
        return 1;
    }

    if (pthread_mutex_init(&ctx.metadata_lock, NULL) != 0) {
        perror("pthread_mutex_init");
        return 1;
    }

    if (pthread_cond_init(&ctx.metadata_cv, NULL) != 0) {
        perror("pthread_cond_init");
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    if (bounded_buffer_init(&ctx.log_buffer) != 0) {
        perror("bounded_buffer_init");
        pthread_cond_destroy(&ctx.metadata_cv);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    if (pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx) != 0) {
        perror("pthread_create(logger)");
        bounded_buffer_destroy(&ctx.log_buffer);
        pthread_cond_destroy(&ctx.metadata_cv);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (ctx.monitor_fd < 0) {
        fprintf(stderr,
                "warning: could not open /dev/container_monitor: %s\n",
                strerror(errno));
    }

    unlink(CONTROL_PATH);

    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) {
        perror("socket");
        goto fail;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        goto fail;
    }

    if (listen(ctx.server_fd, 32) != 0) {
        perror("listen");
        goto fail;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = supervisor_signal_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGCHLD, &sa, NULL) != 0 ||
        sigaction(SIGINT, &sa, NULL) != 0 ||
        sigaction(SIGTERM, &sa, NULL) != 0) {
        perror("sigaction");
        goto fail;
    }

    fprintf(stderr, "supervisor listening on %s\n", CONTROL_PATH);

    while (!g_supervisor_stop) {
        int cfd;
        client_worker_arg_t *arg;
        pthread_t tid;

        if (g_got_sigchld) {
            g_got_sigchld = 0;
            reap_children(&ctx);
        }

        cfd = accept(ctx.server_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            break;
        }

        arg = (client_worker_arg_t *)calloc(1, sizeof(*arg));
        if (arg == NULL) {
            close(cfd);
            continue;
        }
        arg->ctx = &ctx;
        arg->client_fd = cfd;

        if (pthread_create(&tid, NULL, client_worker, arg) != 0) {
            close(cfd);
            free(arg);
            continue;
        }

        pthread_detach(tid);
    }

    stop_all_running(&ctx);

    for (int i = 0; i < 20; ++i) {
        reap_children(&ctx);
        usleep(100000);
    }

    join_all_producers(&ctx);
    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.logger_thread, NULL);

    if (ctx.server_fd >= 0)
        close(ctx.server_fd);
    if (ctx.monitor_fd >= 0)
        close(ctx.monitor_fd);

    unlink(CONTROL_PATH);

    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);
    pthread_cond_destroy(&ctx.metadata_cv);
    free_container_list(ctx.containers);

    return 0;

fail:
    stop_all_running(&ctx);
    for (int i = 0; i < 10; ++i) {
        reap_children(&ctx);
        usleep(100000);
    }
    join_all_producers(&ctx);
    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    if (ctx.logger_thread)
        pthread_join(ctx.logger_thread, NULL);

    if (ctx.server_fd >= 0)
        close(ctx.server_fd);
    if (ctx.monitor_fd >= 0)
        close(ctx.monitor_fd);

    unlink(CONTROL_PATH);

    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);
    pthread_cond_destroy(&ctx.metadata_cv);
    free_container_list(ctx.containers);
    return 1;
}

static int send_stop_request_from_client(const char *container_id)
{
    int fd;
    struct sockaddr_un addr;
    control_request_t req;
    control_response_t resp;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (write_full(fd, &req, sizeof(req)) != 0) {
        close(fd);
        return -1;
    }

    if (read_full(fd, &resp, sizeof(resp)) != 0) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static int send_control_request(const control_request_t *req)
{
    int fd;
    struct sockaddr_un addr;
    control_response_t resp;
    char buf[4096];
    int stop_forwarded = 0;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    if (write_full(fd, req, sizeof(*req)) != 0) {
        perror("write request");
        close(fd);
        return 1;
    }

    if (req->kind == CMD_RUN) {
        struct sigaction sa, old_int, old_term;
        size_t got = 0;

        g_run_interrupted = 0;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = run_client_signal_handler;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT, &sa, &old_int);
        sigaction(SIGTERM, &sa, &old_term);

        while (got < sizeof(resp)) {
            ssize_t n = read(fd, ((char *)&resp) + got, sizeof(resp) - got);
            if (n < 0) {
                if (errno == EINTR) {
                    if (g_run_interrupted && !stop_forwarded) {
                        (void)send_stop_request_from_client(req->container_id);
                        stop_forwarded = 1;
                    }
                    continue;
                }

                perror("read response");
                sigaction(SIGINT, &old_int, NULL);
                sigaction(SIGTERM, &old_term, NULL);
                close(fd);
                return 1;
            }

            if (n == 0) {
                fprintf(stderr, "read response: unexpected EOF\n");
                sigaction(SIGINT, &old_int, NULL);
                sigaction(SIGTERM, &old_term, NULL);
                close(fd);
                return 1;
            }

            got += (size_t)n;
        }

        sigaction(SIGINT, &old_int, NULL);
        sigaction(SIGTERM, &old_term, NULL);
    } else {
        if (read_full(fd, &resp, sizeof(resp)) != 0) {
            perror("read response");
            close(fd);
            return 1;
        }
    }

    if (resp.message[0] != '\0') {
        FILE *stream = resp.status == 0 || req->kind == CMD_RUN ? stdout : stderr;
        fprintf(stream, "%s\n", resp.message);
    }

    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            perror("read payload");
            close(fd);
            return 1;
        }
        if (n == 0)
            break;
        if (write_full(STDOUT_FILENO, buf, (size_t)n) != 0) {
            close(fd);
            return 1;
        }
    }

    close(fd);

    if (req->kind == CMD_RUN)
        return resp.status;

    return resp.status == 0 ? 0 : 1;
}

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_ps(void)
{
    control_request_t req;

    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;

    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s logs <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s stop <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }

    if (strcmp(argv[1], "start") == 0)
        return cmd_start(argc, argv);

    if (strcmp(argv[1], "run") == 0)
        return cmd_run(argc, argv);

    if (strcmp(argv[1], "ps") == 0)
        return cmd_ps();

    if (strcmp(argv[1], "logs") == 0)
        return cmd_logs(argc, argv);

    if (strcmp(argv[1], "stop") == 0)
        return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}
