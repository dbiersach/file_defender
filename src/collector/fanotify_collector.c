/*
 * fanotify_collector.c
 *
 * Primary file-activity collector for the File Defender project.
 *
 * Why fanotify (and not inotify)?
 *   This project must (1) know WHICH process touched a file, so the daemon can
 *   pause it, and (2) read the CONTENT that was written, so it can measure byte
 *   entropy (the strongest ransomware signal). The fanotify API gives us both:
 *   every event carries the originating process id (pid) and an open file
 *   descriptor to the affected file. The simpler inotify API provides neither
 *   (see inotify_demo.c for that comparison).
 *
 * What it does:
 *   Watches a directory subtree for opens, reads, and writes. For each event it
 *   resolves the path, the process name and owning user, samples the file
 *   content to estimate Shannon byte entropy, and prints one CSV line that the
 *   C++ daemon consumes. The CSV columns match testdata/sample_events.csv:
 *
 *     timestamp_seconds,user_name,process_name,process_id,operation,path,bytes,byte_entropy
 *
 * This is a defensive monitor. It only observes file activity; it never
 * modifies, encrypts, or deletes anything.
 *
 * Requirements:
 *   - Linux (developed for Linux Mint 22.3 / kernel 6.x)
 *   - Must run as root (CAP_SYS_ADMIN), e.g.  sudo ./fanotify_collector /home/student
 *
 * Typical use (collector runs as root, daemon as your user):
 *     sudo ./fanotify_collector /home/student | ./file_defender_daemon --model model.json
 *
 * Enhancement note:
 *   This uses fanotify's "classic" notification mode, which reports opens,
 *   reads, and writes with content. Detecting renames and deletes (the classic
 *   ".locked" rename) requires fanotify's newer FID reporting mode
 *   (FAN_REPORT_DFID_NAME). That is left as a documented stretch goal so the
 *   core code stays readable.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Number of bytes sampled from each file to estimate content entropy. */
#define ENTROPY_SAMPLE_BYTES 4096

/*
 * Compute the Shannon entropy (in bits per byte, range 0.0 to 8.0) of a buffer.
 * Encrypted or compressed data is close to 8.0; plain text is typically 4-5.
 * A sudden jump toward 8.0 on many files is a hallmark of ransomware.
 */
static double shannon_entropy(const unsigned char *data, size_t length) {
    if (length == 0) {
        return 0.0;
    }

    size_t counts[256] = {0};
    for (size_t i = 0; i < length; i++) {
        counts[data[i]]++;
    }

    double entropy = 0.0;
    for (int symbol = 0; symbol < 256; symbol++) {
        if (counts[symbol] == 0) {
            continue;
        }
        double p = (double)counts[symbol] / (double)length;
        entropy -= p * log2(p);
    }
    return entropy;
}

/* Read the process name (comm) for a pid from /proc/<pid>/comm. */
static void read_process_name(int pid, char *out, size_t out_size) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", pid);

    FILE *f = fopen(proc_path, "r");
    if (f == NULL) {
        snprintf(out, out_size, "unknown");
        return;
    }
    if (fgets(out, (int)out_size, f) == NULL) {
        snprintf(out, out_size, "unknown");
    } else {
        out[strcspn(out, "\n")] = '\0'; /* strip trailing newline */
    }
    fclose(f);
}

/* Resolve the owning username of a pid via the owner of /proc/<pid>. */
static void read_process_user(int pid, char *out, size_t out_size) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);

    struct stat st;
    if (stat(proc_path, &st) != 0) {
        snprintf(out, out_size, "unknown");
        return;
    }
    struct passwd *pw = getpwuid(st.st_uid);
    if (pw != NULL) {
        snprintf(out, out_size, "%s", pw->pw_name);
    } else {
        snprintf(out, out_size, "%u", st.st_uid);
    }
}

/* Resolve the path of an event's file descriptor via /proc/self/fd. */
static int resolve_fd_path(int fd, char *out, size_t out_size) {
    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);

    ssize_t len = readlink(link_path, out, out_size - 1);
    if (len < 0) {
        return -1;
    }
    out[len] = '\0';
    return 0;
}

/* Map a fanotify event mask to a short operation name for the CSV. */
static const char *operation_name(uint64_t mask) {
    if (mask & FAN_MODIFY) {
        return "write";
    }
    if (mask & FAN_CLOSE_WRITE) {
        return "close";
    }
    if (mask & FAN_ACCESS) {
        return "read";
    }
    if (mask & FAN_OPEN) {
        return "open";
    }
    return "other";
}

/* Seconds since the epoch as a double, for the daemon's time windows. */
static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1.0e9;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <directory-to-watch>\n", argv[0]);
        fprintf(stderr, "Must be run as root, for example: sudo %s /home/student\n", argv[0]);
        return 1;
    }
    const char *watch_dir = argv[1];

    /*
     * FAN_CLASS_NOTIF = notification only (we observe, we never block or deny).
     * The event fd is opened read-only so we can sample content for entropy.
     */
    int fan_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC, O_RDONLY | O_LARGEFILE);
    if (fan_fd < 0) {
        perror("fanotify_init (are you running as root?)");
        return 1;
    }

    /*
     * Mark the whole mount that contains the watched directory. fanotify cannot
     * watch an arbitrary subtree directly, so we watch the mount and then filter
     * events by path prefix below. This still scales well because the kernel
     * does the heavy lifting.
     */
    uint64_t mask = FAN_OPEN | FAN_ACCESS | FAN_MODIFY | FAN_CLOSE_WRITE;
    if (fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, mask, AT_FDCWD, watch_dir) < 0) {
        perror("fanotify_mark");
        close(fan_fd);
        return 1;
    }

    /* Print the CSV header so the output matches testdata/sample_events.csv. */
    printf("timestamp_seconds,user_name,process_name,process_id,operation,path,bytes,byte_entropy\n");
    fflush(stdout);

    fprintf(stderr, "Watching %s (filtering the mount by this prefix). Press Ctrl+C to stop.\n",
            watch_dir);

    const size_t watch_dir_len = strlen(watch_dir);
    struct pollfd pfd = {.fd = fan_fd, .events = POLLIN};

    for (;;) {
        int ready = poll(&pfd, 1, -1);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            break;
        }

        char buffer[8192];
        ssize_t bytes_read = read(fan_fd, buffer, sizeof(buffer));
        if (bytes_read <= 0) {
            if (bytes_read < 0 && errno == EINTR) {
                continue;
            }
            break;
        }

        struct fanotify_event_metadata *meta = (struct fanotify_event_metadata *)buffer;
        while (FAN_EVENT_OK(meta, bytes_read)) {
            if (meta->vers != FANOTIFY_METADATA_VERSION) {
                fprintf(stderr, "fanotify ABI version mismatch\n");
                break;
            }
            if (meta->fd < 0) {
                meta = FAN_EVENT_NEXT(meta, bytes_read);
                continue;
            }

            char path[PATH_MAX];
            if (resolve_fd_path(meta->fd, path, sizeof(path)) == 0 &&
                strncmp(path, watch_dir, watch_dir_len) == 0) {

                /* Sample file content to estimate entropy of what was written. */
                unsigned char sample[ENTROPY_SAMPLE_BYTES];
                ssize_t sampled = pread(meta->fd, sample, sizeof(sample), 0);
                double entropy = (sampled > 0) ? shannon_entropy(sample, (size_t)sampled) : 0.0;

                struct stat st;
                unsigned long long size_bytes = 0;
                if (fstat(meta->fd, &st) == 0) {
                    size_bytes = (unsigned long long)st.st_size;
                }

                char process_name[256];
                char user_name[256];
                read_process_name(meta->pid, process_name, sizeof(process_name));
                read_process_user(meta->pid, user_name, sizeof(user_name));

                printf("%.3f,%s,%s,%d,%s,%s,%llu,%.2f\n",
                       now_seconds(), user_name, process_name, meta->pid,
                       operation_name(meta->mask), path, size_bytes, entropy);
                fflush(stdout);
            }

            close(meta->fd);
            meta = FAN_EVENT_NEXT(meta, bytes_read);
        }
    }

    close(fan_fd);
    return 0;
}
