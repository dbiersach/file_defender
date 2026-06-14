/*
 * fanotify_fid_collector.c
 *
 * WORKED EXAMPLE (advanced): detecting renames, deletes, and creates.
 *
 * The primary collector (fanotify_collector.c) uses fanotify's "classic"
 * notification mode, which delivers an open file descriptor for each event.
 * That mode is perfect for reads and writes (we can read content to measure
 * entropy), but it does NOT report renames, deletes, or creates.
 *
 * Those operations matter for ransomware: the classic ".locked" attack reads a
 * file, writes an encrypted copy, then DELETES or RENAMES the original. To see
 * those events we use fanotify's newer "FID" mode (FAN_REPORT_DFID_NAME), which
 * reports the affected file by giving us:
 *   - a file handle for the PARENT DIRECTORY, and
 *   - the file's name within that directory.
 *
 * Trade-off: FID mode does not give a file descriptor, so we cannot read
 * content here (entropy is reported as 0). The originating pid IS still
 * available. In a complete system you would run BOTH collectors and merge their
 * streams: the classic collector for content/entropy, this one for the
 * rename/delete signal. The C++ daemon already counts rename and delete events
 * in its rename_delete_rate feature.
 *
 * Output is the same CSV schema as the other collectors, so it can feed the
 * daemon directly.
 *
 * Requirements: Linux kernel 5.1+ (Mint 22.3 is fine) and root
 * (CAP_SYS_ADMIN for fanotify, CAP_DAC_READ_SEARCH for open_by_handle_at).
 *
 *   sudo ./fanotify_fid_collector /home/student
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

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
        out[strcspn(out, "\n")] = '\0';
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

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1.0e9;
}

/* Map the event mask to one of the CSV operation names the daemon understands. */
static const char *operation_name(uint64_t mask) {
    if (mask & FAN_CREATE) {
        return "create";
    }
    if (mask & FAN_DELETE) {
        return "delete";
    }
    if (mask & (FAN_MOVED_FROM | FAN_MOVED_TO)) {
        return "rename";
    }
    return "other";
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <directory-to-watch>\n", argv[0]);
        fprintf(stderr, "Must be run as root, for example: sudo %s /home/student\n", argv[0]);
        return 1;
    }
    const char *watch_dir = argv[1];

    /*
     * FAN_REPORT_DFID_NAME asks the kernel to report the parent directory's
     * file handle plus the entry name for create/delete/move events.
     */
    int fan_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME | FAN_CLOEXEC, O_RDONLY);
    if (fan_fd < 0) {
        perror("fanotify_init (need root and kernel 5.1+)");
        return 1;
    }

    /*
     * We need a descriptor on the same mount to turn directory file handles back
     * into paths with open_by_handle_at().
     */
    int mount_fd = open(watch_dir, O_DIRECTORY | O_RDONLY);
    if (mount_fd < 0) {
        perror("open watch_dir");
        close(fan_fd);
        return 1;
    }

    /*
     * FID events require a filesystem mark (not a mount mark). FAN_ONDIR also
     * reports operations on directories themselves.
     */
    uint64_t mask = FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO | FAN_ONDIR;
    if (fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, mask, AT_FDCWD, watch_dir) < 0) {
        perror("fanotify_mark");
        close(fan_fd);
        close(mount_fd);
        return 1;
    }

    printf("timestamp_seconds,user_name,process_name,process_id,operation,path,bytes,byte_entropy\n");
    fflush(stdout);
    fprintf(stderr, "Watching %s for create/rename/delete (FID mode). Ctrl+C to stop.\n", watch_dir);

    const size_t watch_dir_len = strlen(watch_dir);
    struct pollfd pfd = {.fd = fan_fd, .events = POLLIN};

    for (;;) {
        if (poll(&pfd, 1, -1) < 0) {
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
            /* The fid info record follows the fixed metadata header. */
            struct fanotify_event_info_fid *fid =
                (struct fanotify_event_info_fid *)(meta + 1);

            /* We only handle records that include the entry name. */
            if (fid->hdr.info_type == FAN_EVENT_INFO_TYPE_DFID_NAME) {
                struct file_handle *handle = (struct file_handle *)fid->handle;
                /* The name is stored right after the handle bytes. */
                const char *name = (const char *)(handle->f_handle + handle->handle_bytes);

                /* Turn the parent directory handle into a path. */
                int dir_fd = open_by_handle_at(mount_fd, handle, O_PATH);
                if (dir_fd >= 0) {
                    char dir_path[PATH_MAX];
                    char fd_link[64];
                    snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%d", dir_fd);
                    ssize_t len = readlink(fd_link, dir_path, sizeof(dir_path) - 1);
                    if (len > 0) {
                        dir_path[len] = '\0';

                        /* Sized to hold dir_path + '/' + name + '\0' without
                         * truncation (both inputs are bounded by PATH_MAX). */
                        char full_path[2 * PATH_MAX];
                        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, name);

                        if (strncmp(full_path, watch_dir, watch_dir_len) == 0) {
                            char process_name[256];
                            char user_name[256];
                            read_process_name(meta->pid, process_name, sizeof(process_name));
                            read_process_user(meta->pid, user_name, sizeof(user_name));

                            /* No content fd in FID mode, so bytes and entropy are 0. */
                            printf("%.3f,%s,%s,%d,%s,%s,0,0.00\n",
                                   now_seconds(), user_name, process_name, meta->pid,
                                   operation_name(meta->mask), full_path);
                            fflush(stdout);
                        }
                    }
                    close(dir_fd);
                }
            }

            meta = FAN_EVENT_NEXT(meta, bytes_read);
        }
    }

    close(fan_fd);
    close(mount_fd);
    return 0;
}
