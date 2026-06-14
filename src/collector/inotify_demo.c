/*
 * inotify_demo.c
 *
 * A teaching comparison to the fanotify collector.
 *
 * inotify is the simplest Linux file-watching API and is great for learning,
 * but it has two limitations that matter for ransomware defense:
 *
 *   1. It does NOT tell you which process caused an event. Without the pid we
 *      cannot identify or pause the attacker.
 *   2. It does NOT give you the file content, only the name and event type, so
 *      we cannot measure byte entropy.
 *
 * It also watches a single directory per watch descriptor, so watching a whole
 * tree means manually adding a watch for every subdirectory.
 *
 * Run this next to fanotify_collector to see the difference for yourself:
 *
 *     ./inotify_demo /home/student/Documents
 *
 * This program only prints events. It never modifies files.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

#define EVENT_BUFFER_SIZE (64 * (sizeof(struct inotify_event) + NAME_MAX + 1))

/* Translate an inotify mask into readable event names. */
static void print_event_names(uint32_t mask) {
    if (mask & IN_OPEN) {
        printf("open ");
    }
    if (mask & IN_ACCESS) {
        printf("read ");
    }
    if (mask & IN_MODIFY) {
        printf("write ");
    }
    if (mask & IN_CLOSE_WRITE) {
        printf("close_write ");
    }
    if (mask & IN_MOVED_FROM) {
        printf("renamed_from ");
    }
    if (mask & IN_MOVED_TO) {
        printf("renamed_to ");
    }
    if (mask & IN_DELETE) {
        printf("delete ");
    }
    if (mask & IN_CREATE) {
        printf("create ");
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <directory-to-watch>\n", argv[0]);
        return 1;
    }
    const char *watch_dir = argv[1];

    int inotify_fd = inotify_init1(IN_CLOEXEC);
    if (inotify_fd < 0) {
        perror("inotify_init1");
        return 1;
    }

    uint32_t mask = IN_OPEN | IN_ACCESS | IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_FROM |
                    IN_MOVED_TO | IN_DELETE | IN_CREATE;

    /*
     * Note: this only watches the one directory you pass in, not its
     * subdirectories. Recursive watching with inotify means walking the tree
     * and calling inotify_add_watch for every subdirectory yourself, then
     * keeping that list updated as directories are created and removed. This is
     * one of the practical reasons fanotify (which can mark a whole mount) is a
     * better fit for this project.
     */
    int wd = inotify_add_watch(inotify_fd, watch_dir, mask);
    if (wd < 0) {
        perror("inotify_add_watch");
        close(inotify_fd);
        return 1;
    }

    fprintf(stderr, "Watching %s with inotify. Notice: no pid, no content. Ctrl+C to stop.\n",
            watch_dir);

    char buffer[EVENT_BUFFER_SIZE] __attribute__((aligned(__alignof__(struct inotify_event))));

    for (;;) {
        ssize_t length = read(inotify_fd, buffer, sizeof(buffer));
        if (length <= 0) {
            if (length < 0 && errno == EINTR) {
                continue;
            }
            break;
        }

        for (char *ptr = buffer; ptr < buffer + length;) {
            struct inotify_event *event = (struct inotify_event *)ptr;

            printf("event: ");
            print_event_names(event->mask);
            if (event->len > 0) {
                printf("name=%s", event->name);
            }
            /* There is deliberately no pid or entropy here: inotify cannot
             * provide them. Compare with the fanotify collector output. */
            printf("\n");

            ptr += sizeof(struct inotify_event) + event->len;
        }
    }

    close(inotify_fd);
    return 0;
}
