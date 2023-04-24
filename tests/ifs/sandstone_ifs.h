#ifndef SANDSTONE_IFS_H_INCLUDED
#define SANDSTONE_IFS_H_INCLUDED

#define PATH_SYS_IFS_BASE "/sys/devices/virtual/misc/"
#define DEFAULT_TEST_ID   1

#define BUFLEN 256 // kernel module prints at most a 64bit value

/* from linux/ifs/ifs.h: */
/*
 * Driver populated error-codes
 * 0xFD: Test timed out before completing all the chunks.
 * 0xFE: not all scan chunks were executed. Maximum forward progress retries exceeded.
 */
#define IFS_SW_TIMEOUT                          0xFD
#define IFS_SW_PARTIAL_COMPLETION               0xFE
#define IFS_SW_SCAN_CANNOT_START                0x6

#define IFS_EXIT_CANNOT_START                   -2

typedef struct {
    const char *sys_dir;
    bool image_support;
    char image_id[BUFLEN];
    char image_version[BUFLEN];
} ifs_test_t;

static bool compare_error_codes(unsigned long long code, unsigned long long expected)
{
    /* Error code is stored in 39:32 bits */
    if (((code >> 32) & 0xFF) == expected)
        return true;

    return false;
}

static bool write_file(int dfd, const char *filename, const char* value)
{
        size_t l = strlen(value);
        int fd = openat(dfd, filename, O_WRONLY | O_CLOEXEC);
        if (fd == -1)
                return false;
        if (write(fd, value, l) != l) {
                close(fd);
                return false;
        }
        close(fd);
        return true;
}

static ssize_t read_file_fd(int fd, char buf[BUFLEN])
{
        ssize_t n = read(fd, buf, BUFLEN);
        close(fd);

        /* trim newlines */
        while (n > 0 && buf[n - 1] == '\n') {
                buf[n - 1] = '\0';
                --n;
        }
        return n;
}

static ssize_t read_file(int dfd, const char *filename, char buf[BUFLEN])
{
        int fd = openat(dfd, filename, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            return fd;

        return read_file_fd(fd, buf);
}

static int open_sysfs_ifs_base(const char *sys_path)
{
        /* see if driver is loaded, otherwise try to load it */
        int sys_ifs_fd = open(sys_path, O_DIRECTORY | O_PATH | O_CLOEXEC);
        if (sys_ifs_fd < 0) {
                /* modprobe kernel driver, ignore errors entirely here */
                pid_t pid = fork();
                if (pid == 0) {
                        execl("/sbin/modprobe", "/sbin/modprobe", "-q", "intel_ifs", NULL);

                        /* don't print an error if /sbin/modprobe wasn't found, but
                           log_debug() is fine (since the parent is waiting, we can
                           write to the FILE* because it's unbuffered) */
                        log_debug("Failed to run modprobe: %s", strerror(errno));
                        _exit(errno);
                } else if (pid > 0) {
                        /* wait for child */
                        int status, ret;
                        do {
                            ret = waitpid(pid, &status, 0);
                        } while (ret < 0 && errno == EINTR);
                } else {
                        /* ignore failure to fork() -- extremely unlikely */
                }

                /* try opening again now that we've potentially modprobe'd */
                sys_ifs_fd = open(sys_path, O_DIRECTORY | O_PATH | O_CLOEXEC);
        }
    return sys_ifs_fd;
}

#endif /* SANDSTONE_IFS_H_INCLUDED */
