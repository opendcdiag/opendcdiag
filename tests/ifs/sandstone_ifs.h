#ifndef SANDSTONE_IFS_H_INCLUDED
#define SANDSTONE_IFS_H_INCLUDED

#define PATH_SYS_IFS_BASE "/sys/devices/virtual/misc/"
#define DEFAULT_TEST_ID 1

#define BUFLEN 256 // kernel module prints at most a 64bit value

/* from linux/ifs/ifs.h: */
/*
 * Driver populated error-codes
 * 0xFD: Test timed out before completing all the chunks.
 * 0xFE: not all scan chunks were executed. Maximum forward progress retries exceeded.
 */
#define IFS_SW_TIMEOUT                          0xFD
#define IFS_SW_PARTIAL_COMPLETION               0xFE

typedef struct {
    char image_id[BUFLEN];
    char image_version[BUFLEN];
} ifs_test_t;

static bool is_result_code_skip(unsigned long long code)
{
    switch (code) {
    case IFS_SW_TIMEOUT:
    case IFS_SW_PARTIAL_COMPLETION:
        return true;
    }

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

static ssize_t read_file_fd(int fd, char buf[static restrict BUFLEN])
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

static ssize_t read_file(int dfd, const char *filename, char buf[static restrict BUFLEN])
{
        int fd = openat(dfd, filename, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            return fd;

        return read_file_fd(fd, buf);
}

#endif /* SANDSTONE_IFS_H_INCLUDED */
