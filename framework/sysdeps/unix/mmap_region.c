/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_p.h"
#include <sysexits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>             // for fstat()

static off_t filesize(int fd)
{
    struct stat st;
    if (fstat(fd, &st) == -1)
        return 0;
    return st.st_size;
}

struct mmap_region mmap_file(int fd)
{
    struct mmap_region r;
    r.base = NULL;
    r.size = filesize(fd);
    if (r.size != 0) {
        /* map the entire contents */
        r.base = mmap(NULL, ROUND_UP_TO_PAGE(r.size), PROT_READ, MAP_PRIVATE, fd, 0);
        if (r.base == MAP_FAILED) {
            perror("mmap:");
            exit(EX_OSERR);
        }
    }
    return r;
}

void munmap_file(struct mmap_region r)
{
    if (r.base)
        munmap(r.base, ROUND_UP_TO_PAGE(r.size));
}
