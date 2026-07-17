/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_p.h"
#include "sandstone_utils.h"

#include <span>
#include <string>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sysexits.h>
#include <unistd.h>

#ifndef O_SYNC
#  define O_SYNC        0
#endif
#ifndef MAP_SYNC
#  define MAP_SYNC      0
#endif
#ifndef MAP_SHARED_VALIDATE
#  ifdef __linux__
#    define MAP_SHARED_VALIDATE   0x03
#  else
#    define MAP_SHARED_VALIDATE   MAP_SHARED
#  endif
#endif

void ulog_init(std::span<const char * const> args)
{
#if SANDSTONE_ULOG
    if (args.empty())
        return;

    if (args.size() != sApp->ulog_addresses.size()) {
        fprintf(stderr, "%s: --ulog requires exactly %zu file=offset arguments, got %zu\n",
                program_invocation_name, sApp->ulog_addresses.size(), args.size());
        exit(EX_USAGE);
    }

    struct OpenFd {
        std::string path;
        auto_fd fd;
    };
    struct MappedPage {
        int fd;
        ptrdiff_t page_offset;
        void *base;
    };

    std::vector<OpenFd> open_fds;
    std::vector<MappedPage> mapped_pages;

    for (size_t i = 0; i < sApp->ulog_addresses.size(); ++i) {
        const char *arg = args[i];
        const char *eq = strchr(arg, '=');
        if (!eq) {
            fprintf(stderr, "%s: --ulog: argument must be in the form FILE=OFFSET: '%s'\n",
                    program_invocation_name, arg);
            exit(EX_USAGE);
        }

        std::string filename(arg, eq - arg);
        const char *offset_str = eq + 1;

        char *endptr;
        errno = 0;
        ptrdiff_t offset = strtoll(offset_str, &endptr, 0);
        if (errno || endptr == offset_str || *endptr != '\0' || offset < 0) {
            fprintf(stderr, "%s: --ulog: invalid offset '%s'\n",
                    program_invocation_name, offset_str);
            exit(EX_USAGE);
        }

        // Open file (or reuse an already-opened fd for the same path)
        int fd = -1;
        for (auto &entry : open_fds) {
            if (entry.path == filename) {
                fd = entry.fd;
                break;
            }
        }
        if (fd == -1) {
            fd = open(filename.c_str(), O_RDWR | O_SYNC);
            if (fd == -1) {
                fprintf(stderr, "%s: --ulog: cannot open '%s': %s\n",
                        program_invocation_name, filename.c_str(), strerror(errno));
                exit(EX_NOINPUT);
            }
            open_fds.push_back({ std::move(filename), auto_fd(fd) });
        }

        // Map the region containing the offset (or reuse an already-mapped region).
        // Use 64 KB alignment: POSIX mmap accepts any multiple of the page size, and
        // Windows MapViewOfFile requires the offset to be aligned to the allocation
        // granularity (dwAllocationGranularity), which is 64 KB on all known systems.
        static constexpr ptrdiff_t MmapGranularity = 65536;
        ptrdiff_t page_offset = offset & ~(MmapGranularity - 1);
        void *page = nullptr;
        for (auto &entry : mapped_pages) {
            if (entry.fd == fd && entry.page_offset == page_offset) {
                page = entry.base;
                break;
            }
        }
        if (!page) {
            page = mmap(nullptr, MmapGranularity, PROT_READ | PROT_WRITE, MAP_SHARED_VALIDATE | MAP_SYNC, fd, off_t(page_offset));
            if (page == MAP_FAILED && errno == EOPNOTSUPP) {
                page = mmap(nullptr, MmapGranularity, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off_t(page_offset));
                if (page != MAP_FAILED)
                    fprintf(stderr, "# --ulog: MAP_SYNC not supported on '%s', falling back to MAP_SHARED\n",
                            filename.c_str());
            }
            if (page == MAP_FAILED) {
                fprintf(stderr, "%s: --ulog: mmap of '%s' at offset 0x%tx failed: %s\n",
                        program_invocation_name, open_fds.back().path.c_str(),
                        page_offset, strerror_for_mmap());
                exit(EX_OSERR);
            }
            mapped_pages.push_back({ fd, page_offset, page });
        }

        size_t offset_in_page = size_t(offset - page_offset);
        sApp->ulog_addresses[i] = reinterpret_cast<volatile uint32_t *>(static_cast<char *>(page) + offset_in_page);
    }
#endif  // SANDSTONE_ULOG
}

void ulog_update(const struct test *test)
{
#if SANDSTONE_ULOG
    if constexpr (!SandstoneConfig::HasUlogSupport)
        return;

    if (!sApp->ulog_addresses[0])
        return;

    int iteration = sApp->current_iteration_count;
    *sApp->ulog_addresses[0] = (test->shortid << 8) | (iteration < 0 ? uint8_t(-iteration) : 0);
    *sApp->ulog_addresses[1] = random_seed_low32();
    *sApp->ulog_addresses[2] = 0;
#endif // SANDSTONE_ULOG
}
