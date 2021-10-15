/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_p.h"

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#define PAGE_SIZE       4096U
#define PAGE_SHIFT      __builtin_ctz(PAGE_SIZE)

// proc(5) says:
// /proc/[pid]/pagemap (since Linux 2.6.25)
//    This file shows the mapping of each of the process's virtual pages
//    into physical page frames or swap area. It contains one 64-bit value
//    for each virtual page, with the bits set as follows:
//
//     63     If set, the page is present in RAM.
//
//     62     If set, the page is in swap space
//
//     61 (since Linux 3.5)
//            The page is a file-mapped page or a shared anonymous page.
//
//     60-57 (since Linux 3.11)
//            Zero
//
//     56 (since Linux 4.2)
//            The page is exclusively mapped.
//
//     55 (since Linux 3.11)
//            PTE is soft-dirty (see the kernel source file Documentation/admin-guide/mm/soft-dirty.rst).
//
//    54-0   If the page is present in RAM (bit 63), then  these  bits
//           provide the page frame number, which can be used to index
//           /proc/kpageflags and /proc/kpagecount.  If  the  page  is
//           present  in  swap  (bit  62), then bits 4-0 give the swap
//           type, and bits 54-5 encode the swap offset.

uint64_t retrieve_physical_address(const volatile void *ptr)
{
    struct CloseFd {
        int fd = -1;
        ~CloseFd() { if (fd >= 0) close(fd); }
    };

    // On Linux, the first and the last pages are always unmapped. The last
    // page needs to be for ABI reasons, as any negative values between -1 and
    // -4095 are errno codes. The first page because of NULL pointer
    // dereferences (unless MMAP_PAGE_ZERO personality is in effect, but the
    // less you know about that, the better).
    // /proc/sys/vm/mmap_min_addr also applies to non-superuser processes.

    uintptr_t v = uintptr_t(ptr);
    if (v < PAGE_SIZE || v > ~uintptr_t(PAGE_SIZE))
        return 0;

    static const CloseFd pagemap = { open("/proc/self/pagemap", O_RDONLY) };
    if (pagemap.fd == -1)
        return 0;

    uint64_t descriptor;
    off_t pagemapoffset = v / PAGE_SIZE * sizeof(uint64_t);
    int n = pread(pagemap.fd, &descriptor, sizeof(descriptor), pagemapoffset);
    if (n < 0)
        return 0;

    // bit 63: page present in RAM?
    if (int64_t(descriptor) >= 0)
        return 0;

    // is the PFN a valid number?
    descriptor &= (UINT64_C(1) << 54) - 1;
    if (!descriptor)
        return 0;

    return (descriptor << PAGE_SHIFT) + (v & (PAGE_SIZE - 1));
}
