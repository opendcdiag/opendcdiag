/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "topology.h"
#include "sandstone_p.h"

#include <algorithm>
#include <map>
#include <string>
#include <vector>
#include <utility>

#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __x86_64__
#  include <cpuid.h>
#endif
#if defined(_WIN32)
#   include <windows.h>
#endif

static void update_topology(std::span<const struct cpu_info> new_cpu_info,
                            std::span<const Topology::Package> sockets = {});

struct cpu_info *cpu_info = nullptr;

static Topology &cached_topology()
{
    static Topology cached_topology = Topology({});
    return cached_topology;
}

#ifdef __linux__
namespace {
struct linux_cpu_info
{
    using Fields = std::map<std::string, std::string>;
    Fields general_fields;
    std::vector<Fields> cpu_fields;

    std::optional<uint64_t> number(int cpu_number, const char *field, int base = 0)
    {
        const Fields *f;
        if (cpu_number < 0)
            f = &general_fields;
        else if (cpu_number < cpu_fields.size())
            f = &cpu_fields[cpu_number];
        else
            return std::nullopt;

        auto it = f->find(field);
        if (it == f->end())
            return std::nullopt;

        // decode using strtoull, which skips spaces and decodes numbers with 0x prefix
        char *endptr;
        uint64_t value = strtoull(it->second.c_str(), &endptr, base);
        if (endptr > it->second.c_str())
            return value;
        return std::nullopt;
    }
};
}

static auto_fd open_sysfs_cpu_dir(int cpu)
{
    char buf[sizeof("/sys/devices/system/cpu/cpu2147483647")];
    sprintf(buf, "/sys/devices/system/cpu/cpu%d", cpu);
    return auto_fd { open(buf, O_PATH | O_CLOEXEC) };
}

static linux_cpu_info parse_proc_cpuinfo()
{
    static const char header[] = "processor\t";
    AutoClosingFile f{ fopen("/proc/cpuinfo", "r") };
    assert(f.f && "/proc must be mounted for proper operation");

    linux_cpu_info result;
    linux_cpu_info::Fields *current = &result.general_fields;

    char *line = nullptr;
    size_t len = 0;
    size_t nread;
    while ((nread = getline(&line, &len, f)) != -1) {
        const char *colon = strchr(line, ':');
        char *lineend = strchr(line, '\n');
        if (lineend)
            *lineend = '\0';
        else
            lineend = line + strlen(line);

        if (strlen(line) == 0) {
            current = &result.general_fields;
        } else if (strlen(line) >= strlen(header) && memcmp(line, header, strlen(header)) == 0) {
            // new processor, parse the number

            char *endptr = nullptr;
            uint64_t value = strtoull(colon + 1, &endptr, 0);
            if (endptr > colon) {
                if (value >= result.cpu_fields.size())
                    result.cpu_fields.resize(value + 1);
                current = &result.cpu_fields[value];
            } else {
                current = &result.general_fields;
            }
        } else if (colon != nullptr) {
            auto trimmed_string = [](const char *s, const char *e) {
                while (s != e && (*s == ' ' || *s == '\t'))
                    ++s;
                while (e - 1 != s && (e[-1] == ' ' || e[-1] == '\t'))
                    --e;

                return std::string(s, e - s);
            };

            current->insert({ trimmed_string(line, colon),
                              trimmed_string(colon + 1, lineend) });
        }
    }

    free(line);
    return result;
}

static linux_cpu_info &proc_cpuinfo()
{
    static linux_cpu_info r =
        parse_proc_cpuinfo();
    return r;
}
#endif

static bool cpu_compare(const struct cpu_info &cpu1, const struct cpu_info &cpu2)
{
    static_assert(offsetof(struct cpu_info, numa_id) + 2 == offsetof(struct cpu_info, package_id));
    static_assert(offsetof(struct cpu_info, tile_id) + 4 == offsetof(struct cpu_info, package_id));
    static_assert(offsetof(struct cpu_info, module_id) + 6 == offsetof(struct cpu_info, package_id));
    static_assert(offsetof(struct cpu_info, thread_id) + 2 == offsetof(struct cpu_info, core_id));
    static_assert(offsetof(struct cpu_info, cpu_number) + 6 == offsetof(struct cpu_info, core_id));
    static auto cpu_tuple = [](const struct cpu_info &c) {
        uint64_t h, l;
        memcpy(&h, &c.module_id, sizeof(h));
        memcpy(&l, &c.cpu_number, sizeof(l));
        return std::make_tuple(h, l);
    };

    return cpu_tuple(cpu1) < cpu_tuple(cpu2);
};

static void reorder_cpus()
{
    std::sort(cpu_info, cpu_info + num_cpus(), cpu_compare);
}

static std::vector<struct cpu_info> create_mock_topology(const char *topo)
{
    auto parse_int_and_advance = [&topo](auto *ptr) {
        char *end;
        *ptr = strtoll(topo, &end, 0);
        if (topo == end || *end == '\0') {
            topo = nullptr;
            return false;           // nothing parsed or was the last number
        }
        topo = end + 1;
        if (*end == ' ')
            return false;           // next entry
        return true;
    };

    struct cpu_info proto_cpu = { .family = 6 };
#ifdef __AVX2__
    proto_cpu.model = 0x3c;     // HSW
#else
    proto_cpu.model = 0x25;     // WSM
#endif
    std::fill(std::begin(proto_cpu.cache), std::end(proto_cpu.cache), cache_info{-1, -1});

    std::vector<struct cpu_info> mock_cpu_info;
    while (topo && *topo) {
        struct cpu_info *info = &mock_cpu_info.emplace_back(proto_cpu);
        info->cpu_number = mock_cpu_info.size() - 1;

        // mock cache too (8 kB L1, 32 kB L2, 256 kB L3)
        info->cache[0] = { 0x2000, 0x2000 };
        info->cache[1] = { 0x8000, 0x8000 };
        info->cache[2] = { 0x40000, 0x40000 };

        if (!parse_int_and_advance(&info->package_id))
            continue;
        if (!parse_int_and_advance(&info->core_id)) {
            info->module_id = info->core_id;
            continue;
        }
        info->module_id = info->core_id;
        if (!parse_int_and_advance(&info->thread_id))
            continue;
        if (!parse_int_and_advance(&info->model))
            continue;
        if (!parse_int_and_advance(&info->stepping))
            continue;
        if (!parse_int_and_advance(&info->microcode))
            continue;
    }

    return mock_cpu_info;
}

static void apply_mock_topology(const std::vector<struct cpu_info> &mock_topology, const LogicalProcessorSet &enabled_cpus)
{
    // similar to init_topology_internal()'s loop below
    int count = sApp->thread_count = std::min<int>(mock_topology.size(), enabled_cpus.count());
    for (int i = 0, curr_cpu = 0; i < count; ++i, ++curr_cpu) {
        while (!enabled_cpus.is_set(LogicalProcessor(curr_cpu))) {
            ++curr_cpu;
        }

        cpu_info[i] = mock_topology[curr_cpu];
    }
}

#ifdef __linux__
/* this is only used to read sysfs, hence inside __linux__ */
static FILE *fopenat(int dfd, const char *name)
{
    FILE *f = nullptr;
    int fd = openat(dfd, name, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return f;
    f = fdopen(fd, "r");
    if (!f)
        close(fd);
    return f;
};

static bool fill_cache_info_sysfs(struct cpu_info *info, int cpufd)
{
    FILE *f;
    char buf[256];  // size repeated in fscanf below

    // Read cache information
    for (int j = 0; ; ++j) {
        int level;

        sprintf(buf, "cache/index%d", j);
        auto_fd cachefd{openat(cpufd, buf, O_PATH | O_CLOEXEC)};
        if (cachefd == -1)
            break;

        f = fopenat(cachefd, "level");
        if (!f)
            continue;
        IGNORE_RETVAL(fscanf(f, "%d", &level));
        fclose(f);

        if (level <= int(sizeof(info->cache) / sizeof(info->cache[0]))) {
            int size;
            char suffix = '\0';
            f = fopenat(cachefd, "size");
            if (!f)
                continue;
            IGNORE_RETVAL(fscanf(f, "%d%c", &size, &suffix));
            fclose(f);

            if (suffix == 'K')
                size *= 1024;
            else if (suffix == 'M')
                size *= 1024 * 1024;

            f = fopenat(cachefd, "type");
            if (!f)
                continue;
            IGNORE_RETVAL(fscanf(f, "%255s", buf));
            fclose(f);

            if (strcmp(buf, "Instruction") == 0)
                info->cache[level - 1].cache_instruction = size;
            else if (strcmp(buf, "Data") == 0)
                info->cache[level - 1].cache_data = size;
            else
                info->cache[level - 1].cache_instruction =
                        info->cache[level - 1].cache_data = size;
        }
    }
    return true;
}

static bool fill_numa()
{
    auto parse_cpulist_range = [](const char *&ptr) {
        // parses one range (which can be a single number) and advances ptr to
        // the next range
        // see https://codebrowser.dev/linux/linux/lib/vsprintf.c.html#bitmap_list_string
        struct { int start, stop; } r;
        assert(*ptr);

        char *endptr;
        r.start = strtol(ptr, &endptr, 10);
        assert(endptr > ptr);

        if (*endptr == '-') {
            // it's a range
            r.stop = strtol(endptr + 1, &endptr, 10);
        } else {
            // it was a single number
            r.stop = r.start;
        }
        if (*endptr == ',')
            ++endptr;   // there's more
        ptr = endptr;
        return r;
    };

    int dfd = open("/sys/devices/system/node", O_RDONLY | O_DIRECTORY);
    if (dfd < 0)
        return false;

    // fdopendir takes ownership and will close dfd for us
    DIR *dir = fdopendir(dfd);
    if (!dir) [[unlikely]] {
        close(dfd);
        return false;
    }

    std::string cpulist;
    if (!cpulist.capacity())
        cpulist.reserve(16);
    while (struct dirent *entry = readdir(dir)) {
        std::string_view name(entry->d_name);
        if (!name.starts_with("node"))
            continue;
        name.remove_prefix(strlen("node"));

        char *endptr;
        long id = strtol(name.data(), &endptr, 10);
        if (endptr != name.end())
            continue;   // maybe something else starting with "node" ("node_list" ?)

        auto_fd listfd = { openat(dfd, (std::string(entry->d_name) + "/cpulist").c_str(),
                                  O_RDONLY | O_CLOEXEC) };
        if (listfd < 0)
            continue;

        cpulist.resize(cpulist.capacity());
        while (true) {
            ssize_t n = pread(listfd, &cpulist[0], cpulist.size(), 0);
            if (n <= 0) [[unlikely]]
                return false;

            if (cpulist[n - 1] == '\n') {
                // it fit
                cpulist.resize(n - 1);
                break;
            }

            // need more space
            cpulist.resize(cpulist.capacity() * 4);
        }

        // Parse the list. This will *usually* be one or two ranges.
        struct cpu_info *cpu = &cpu_info[0];
        struct cpu_info *const end = cpu_info + sApp->thread_count;
        const char *ptr = cpulist.c_str();
        while (*ptr && cpu != end) {
            auto [start, stop] = parse_cpulist_range(ptr);

            // Find the starting CPU.
            // At this point, the cpu_info array is sorted by cpu_number and,
            // if we're running over the entire system, the array index
            // matches the cpu_number too.
            if (start < sApp->thread_count && cpu_info[start].cpu_number == start) {
                cpu = &cpu_info[start];
            } else {
                // no such luck, scan forward from the last cpu we marked
                for ( ; cpu < end; ++cpu) {
                    if (cpu->cpu_number >= start)
                        break;
                }
            }

            // Mark the range until stop
            for ( ; cpu < end && cpu->cpu_number <= stop; ++cpu)
                cpu->numa_id = id;
        }
    }

    closedir(dir);
    return true;
}

static bool fill_topo_sysfs(struct cpu_info *info)
{
    FILE *f;

    auto_fd cpufd = open_sysfs_cpu_dir(info->cpu_number);
    if (cpufd < 0)
        return false;
    if (!fill_cache_info_sysfs(info, cpufd))
        return false;

    // Read the topology
    f = fopenat(cpufd, "topology/physical_package_id");
    if (!f)
        return false;
    IGNORE_RETVAL(fscanf(f, "%hd", &info->package_id));
    fclose(f);

    // Linux doesn't appear to have information about tiles

    f = fopenat(cpufd, "topology/core_id");
    if (!f)
        return false;
    IGNORE_RETVAL(fscanf(f, "%hd", &info->core_id));
    fclose(f);

    f = fopenat(cpufd, "topology/cluster_id");
    if (f) {
        // Linux calls them modules "clusters"
        IGNORE_RETVAL(fscanf(f, "%hd", &info->module_id));
        fclose(f);
    }
    if (info->module_id < 0) {
        // Override the missing information. This is probably a VM without
        // cache info or an architecture where Linux doesn't have cluster_id.
        info->module_id = info->core_id;
    }

    f = fopenat(cpufd, "topology/thread_siblings_list");
    if (!f)
        return false;
    info->thread_id = 0;
    while (!feof(f)) {
        int n;
        IGNORE_RETVAL(fscanf(f, "%d", &n));
        if (n == info->cpu_number)
            break;
        ++info->thread_id;
        fgetc(f);

        assert(info->thread_id < MAX_HWTHREADS_PER_CORE);
    }
    fclose(f);

    if (std::optional apicid = proc_cpuinfo().number(info->cpu_number, "apicid", 10))
        info->hwid = *apicid;
    return true;
}
#elif defined(_WIN32)

// The definition of CACHE_RELATIONSHIP in MinGW's headers is outdated
struct CACHE_RELATIONSHIP_2 {
    BYTE Level;
    BYTE Associativity;
    WORD LineSize;
    DWORD CacheSize;
    PROCESSOR_CACHE_TYPE Type;
    BYTE Reserved[18];
    WORD                 GroupCount;
    union {
        GROUP_AFFINITY GroupMask;
        GROUP_AFFINITY GroupMasks[ANYSIZE_ARRAY];
    };
};

// Likewise (missing GroupCount and GroupMasks)
struct NUMA_NODE_RELATIONSHIP_2 {
  DWORD NodeNumber;
  BYTE  Reserved[18];
  WORD  GroupCount;
  union {
    GROUP_AFFINITY GroupMask;
    GROUP_AFFINITY GroupMasks[ANYSIZE_ARRAY];
  } DUMMYUNIONNAME;
};

static bool detect_topology_via_os(LOGICAL_PROCESSOR_RELATIONSHIP relationships)
{
    DWORD length = 0;
    GetLogicalProcessorInformationEx(relationships, nullptr, &length);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return false;

    auto buffer = std::make_unique<unsigned char[]>(length);
    auto lpi = new (buffer.get()) SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX;

    if (!GetLogicalProcessorInformationEx(relationships, lpi, &length))
        return false;

    static constexpr unsigned CpusPerGroup =
            std::numeric_limits<KAFFINITY>::digits;

    struct cpu_info *const info = cpu_info;
    std::span infos(info, info + num_cpus());
    auto first_cpu_for_group = [infos](unsigned group) -> struct cpu_info * {
        for (struct cpu_info &info : infos) {
            if (info.cpu_number / CpusPerGroup == group)
                return &info;
        }
        return nullptr;
    };

    auto for_each_proc_in = [&](unsigned groupCount, GROUP_AFFINITY *groups, auto lambda) {
        // find the first CPU matching this group
        for (GROUP_AFFINITY &ga : std::span(groups, groupCount)) {
            struct cpu_info *info = first_cpu_for_group(ga.Group);
            if (!info)
                continue;

            KAFFINITY mask = ga.Mask;
            while (mask) {
                int n = std::countr_zero(mask);
                mask &= ~(1 << n);

                // find the CPU matching this number in this group
                for ( ; info < std::to_address(infos.end()); ++info) {
                    unsigned group = info->cpu_number / CpusPerGroup;
                    unsigned number = info->cpu_number % CpusPerGroup;
                    if (group == ga.Group && number < n)
                        continue;
                    if (group == ga.Group && number == n)
                        lambda(info++);
                    break;
                }
            }
        }
    };

    unsigned char *ptr = buffer.get();
    unsigned char *end = ptr + length;

    int pkg_id = 0;
    int module_id = 0;
    int core_id = 0;
    for ( ; ptr < end; ptr += lpi->Size) {
        lpi = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *>(ptr);
        switch (lpi->Relationship) {
        case RelationProcessorPackage:
            for_each_proc_in(lpi->Processor.GroupCount, lpi->Processor.GroupMask,
                             [&](struct cpu_info *info) {
                                 info->package_id = pkg_id;
                             }
                );
            ++pkg_id;
            module_id = 0;
            core_id = 0;
            break;

        case RelationProcessorModule:
            for_each_proc_in(lpi->Processor.GroupCount, lpi->Processor.GroupMask,
                              [&](struct cpu_info *info) {
                                  info->module_id = module_id;
                              }
                 );
            ++module_id;
            break;

        case RelationProcessorCore:
            for_each_proc_in(lpi->Processor.GroupCount, lpi->Processor.GroupMask,
                             [&, thread_id = 0](struct cpu_info *info) mutable {
                                 info->core_id = core_id;
                                 info->thread_id = thread_id++;
                             }
                );
            ++core_id;
            break;

        case RelationCache: {
            auto &cache = *reinterpret_cast<CACHE_RELATIONSHIP_2 *>(&lpi->Cache);
            for_each_proc_in(cache.GroupCount, cache.GroupMasks,
                             [&](struct cpu_info *info) {
                                 int level = cache.Level - 1;
                                 if (level >= std::size(info->cache))
                                     return;
                                 if (cache.Type == CacheUnified
                                         || cache.Type == CacheInstruction)
                                     info->cache[level].cache_instruction = cache.CacheSize;
                                 if (cache.Type == CacheUnified
                                         || cache.Type == CacheData)
                                     info->cache[level].cache_data = cache.CacheSize;
                             }
                );
            break;
        }

        case RelationNumaNodeEx: {
            // this only works for Windows 20H2 or later, otherwise GroupCount = 0
            auto &numa = *reinterpret_cast<NUMA_NODE_RELATIONSHIP_2 *>(&lpi->NumaNode);
            for_each_proc_in(numa.GroupCount, numa.GroupMasks,
                             [&](struct cpu_info *info) {
                                 info->numa_id = numa.NodeNumber;
                             }
                );
            break;
        }

        default:
            break;
        }
    }

    if (info->core_id == -1)
        return false;       // failed; we got no RelationProcessorCore results

    if (info->module_id == -1) {
        // we got no RelationProcessorModule, so "fake" them by assuming
        // core_ids == module_ids
        for (struct cpu_info &cpu : infos)
            cpu.module_id = cpu.core_id;
    }
    return true;
}

static bool fill_topo_sysfs(struct cpu_info *info)
{
    if (info != &cpu_info[0])
        return info->core_id != -1; // we only need to run once

    return detect_topology_via_os(RelationAll);
}

static void fill_numa()
{
    if (cpu_info[0].numa_id >= 0)
        return;         // already filled in above

    detect_topology_via_os(RelationNumaNodeEx);
}
#else /* __linux__ */
static auto fill_topo_sysfs = nullptr;
static void fill_numa()
{
    // unimplemented
}
#endif /* __linux__ */

#ifdef __x86_64__
static bool fill_family_cpuid(struct cpu_info *info)
{
    /*
     * EAX layout from the manual:
     *  31    28 27       20 19      16 15 14 13     8 7     4 3    0
     *  +-------+-----------+----------+-----+--------+-------+------+
     *  |XXXXXXX| Extended  | Extended |XXXXX| Family | Model | Step |
     *  |XXXXXXX| Family ID | Model ID |XXXXX|   ID   |       | ping |
     *  +-------+-----------+----------+-----+--------+-------+------+
     *
     * We need to derive "display family" and "display model" from these as per
     * SDM.
     */
    uint32_t eax, ebx, ecx, edx;
    uint8_t stepping;
    uint16_t display_family, family, model;

    eax = ebx = ecx = edx = 0;
    __cpuid(1, eax, ebx, ecx, edx);
    family = display_family = (eax >> 8) & 0xf;
    if (family == 0xf) display_family += (eax >> 20) & 0xff;
    model = (eax >> 4) & 0xf;
    if (family == 0xf || family == 0x6)
        model += ((eax >> (16-4)) & 0xf0);
    stepping = eax & 0xf;

    info->family = display_family;
    info->model = model;
    info->stepping = stepping;

    // Report a warning if the information on a socket differs from socket 0.
    if (info == cpu_info)
        return true;        // first logical processor, nothing to compare to

    assert(size_t(info - cpu_info) < size_t(num_cpus()));
    if (info->package_id == info[-1].package_id)
        return true;        // same socket, so if there's a discrepancy it's already reported

    if (__builtin_expect(cpu_info[0].family != display_family || cpu_info[0].model != model ||
                         cpu_info[0].stepping != stepping, false)) {
        /* print reference cpu info once */
        static bool report_cpu0_once = false;
        if (!report_cpu0_once) {
            fprintf(stderr, "WARNING: Inconsistent CPU information detected. "
                       "Reference socket %d is family 0x%02x, model 0x%02x, stepping 0x%02x\n",
                    cpu_info[0].package_id, cpu_info[0].family, cpu_info[0].model, cpu_info[0].stepping);
            report_cpu0_once = true;
        }
        fprintf(stderr, "WARNING: CPU %d on socket %d differs from socket %d: family 0x%02x "
                        "model 0x%02x, stepping 0x%02x.\n", info->cpu_number, info->package_id,
                cpu_info[0].package_id, display_family, model, stepping);
    }

    return true;
}

static bool fill_cache_info_cpuid(struct cpu_info *info, uint32_t *max_cpus_sharing_l2)
{
    /* since info->cache is statically allocated */
    static int max_levels = sizeof(info->cache) / sizeof(*info->cache);

    /* read the leaf 0x04: deterministic cache parameters */
    uint32_t a, b, c, d; /* eax, ebx, ecx, edx */
    int subleaf = 0; /* incrementing subleaf index */

    do {
        int ways, parts, line_sz, sets;
        int level, size;

        __cpuid_count(0x04, subleaf, a, b, c, d);

        if (!(a & 0xf)) break; /* first 4 bits eax are 0 -- no more info */

        level = (a >> 5) & 0x7; /* eax 3 bits 07:05 */
        if (level > max_levels) return 1; /* this is fatal. */

        /* cache topology */
        ways = ((b >> 22) & ((1 << 9) - 1)) + 1; /* ebx 9 bits 31:22 plus 1 */
        parts = ((b >> 12) & ((1 << 9) - 1)) + 1; /* ebx 9 bits 21:12 plus 1 */
        line_sz = (b & ((1 << 12) - 1)) + 1; /* ebx 12 bits 11:0 plus 1*/
        sets = c + 1; /* entire ecx plus 1 */

        size = ways * parts * line_sz * sets;
        if (level == 2 && max_cpus_sharing_l2)
            *max_cpus_sharing_l2 = ((a >> 14) & ((1 << 11) - 1)) + 1; /* eax 11 bits 25:14 plus 1 */

        switch (a & 0xf) { /* first four eax bits are type */
            case 1: /* data */
                info->cache[level - 1].cache_data = size;
                break;
            case 2: /* instruction */
                info->cache[level - 1].cache_instruction = size;
                break;
            case 3: /* unified */
                info->cache[level - 1].cache_data =
                    info->cache[level - 1].cache_instruction =
                    size;
                break;
            default: /* at this point it's > 3, i.e. a reserved value. */
                return 1;
        }
        subleaf++;

    } while (a);

    return true;
}

static bool fill_topo_cpuid(struct cpu_info *info)
{
    enum Domain {
        Invalid = 0,
        Logical = 1,
        Core = 2,
        Module = 3,
        Tile = 4,
        Die = 5,
        DieGrp = 6,
    };
    // we only want up to Tile
    constexpr Domain Package = Domain(Domain::Tile + 1);

    int curr_cpu = info->cpu_number;
    uint32_t a, b, c, apicid;
    uint32_t max_cpus_sharing_l2 = 0;

    if (curr_cpu < 0)
        return false;
    if (!fill_cache_info_cpuid(info, &max_cpus_sharing_l2))
        return false;

    static int8_t leaf;
    static std::array<uint8_t, Package> widthsarray;
    auto width = [](Domain domain) -> uint8_t & { return widthsarray[domain - 1]; };

    if (leaf < 0)
        return false;
    if (!leaf) {
        __cpuid(0, a, b, c, apicid);
        leaf = -1;
        if (a >= 0x1f)
            leaf = 0x1f;        // use V2 Extended Topology
        else if (a >= 0x0b)
            leaf = 0x0b;        // use regular Extended Topology
        else
            return false;

        int subleaf = 0;
        __cpuid_count(leaf, subleaf, a, b, c, apicid);

        // extract the domain levels
        while (b) {
            Domain domain = Domain((c >> 8) & 0xff);
            a &= 0xf;
            switch (domain) {
            case Domain::Invalid:
                __builtin_unreachable();
                break;
            case Domain::Logical:
            case Domain::Core:
            case Domain::Module:
            case Domain::Tile:
                width(domain) = a;
                break;

            case Domain::Die:
            case Domain::DieGrp:
                // ignore
                break;
            }

            // the package shift is implied by the largest shift
            width(Package) = std::max(uint8_t(a), width(Package));

            // get next level
            subleaf++;
            __cpuid_count(leaf, subleaf, a, b, c, apicid);
        }

        if (width(Domain::Logical) == 0 || width(Domain::Core) == 0
                || width(Package) == 0) [[unlikely]] {
            // no information on CPUID leaf; fallback to OS
            leaf = -1;
            return false;
        }
    } else {
        // just get this processor's APIC ID
        __cpuid_count(leaf, 0, a, b, c, apicid);
    }

    // process the widths
    auto extract = [&](uint32_t start, uint32_t end) {
        uint32_t value = apicid;
        if (end < 32)
            value &= ~(~0U << end);
        value >>= start;
        return value;
    };

    info->hwid = apicid;
    info->package_id = extract(width(Package), -1);
    info->thread_id = extract(0, width(Domain::Logical));
    info->core_id = extract(width(Domain::Logical), width(Package));

    uint32_t next = width(Domain::Core);
    if (width(Domain::Module)) {
        info->module_id = extract(next, width(Package));
        next = width(Domain::Module);
    } else if (max_cpus_sharing_l2) {
        // CPUID didn't provide module information, we assume that a module is
        // a group of cores that share L2 cache. That is true for Intel parts,
        // and is what Linux implements (how Windows determines how to return
        // RelationProcessorModule is a guess). Intel docs say "the nearest
        // power-of-2 not smaller than".
        int l2_sharing_width = 31 - std::countl_zero(max_cpus_sharing_l2);
        info->module_id = extract(l2_sharing_width, width(Package));
    } else {
        // if neither CPUID nor cache provide module information, we assume module == core
        info->module_id = info->core_id;
    }
    if (width(Domain::Tile)) {
        info->tile_id = extract(next, width(Package));
        next = width(Domain::Tile);
    }

    return true;
}

static bool fill_ucode_msr(struct cpu_info *info)
{
    uint64_t ucode = 0;

    if (!read_msr(info->cpu_number, 0x8B, &ucode))
        return false;
    info->microcode = (uint32_t)(ucode >> 32);

    return true;
}
#else
constexpr auto fill_family_cpuid = nullptr;
constexpr auto fill_ucode_msr = nullptr;
constexpr auto fill_topo_cpuid = nullptr;
#endif // x86-64

static bool fill_ucode_sysfs(struct cpu_info *info)
{
#ifdef __linux__
    FILE *f;
    auto_fd cpufd { open_sysfs_cpu_dir(info->cpu_number) };
    if (cpufd < 0)
        return false;

    // Read Microcode version
    f = fopenat(cpufd, "microcode/version");
    if (f) {
        IGNORE_RETVAL(fscanf(f, "%" PRIx64 , &info->microcode));
        fclose(f);
    } else {
        // Prior to Linux 4.19, the microcode/version sysfs node was not world-readable
        if (auto opt = proc_cpuinfo().number(info->cpu_number, "microcode"))
            info->microcode = *opt;
    }
    return info->microcode != 0;
#elif defined(_WIN32)
    HKEY hKey = (HKEY)-1;
    LONG lResult = ERROR_SUCCESS;
    bool ok = false;

    // Reads from CentralProcessor\0 - this is the documented way to get the uCode version generically
    // We can read the value all the time or read once and cache it and return it - we choose the latter here
    lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey);

    if (lResult == ERROR_SUCCESS)
    {
        // If we are here, we could open the key and our handle should be golden to use
        BYTE keybuf[MAX_PATH]; /* overkill */
        DWORD keysize = sizeof(keybuf);

        memset(keybuf, 0, keysize);

        lResult = RegQueryValueExA(hKey, "Update Revision", nullptr, nullptr, keybuf, &keysize);

        if (lResult == ERROR_SUCCESS)
        {
            // If we got here, we can proceed to read the value from the registry
            if (keysize >= 8)
            {
                // We expect to read at least 8 bytes
                uint32_t update_revision;

                // Extract uCode Revision - first 4 bytes are skipped (8 bytes total, little-endian)
                //
                // See C:\>reg query HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0
                memcpy(&update_revision, (unsigned char*)keybuf + 4, sizeof(uint32_t));

                info->microcode = (uint32_t)update_revision;

                ok = true;
            }
        }
    }

    if (hKey)
    {
        RegCloseKey(hKey);
    }

    return ok;
#else
    return false;
#endif /* __linux__ */
}

#ifdef __x86_64__
static bool fill_ppin_msr(struct cpu_info *info)
{
    info->ppin = 0;
    return read_msr(info->cpu_number, 0x4F, &info->ppin); /* MSR_PPIN */
}
#else
constexpr auto fill_ppin_msr = nullptr;
#endif // __x86_64__

static bool fill_ppin_sysfs(struct cpu_info *info)
{
#if defined(__linux__) && defined(__x86_64__)
    auto_fd cpufd = open_sysfs_cpu_dir(info->cpu_number);
    if (cpufd < 0)
        return false;

    if (AutoClosingFile f { fopenat(cpufd, "topology/ppin") }) {
        if (fscanf(f, "%" PRIx64, &info->ppin) > 0)
            return true;
    }
#endif

    return false;
}

template <auto &fnArray> static bool try_detection(struct cpu_info *cpu)
{
    using DetectorFunction = std::decay_t<decltype(fnArray[0])>;
    if (std::size(fnArray) > 0) {
        if (std::size(fnArray) == 1) {
            // no need to cache, there's only one implementation
            DetectorFunction fn = fnArray[0];
            return fn ? fn(cpu) : true;
        }

        static DetectorFunction cached_fn = nullptr;
        if (cached_fn)
            return cached_fn(cpu);

        for (DetectorFunction fn : fnArray) {
            if (!fn)
                continue;
            if (fn(cpu)) {
                cached_fn = fn;
                return true;
            }
        }
    }
    return false;
}

typedef bool (* fill_family_func)(struct cpu_info *);
typedef bool (* fill_ppin_func)(struct cpu_info *);
typedef bool (* fill_ucode_func)(struct cpu_info *);
typedef bool (* fill_topo_func)(struct cpu_info *);

static const fill_family_func family_impls[] = { fill_family_cpuid };
static const fill_ppin_func ppin_impls[] = { fill_ppin_sysfs, fill_ppin_msr };
/* prefer sysfs, fallback to MSR. the latter is not reliable and may require
 * root. */
static const fill_ucode_func ucode_impls[] = { fill_ucode_sysfs, fill_ucode_msr };
/* prefer CPUID, fallback to sysfs. */
static const fill_topo_func topo_impls[] = { fill_topo_cpuid, fill_topo_sysfs };

void apply_cpuset_param(char *param)
{
    struct MatchCpuInfoByCpuNumber {
        int cpu_number;
        bool operator()(const struct cpu_info &cpu)
        { return cpu.cpu_number == cpu_number; }
    };

    if (SandstoneConfig::RestrictedCommandLine)
        return;

    std::span<struct cpu_info> old_cpu_info(cpu_info, sApp->thread_count);
    std::vector<struct cpu_info> new_cpu_info;
    int total_matches = 0;

    LogicalProcessorSet result = {};
    new_cpu_info.reserve(old_cpu_info.size());

    bool add = true;
    if (*param == '!') {
        // we're removing from the existing set
        new_cpu_info = { old_cpu_info.begin(), old_cpu_info.end() };
        add = false;
        ++param;
    }

    std::string p = param;
    for (char *arg = strtok(p.data(), ","); arg; arg = strtok(nullptr, ",")) {
        const char *orig_arg = arg;
        auto parse_int = [&arg, orig_arg]() {
            errno = 0;
            char *endptr = arg;
            long n = strtol(arg, &endptr, 0);
            if (n == 0 && errno) {
                fprintf(stderr, "%s: error: Invalid CPU set parameter: %s (%m)\n",
                        program_invocation_name, orig_arg);
                exit(EX_USAGE);
            }
            if (n != int(n)) {
                fprintf(stderr, "%s: error: Invalid CPU set parameter: %s (out of range)\n",
                        program_invocation_name, orig_arg);
                exit(EX_USAGE);
            }
            arg = endptr;       // advance
            return int(n);
        };
        auto apply_to_set = [&](const struct cpu_info &cpu) {
            LogicalProcessor lp = LogicalProcessor(cpu.cpu_number);
            if (result.is_set(lp))
                return;

            if (add) {
                auto it = std::lower_bound(new_cpu_info.begin(), new_cpu_info.end(), cpu, cpu_compare);
                new_cpu_info.insert(it, cpu);
            } else {
                auto it = std::find_if(new_cpu_info.begin(), new_cpu_info.end(),
                                       MatchCpuInfoByCpuNumber(cpu.cpu_number));
                if (it == new_cpu_info.end())
                    return;
                new_cpu_info.erase(it);
            }
            result.set(lp);
            ++total_matches;
        };

        char c = *arg;
        if (c >= '0' && c <= '9') {
            // logical processor number
            int cpu_number = parse_int();
            if (*arg != '\0') {
                fprintf(stderr, "%s: error: Invalid CPU set parameter: %s (could not parse)\n",
                        program_invocation_name, orig_arg);
                exit(EX_USAGE);
            }

            auto cpu = std::find_if(old_cpu_info.begin(), old_cpu_info.end(),
                                    MatchCpuInfoByCpuNumber(cpu_number));
            if (cpu == old_cpu_info.end()) {
                fprintf(stderr, "%s: error: Invalid CPU set parameter: %s (no such logical processor)\n",
                        program_invocation_name, orig_arg);
                exit(EX_USAGE);
            }
            apply_to_set(*cpu);
        } else if ( strcmp( p.data(), "odd") == 0 || strcmp( p.data(), "even") == 0){
            int desired_remainder = strcmp(p.data(), "odd") == 0 ? 1 : 0;
            for (struct cpu_info &cpu : old_cpu_info)
            {
                if (cpu.cpu_number % 2 == desired_remainder)
                    apply_to_set(cpu);
            }
        } else if (c >= 'a' && c <= 'z') {
            // topology search
            auto set_if_unset = [orig_arg](int n, int &where, const char *what) {
                if (where != -1) {
                    fprintf(stderr, "%s: error: Invalid CPU set parameter: %s (%s already defined)\n",
                            program_invocation_name, orig_arg, what);
                    exit(EX_USAGE);
                }
                where = n;
            };

            int package = -1, core = -1, thread = -1;
            do {
                ++arg;
                int n = parse_int();
                switch (c) {
                case 'p':
                    set_if_unset(n, package, "package");
                    break;
                case 'c':
                    set_if_unset(n, core, "core");
                    break;
                case 't':
                    set_if_unset(n, thread, "thread");
                    break;
                default:
                    fprintf(stderr, "%s: error: Invalid CPU selection type \"%c\"; valid types are "
                                    "'p' (package/socket ID), 'c' (core), 't' (thread)\n", program_invocation_name, c);
                    exit(EX_USAGE);
                }
                c = *arg;
            } while (c != '\0');

            int match_count = 0;
            for (struct cpu_info &cpu : old_cpu_info) {
                if (package != -1 && cpu.package_id != package)
                    continue;
                if (core != -1 && cpu.core_id != core)
                    continue;
                if (thread != -1 && cpu.thread_id != thread)
                    continue;
                apply_to_set(cpu);
                ++match_count;
            }

            if (match_count == 0)
                fprintf(stderr, "%s: warning: CPU selection '%s' matched nothing\n",
                        program_invocation_name, orig_arg);
        }
    }

    if (total_matches == 0) {
        fprintf(stderr, "%s: error: --cpuset matched nothing, this is probably not what you wanted.\n",
                program_invocation_name);
        exit(EX_USAGE);
    }
    if (!add && new_cpu_info.size() == 0) {
        fprintf(stderr, "%s: error: negated --cpuset matched everything, this is probably not "
                        "what you wanted.\n", program_invocation_name);
        exit(EX_USAGE);
    }

    assert(total_matches == result.count());
    if (add)
        assert(total_matches == new_cpu_info.size());
    else
        assert(total_matches == old_cpu_info.size() - new_cpu_info.size());
    update_topology(new_cpu_info);
}

static void init_topology_internal(const LogicalProcessorSet &enabled_cpus)
{
    assert(sApp->thread_count == enabled_cpus.count());
    cpu_info = sApp->shmem->cpu_info;

    if (SandstoneConfig::Debug) {
        static auto mock_topology = create_mock_topology(getenv("SANDSTONE_MOCK_TOPOLOGY"));
        if (mock_topology.size())
            return apply_mock_topology(mock_topology, enabled_cpus);
    }

    int curr_cpu = 0;
    for (int i = 0; i < sApp->thread_count; ++i, ++curr_cpu) {
        auto lp = LogicalProcessor(curr_cpu);
        while (!enabled_cpus.is_set(lp)) {
            lp = LogicalProcessor(++curr_cpu);
        }

        /* fill everything with -1 to indicate n/a and set the OS cpu id. */
        auto info = cpu_info + i;
        info->cpu_number = curr_cpu;
        info->package_id = -1;
        info->numa_id = -1;
        info->tile_id = -1;
        info->module_id = -1;
        info->core_id = -1;
        info->thread_id = -1;
        info->hwid = -1;

        std::fill(std::begin(info->cache), std::end(info->cache), cache_info{-1, -1});
    }

    auto detect = [](void *ptr) -> void * {
        const auto & enabled_cpus = *static_cast<const LogicalProcessorSet *>(ptr);
        int curr_cpu = 0;
        for (int i = 0; i < sApp->thread_count; ++i, ++curr_cpu) {
            auto lp = LogicalProcessor(curr_cpu);
            while (!enabled_cpus.is_set(lp)) {
                lp = LogicalProcessor(++curr_cpu);
            }

            pin_to_logical_processor(lp);
            try_detection<topo_impls>(&cpu_info[i]);
            try_detection<family_impls>(&cpu_info[i]);
            try_detection<ppin_impls>(&cpu_info[i]);
            try_detection<ucode_impls>(&cpu_info[i]);
        }
        return nullptr;
    };

    pthread_t detection_thread;
    pthread_create(&detection_thread, nullptr, detect, const_cast<LogicalProcessorSet *>(&enabled_cpus));
    pthread_join(detection_thread, nullptr);

    fill_numa();
}

static void populate_core_group(Topology::CoreGrouping *group, const Topology::Thread *begin,
                                const Topology::Thread *end)
{
    // fill in the threads
    auto fill_in_threads = [&](auto &where, auto what) {
        const Topology::Thread *first = begin;
        const Topology::Thread *last = first;
        for ( ; last != end; ++last) {
            if (last->*what == first->*what)
                continue;
            where.push_back({ { first, last } });
            first = last;
        }
        // add any remainders
        where.push_back({ { first, end } });
    };

    fill_in_threads(group->cores, &Topology::Thread::core_id);
    // fill_in_threads(group->modules, &Topology::Thread::module_id);
}

static Topology build_topology()
{
    struct cpu_info *info = cpu_info;
    const struct cpu_info *const end = cpu_info + num_cpus();

    std::vector<Topology::Package> packages;
    if (int max_package_id = end[-1].package_id; max_package_id >= 0)
        packages.reserve(max_package_id + 1);
    else
        return Topology({});

    while (info != end) {
        if (info->package_id < 0 || info->core_id < 0 || info->thread_id < 0)
            return Topology({});

        Topology::Package *pkg = &packages.emplace_back();

        // scan forward to the end of this package
        Topology::Thread *first = info;
        Topology::Thread *numafirst = info;
        int core_count = 0;
        for (int last_core_id = -1; info != end; ++info) {
            if (info->core_id < 0 || info->thread_id < 0)
                return Topology({});
            if (info->package_id != first->package_id)
                break;
            if (info->core_id != last_core_id) {
                ++core_count;
                last_core_id = info->core_id;
            }
            if (info->numa_id != numafirst->numa_id) {
                // start of a new NUMA node inside of this Package
                populate_core_group(&pkg->numa_domains.emplace_back(), numafirst, info);
                numafirst = info;
            }
        }

        // populate the full core
        pkg->cores.reserve(core_count + 1);
        populate_core_group(pkg, first, info);

        // populate the last NUMA node, which may be the only one too
        Topology::NumaNode *numa = &pkg->numa_domains.emplace_back();
        if (pkg->numa_domains.size() == 1)
            numa->CoreGrouping::operator=(*pkg);    // just copy the Package
        else
            populate_core_group(numa, numafirst, info);
    }

    return Topology(std::move(packages));
}

const Topology &Topology::topology()
{
    return cached_topology();
}

Topology::Data Topology::clone() const
{
    Data result;
    result.all_threads.assign(cpu_info, cpu_info + num_cpus());
    result.packages = packages;

    // now update all spans to point to the data we carry
    for (Package &pkg : result.packages) {
        for (Core &core : pkg.cores) {
            int starting_cpu = core.threads.front().cpu();
            int ending_cpu = core.threads.back().cpu();
            core.threads = { result.all_threads.data() + starting_cpu,
                             result.all_threads.data() + ending_cpu + 1 };
        }
    }
    return result;
}

void update_topology(std::span<const struct cpu_info> new_cpu_info,
                     std::span<const Topology::Package> packages)
{
    struct cpu_info *end;
    if (packages.empty()) {
        // copy all
        end = std::copy(new_cpu_info.begin(), new_cpu_info.end(), cpu_info);
    } else {
        // copy only if matching the socket ID
        auto matching = [=](const struct cpu_info &ci) {
            for (const Topology::Package &p : packages) {
                if (p.id() == ci.package_id)
                    return true;
            }
            return false;
        };
        end = std::copy_if(new_cpu_info.begin(), new_cpu_info.end(), cpu_info, matching);
    }

    int new_thread_count = end - cpu_info;
    if (int excess = sApp->thread_count - new_thread_count; excess > 0)
        std::fill_n(end, excess, (struct cpu_info){});

    sApp->thread_count = new_thread_count;
    cached_topology() = build_topology();
}

void init_topology(const LogicalProcessorSet &enabled_cpus)
{
    init_topology_internal(enabled_cpus);
    reorder_cpus();
    cached_topology() = build_topology();
}

void restrict_topology(CpuRange range)
{
    assert(range.starting_cpu + range.cpu_count <= sApp->thread_count);
    auto old_cpu_info = std::exchange(cpu_info, sApp->shmem->cpu_info + range.starting_cpu);
    int old_thread_count = std::exchange(sApp->thread_count, range.cpu_count);

    Topology &topo = cached_topology();
    if (old_cpu_info != cpu_info || old_thread_count != sApp->thread_count ||
            topo.packages.size() == 0)
        topo = build_topology();
}

static char character_for_mask(uint32_t mask)
{
    static_assert((1 << MAX_HWTHREADS_PER_CORE) <= 36, "Cannot represent this many threads");
    return mask < 0xa ? '0' + mask : 'a' + mask - 0xa;
}

std::string Topology::build_falure_mask(const struct test *test) const
{
    std::string result;
    if (!isValid())
        return result;

    // Get the number of cores to use in the mask. Physically, this is the same
    // in all the packages, but may be weird configurations depending on the
    // cpuset mask we've been run with. We must also avoid the case where we
    // have no cores in package 0, so our returned string doesn't start with a
    // colon.
    size_t max_cores = 0;
    for (const Package &p : packages)
        max_cores = std::max(max_cores, p.cores.size());

    int totalfailcount = 0;
    std::vector<std::string> per_package_mask;
    per_package_mask.resize(packages.size());

    for (size_t pkgid = 0; pkgid < packages.size(); ++pkgid) {
        auto &package = packages[pkgid];
        auto &package_mask = per_package_mask[pkgid];

        package_mask.resize(max_cores, '_');
        for (size_t coreid = 0; coreid < package.cores.size(); ++coreid) {
            auto &core = package.cores[coreid];
            uint32_t threadmask = 0;
            int threadcount = 0;
            int failcount = 0;
            for (const Thread &t : core.threads) {
                int cpu_id = t.cpu();
                if (sApp->thread_data(cpu_id)->has_failed()) {
                    threadmask |= 1U << t.thread_id;
                    ++failcount;
                }
                ++threadcount;
            }

            if (threadcount == 0)
                continue;               // no tests run in this core, in any thread

            char c;
            if (threadmask == 0) {
                // no threads failed
                c = '.';
            } else if (failcount == threadcount) {
                // all threads failed
                c = 'X';
            } else {
                // some but not all threads failed, identify which ones
                c = character_for_mask(threadmask);
            }
            package_mask[coreid] = c;
            totalfailcount += failcount;
        }
    }

    if (totalfailcount == 0)
        return result;

    // combine everything into one string
    for (const std::string &s : per_package_mask) {
        result += s;
        result += ':';
    }

    // remove last ':'
    result.resize(result.size() - 1);
    return result;
}
