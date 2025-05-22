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
#include <fcntl.h>
#include <hwloc.h>
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

#ifdef __linux__
#define CORE_INDEX(core) (core ? core->os_index : -1)
#elif defined(_WIN32)
#define CORE_INDEX(core) (core ? core->logical_index : -1)
#endif

namespace {
struct auto_fd
{
    int fd = -1;
    auto_fd(int fd = -1) : fd(fd) {}
    ~auto_fd() { if (fd != -1) close(fd); }

    // make it movable but not copyable
    auto_fd(const auto_fd &) = delete;
    auto_fd &operator=(const auto_fd &) = delete;

    auto_fd(auto_fd &&other) : fd(std::exchange(other.fd, -1)) {}
    auto_fd &operator=(auto_fd &&other)
    {
        auto_fd tmp(std::move(other));
        std::swap(tmp.fd, fd);
        return *this;
    }

    operator int() const { return fd; }
};
}

struct cpu_info *cpu_info = nullptr;

static Topology &cached_topology()
{
    static Topology cached_topology = Topology({});
    return cached_topology;
}

#ifdef __linux__
static auto_fd open_sysfs_cpu_dir(int cpu)
{
    char buf[sizeof("/sys/devices/system/cpu/cpu2147483647")];
    sprintf(buf, "/sys/devices/system/cpu/cpu%d", cpu);
    return auto_fd { open(buf, O_PATH | O_CLOEXEC) };
}
#endif

static bool cpu_compare(const struct cpu_info &cpu1, const struct cpu_info &cpu2)
{
    static auto cpu_tuple = [](const struct cpu_info &c) {
        uint64_t h = (uint64_t(c.package_id) << 32) +
                unsigned(c.core_id);
        uint64_t l = ((uint64_t(c.thread_id)) << 32) +
                unsigned(c.cpu_number);
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
        if (!parse_int_and_advance(&info->core_id))
            continue;
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
#endif /* __linux__ */

#ifdef __x86_64__
static bool fill_family_cpuid(struct cpu_info *info, hwloc_topology_t topology)
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

static bool fill_ucode_msr(struct cpu_info *info, hwloc_topology_t topology)
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

static bool fill_ucode_sysfs(struct cpu_info *info, hwloc_topology_t topology)
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
        f = fopen("/proc/cpuinfo", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "microcode", 9) == 0) {
                    char *colon = strchr(line, ':');
                    if (colon) {
                        info->microcode = strtoull(colon + 1, nullptr, 0);
                        break;
                    }
                }
            }
            fclose(f);
        }
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
static bool fill_ppin_msr(struct cpu_info *info, hwloc_topology_t topology)
{
    info->ppin = 0;
    return read_msr(info->cpu_number, 0x4F, &info->ppin); /* MSR_PPIN */
}
#else
constexpr auto fill_ppin_msr = nullptr;
#endif // __x86_64__

static bool fill_ppin_sysfs(struct cpu_info *info, hwloc_topology_t topology)
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

static bool fill_topology_hwloc(struct cpu_info *info, hwloc_topology_t topology)
{
    hwloc_obj_t pu = hwloc_get_pu_obj_by_os_index(topology, info->cpu_number);
    if (!pu) {
        hwloc_topology_destroy(topology);
        return false;
    }

    hwloc_obj_t package = hwloc_get_ancestor_obj_by_type(topology, HWLOC_OBJ_PACKAGE, pu);
    info->package_id = package ? package->logical_index : -1;
    hwloc_obj_t core = hwloc_get_ancestor_obj_by_type(topology, HWLOC_OBJ_CORE, pu);
    info->core_id =  CORE_INDEX(core);

    if (core) {
        for (unsigned i = 0; i < core->arity; ++i) {
            if (core->children[i] == pu) {
                info->thread_id = i;
                break;
            }
        }
    }

    int depth = hwloc_get_type_depth(topology, HWLOC_OBJ_NUMANODE);
    if (depth != HWLOC_TYPE_DEPTH_UNKNOWN) {
        int num_nodes = hwloc_get_nbobjs_by_depth(topology, depth);
        if (pu && pu->nodeset) {
            for (int i = 0; i < num_nodes; i++) {
                hwloc_obj_t numa_node = hwloc_get_obj_by_depth(topology, depth, i);
                if (hwloc_bitmap_isset(pu->nodeset, numa_node->os_index)) {
                    info->numa_node_id = numa_node->os_index;  // Not logical_index
                    break;
                }
            }
        }
    }

    hwloc_obj_t cache;
    for (int level = 0; level < 3; ++level) { // Assuming 3 levels: L1, L2, L3
        switch (level) {
            case 0:
                cache = hwloc_get_ancestor_obj_by_type(topology, HWLOC_OBJ_L1CACHE, pu);
                break;
            case 1:
                cache = hwloc_get_ancestor_obj_by_type(topology, HWLOC_OBJ_L2CACHE, pu);
                break;
            case 2:
                cache = hwloc_get_ancestor_obj_by_type(topology, HWLOC_OBJ_L3CACHE, pu);
                break;
        }
        if (cache && cache->attr) {
            if (cache->attr->cache.type == HWLOC_OBJ_CACHE_UNIFIED || cache->attr->cache.type == HWLOC_OBJ_CACHE_DATA) {
                info->cache[level].cache_data = cache->attr->cache.size;
            }
            if (cache->attr->cache.type == HWLOC_OBJ_CACHE_UNIFIED || cache->attr->cache.type == HWLOC_OBJ_CACHE_INSTRUCTION) {
                info->cache[level].cache_instruction = cache->attr->cache.size;
            }
        }
    }
    return true;
}

template <auto &fnArray> static bool try_detection(struct cpu_info *cpu, hwloc_topology_t topology = nullptr)
{
    using DetectorFunction = std::decay_t<decltype(fnArray[0])>;
    if (std::size(fnArray) > 0) {
        if (std::size(fnArray) == 1) {
            // no need to cache, there's only one implementation
            DetectorFunction fn = fnArray[0];
            return fn ? fn(cpu, topology) : true;
        }

        static DetectorFunction cached_fn = nullptr;
        if (cached_fn)
            return cached_fn(cpu, topology);

        for (DetectorFunction fn : fnArray) {
            if (!fn)
                continue;
            if (fn(cpu, topology)) {
                cached_fn = fn;
                return true;
            }
        }
    }
    return false;
}

typedef bool (* fill_family_func)(struct cpu_info *, hwloc_topology_t);
typedef bool (* fill_ppin_func)(struct cpu_info *, hwloc_topology_t);
typedef bool (* fill_ucode_func)(struct cpu_info *, hwloc_topology_t);
typedef bool (* fill_topo_func)(struct cpu_info *, hwloc_topology_t);

static const fill_family_func family_impls[] = { fill_family_cpuid };
static const fill_ppin_func ppin_impls[] = { fill_ppin_sysfs, fill_ppin_msr };
/* prefer sysfs, fallback to MSR. the latter is not reliable and may require
 * root. */
static const fill_ucode_func ucode_impls[] = { fill_ucode_sysfs, fill_ucode_msr };
/* fill via hwloc. */
static const fill_topo_func topo_impls[] = { fill_topology_hwloc };

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

    hwloc_topology_t topology;
    hwloc_topology_init(&topology);
    hwloc_topology_load(topology);

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
        info->core_id = -1;
        info->thread_id = -1;

        std::fill(std::begin(info->cache), std::end(info->cache), cache_info{-1, -1});
        try_detection<topo_impls>(&cpu_info[i], topology);
    }
    hwloc_topology_destroy(topology);

    auto detect = [](void *ptr) -> void * {
        const auto & enabled_cpus = *static_cast<const LogicalProcessorSet *>(ptr);
        int curr_cpu = 0;
        for (int i = 0; i < sApp->thread_count; ++i, ++curr_cpu) {
            auto lp = LogicalProcessor(curr_cpu);
            while (!enabled_cpus.is_set(lp)) {
                lp = LogicalProcessor(++curr_cpu);
            }

            pin_to_logical_processor(lp);
            try_detection<family_impls>(&cpu_info[i]);
            try_detection<ppin_impls>(&cpu_info[i]);
            try_detection<ucode_impls>(&cpu_info[i]);
        }
        return nullptr;
    };

    pthread_t detection_thread;
    pthread_create(&detection_thread, nullptr, detect, const_cast<LogicalProcessorSet *>(&enabled_cpus));
    pthread_join(detection_thread, nullptr);
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
        }

        pkg->cores.reserve(core_count + 1);

        // fill in the threads
        for (Topology::Thread *last = first; last != info; ++last) {
            if (last->core_id == first->core_id)
                continue;
            pkg->cores.push_back({ { first, last } });
            first = last;
        }
        pkg->cores.push_back({ { first, info } });
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
