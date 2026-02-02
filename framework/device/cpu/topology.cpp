/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "topology.h"
#include "sandstone_p.h"
#include "thermal_monitor.hpp"

#include <algorithm>
#include <cassert>
#include <cinttypes>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __x86_64__
#  include <cpuid.h>
#endif
#if defined(_WIN32)
#   include <windows.h>
#endif

// Because of the anonymous struct inside of struct cpu_info_t
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"

namespace {
struct TopologyDetector
{
    TopologyDetector();
    void detect(const LogicalProcessorSet &enabled_cpus);
    void sort();

private:
    bool setup_cpuid_detection();
    bool detect_via_cpuid(Topology::Thread *info);
    bool detect_via_os(Topology::Thread *info);
    bool detect_numa();

    int last_package_id = -1;

    HardwareInfo::PackageInfo &package_for_id(int id)
    {
        // assumes package numbering is sequential
        auto &package_infos = sApp->hwinfo.package_infos;
        if (package_infos.size() && package_infos.back().id == id)
            return package_infos.back();
        return package_infos.emplace_back(id);
    }

#ifdef __x86_64__
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
    static constexpr Domain Package = Domain(Domain::Tile + 1);

    bool is_hybrid = false;
    int8_t topology_leaf = -1;
    std::array<uint8_t, Package> topology_widths_array = {};
    uint8_t &width(Domain domain) { return topology_widths_array[domain - 1]; };

    bool detect_hybrid_type_via_cpuid(Topology::Thread *info);
    bool detect_cache_via_cpuid(Topology::Thread *info, uint32_t *max_cpus_sharing_l2);
    bool detect_topology_via_cpuid(Topology::Thread *info);
#endif

    void detect_family_via_cpuid();
    bool detect_ppin_via_msr(HardwareInfo::PackageInfo *info, LogicalProcessor lp);
    bool detect_ucode_via_msr(Topology::Thread *info);

#ifdef __linux__
    struct ProcCpuInfoData {
        using Fields = std::map<std::string, std::string>;
        Fields general_fields;
        std::vector<Fields> cpu_fields;

        std::optional<uint64_t> number(int cpu_number, const char *field, int base = 0);
        void load();
    } proc_cpuinfo_;
    ProcCpuInfoData &proc_cpuinfo()
    {
        if (proc_cpuinfo_.cpu_fields.size() == 0)
            proc_cpuinfo_.load();
        return proc_cpuinfo_;
    }

    bool detect_cache_via_os(Topology::Thread *info, int cpufd);
    bool detect_ppin_via_os(HardwareInfo::PackageInfo *info, int cpufd);
    bool detect_topology_via_os(Topology::Thread *info, int cpufd);
    bool detect_ucode_via_os(Topology::Thread *info, int cpufd);
#elif defined(_WIN32)
    bool detect_topology_via_os(LOGICAL_PROCESSOR_RELATIONSHIP relationships);
    bool detect_ucode_via_os(Topology::Thread *info);
#endif

    bool old_create_mock_topology(const char *topo);
    bool create_mock_topology(const char *topo);
};
} // unnamed namespace

static void update_topology(std::span<const cpu_info_t> new_cpu_info,
                            std::span<const Topology::Package> sockets = {});

int num_cpus()
{
    return thread_count();
}

int num_packages()
{
    return Topology::topology().packages.size();
}

std::unique_ptr<DeviceScheduler> make_rescheduler(RescheduleMode mode)
{
    if (mode == RescheduleMode::barrier) {
        return std::make_unique<BarrierDeviceScheduler>();
    } else if (mode == RescheduleMode::queue) {
        return std::make_unique<QueueDeviceScheduler>();
    } else if (mode == RescheduleMode::random) {
        return std::make_unique<RandomDeviceScheduler>();
    }
    return nullptr;
}

namespace {
void pin_to_next_cpu(int next_cpu, tid_t thread_id = 0)
{
    if (!pin_thread_to_logical_processor(LogicalProcessor(next_cpu), thread_id)) {
        log_warning("Failed to reschedule %d (%tu) to CPU %d", thread_id, (uintptr_t)pthread_self(), next_cpu);
    }
}
} // end anonymous namespace

void BarrierDeviceScheduler::reschedule_to_next_device()
{
    auto on_completion = [&]() noexcept {
        std::unique_lock lock(groups_mutex);
        int g_idx = thread_num / members_per_group;
        GroupInfo &group = groups[g_idx];

        // Rotate cpus vector so reschedule group members to a different cpu
        std::rotate(group.next_cpu.begin(), group.next_cpu.begin() + 1, group.next_cpu.end());
        lock.unlock();

        // Reschedule group members
        for (int i=0; i<group.tid.size(); i++) {
            pin_to_next_cpu(device_info[group.next_cpu[i]].cpu_number, group.tid[i]);
        }
    };

    std::unique_lock lock(groups_mutex);
    // Initialize groups on first run
    if (groups.empty()) {
        int full_groups = num_cpus() / members_per_group;
        int partial_group_members = num_cpus() % members_per_group;

        groups.reserve(full_groups + (partial_group_members > 0));
        for (int i=0; i<full_groups; i++) {
            groups.emplace_back(members_per_group, on_completion);
        }
        if (partial_group_members > 0) {
            groups.emplace_back(partial_group_members, on_completion);
        }
    }

    // Fill thread info if not done already
    int g_idx = thread_num / members_per_group;
    GroupInfo &group = groups[g_idx];
    int thread_info_idx = thread_num % members_per_group;
    if (group.tid[thread_info_idx] == 0) {
        group.tid[thread_info_idx] = sApp->test_thread_data(thread_num)->tid.load();
        group.next_cpu[thread_info_idx] = thread_num;
    }

    lock.unlock();

    // Wait on proper barrier
    group.barrier->arrive_and_wait();
    return;
}

void BarrierDeviceScheduler::finish_reschedule()
{
    std::unique_lock lock(groups_mutex);

    // Don't clean up when test does not support rescheduling
    if (groups.size() == 0) return;

    // When thread finishes, unsubscribe it from barrier
    // this avoid partners deadlocks
    int g_idx = thread_num / members_per_group;
    GroupInfo &group = groups[g_idx];

    // Remove thread info from groups
    int thread_info_idx = thread_num % members_per_group;
    group.tid.erase(group.tid.begin() + thread_info_idx);

    // Remove CPU information only if the thread failed, as it likely indicates a problematic device;
    // otherwise, keep it for execution.
    if(sApp->test_thread_data(thread_num)->has_failed())
        group.next_cpu.erase(group.next_cpu.begin() + thread_info_idx);
    lock.unlock();

    group.barrier->arrive_and_drop();
}

void QueueDeviceScheduler::reschedule_to_next_device()
{
    // Select a cpu from the queue
    std::lock_guard lock(q_mutex);
    if (q_idx == 0)
        shuffle_queue();

    int next_idx = queue[q_idx];
    if (++q_idx == queue.size())
        q_idx = 0;

    pin_to_next_cpu(device_info[next_idx].cpu_number);
    return;
}

void QueueDeviceScheduler::shuffle_queue()
{
    // Must be called with mutex locked
    if (queue.size() == 0) {
        // First use: populate queue with the indexes available
        for (int i=0; i<num_cpus(); i++)
            queue.push_back(i);
    }

    std::default_random_engine rng(random32());
    std::shuffle(queue.begin(), queue.end(), rng);
}

void RandomDeviceScheduler::reschedule_to_next_device()
{
    // Select a random cpu index among the ones available
    int next_idx = unsigned(random()) % num_cpus();
    pin_to_next_cpu(device_info[next_idx].cpu_number);

    return;
}

cpu_info_t *device_info = nullptr;

static Topology &cached_topology()
{
    static Topology cached_topology = Topology({});
    return cached_topology;
}

#ifdef __linux__
std::optional<uint64_t> TopologyDetector::ProcCpuInfoData::number(int cpu_number, const char *field, int base)
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

static auto_fd open_sysfs_cpu_dir(int cpu)
{
    char buf[sizeof("/sys/devices/system/cpu/cpu2147483647")];
    sprintf(buf, "/sys/devices/system/cpu/cpu%d", cpu);
    return auto_fd { open(buf, O_PATH | O_CLOEXEC) };
}

void TopologyDetector::ProcCpuInfoData::load()
{
    static const char header[] = "processor\t";
    AutoClosingFile f{ fopen("/proc/cpuinfo", "r") };
    assert(f.f && "/proc must be mounted for proper operation");

    auto &result = *this;
    Fields *current = &general_fields;

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
}
#endif

static bool cpu_compare(const cpu_info_t &cpu1, const cpu_info_t &cpu2)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  error "This doesn't work on big endian systems! Please contribute a fix."
#endif
    // Confirm that the members are in the right order in a 16-byte block
    static_assert(sizeof(cpu_info_t::package_id) == 2);
    static_assert(offsetof(cpu_info_t, cpu_number) + 14 == offsetof(cpu_info_t, package_id));
    static_assert(offsetof(cpu_info_t, cpu_number) + 12 == offsetof(cpu_info_t, numa_id));
    static_assert(offsetof(cpu_info_t, cpu_number) + 11 == offsetof(cpu_info_t, native_core_type));
    static_assert(offsetof(cpu_info_t, cpu_number) + 9 == offsetof(cpu_info_t, tile_id));
    static_assert(offsetof(cpu_info_t, cpu_number) + 7 == offsetof(cpu_info_t, module_id));
    static_assert(offsetof(cpu_info_t, cpu_number) + 5 == offsetof(cpu_info_t, core_id));
    static_assert(offsetof(cpu_info_t, cpu_number) + 4 == offsetof(cpu_info_t, thread_id));

    static auto cpu_tuple = [](const cpu_info_t &c) {
        unsigned __int128 result;
        memcpy(&result, &c.cpu_number, sizeof(result));
        return result;
    };

    return cpu_tuple(cpu1) < cpu_tuple(cpu2);
};

__attribute__((noinline))
void TopologyDetector::sort()
{
    std::sort(device_info, device_info + num_cpus(), cpu_compare);
}

bool TopologyDetector::old_create_mock_topology(const char *topo)
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

    int cpu_count = 0;
    while (topo && *topo) {
        if (cpu_count == sApp->thread_count)
            break;      // can't add more

        cpu_info_t *info = &device_info[cpu_count];
        ++cpu_count;

        info->package_id = info->module_id = info->core_id = info->thread_id = 0;

        // mock cache too (8 kB L1, 32 kB L2, 256 kB L3)
        info->cache[0] = { 0x2000, 0x2000 };
        info->cache[1] = { 0x8000, 0x8000 };
        info->cache[2] = { 0x40000, 0x40000 };

        bool next = parse_int_and_advance(&info->package_id);
        if (info->package_id != last_package_id) {
            package_for_id(info->package_id);
            last_package_id = info->package_id;
        }
        if (!next)
            continue;

        next = parse_int_and_advance(&info->core_id);
        info->module_id = info->core_id;
        if (!next)
            continue;

        if (!parse_int_and_advance(&info->thread_id))
            continue;
    }

    sApp->thread_count = cpu_count;
    return true;
}

// Creates a mock topology for the system. The variable must be a space- or
// comma-separated list of entries of the type from the switch below, which is
// similar to the --cpuset=/--deviceset= command-line parameter (see
// apply_deviceset_param()).
//
// There is little validation on the input because this is *debug* code so you
// had better know what you're doing!
bool TopologyDetector::create_mock_topology(const char *topo)
{
    auto parse_int_and_advance = [&topo](auto *ptr) {
        char *end;
        *ptr = strtoll(topo, &end, 0);
        topo = end;
    };

    if (!topo || !*topo)
        return false;

    if (*topo >= '0' && *topo <= '9')
        return old_create_mock_topology(topo);   // older format

    int cpu_count = 0;
    while (topo && *topo) {
        if (cpu_count == sApp->thread_count)
            break;      // can't add more

        cpu_info_t *info = &device_info[cpu_count];
        ++cpu_count;

        info->package_id = info->core_id = info->thread_id = 0;
        info->numa_id = info->module_id = info->tile_id = -1;
        info->native_core_type = core_type_unknown;

        // mock cache too (8 kB L1, 32 kB L2, 256 kB L3)
        info->cache[0] = { 0x2000, 0x2000 };
        info->cache[1] = { 0x8000, 0x8000 };
        info->cache[2] = { 0x40000, 0x40000 };

        char c = topo[0] | 0x20;  // lowercased (if a letter); numbers unchanged
        // parse the different fields of the topology
        while (c >= 'a' && c <= 'z') {
            ++topo;
            switch (c) {
            case 'p':
                parse_int_and_advance(&info->package_id);
                package_for_id(info->package_id); // ensure it exists
                last_package_id = info->package_id;
                break;
            case 'n':
                parse_int_and_advance(&info->numa_id);
                break;
            case 'm':
                parse_int_and_advance(&info->module_id);
                break;
            case 'c':
                parse_int_and_advance(&info->core_id);
                break;
            case 't':
                parse_int_and_advance(&info->thread_id);
                break;

            case 'y':   // core tYpe
                switch (topo[0] | 0x20) {
                case 'e':
                    info->native_core_type = core_type_efficiency;
                    ++topo;
                    break;
                case 'p':
                    info->native_core_type = core_type_performance;
                    ++topo;
                    break;
                }
                break;
            }

            c = topo ? topo[0] | 0x20 : '\0';
        }

        if (info->module_id < 0)
            info->module_id = info->core_id;
        if (info->numa_id < 0)
            info->numa_id = info->package_id;

        while (topo && (*topo == ' ' || *topo == ','))
            ++topo;
    }

    sApp->thread_count = cpu_count;
    return true;
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

bool TopologyDetector::detect_cache_via_os(Topology::Thread *info, int cpufd)
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

        static const int cache_size = std::size(info->cache);
        if (level <= cache_size && level > 0) {
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

bool TopologyDetector::detect_numa()
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
            if (n <= 0) [[unlikely]] {
                closedir(dir);
                return false;
            }

            if (cpulist[n - 1] == '\n') {
                // it fit
                cpulist.resize(n - 1);
                break;
            }

            // need more space
            cpulist.resize(cpulist.capacity() * 4);
        }

        // Parse the list. This will *usually* be one or two ranges.
        cpu_info_t *cpu = &device_info[0];
        cpu_info_t *const end = device_info + sApp->thread_count;
        const char *ptr = cpulist.c_str();
        while (*ptr && cpu != end) {
            auto [start, stop] = parse_cpulist_range(ptr);

            // Find the starting CPU.
            // At this point, the device_info array is sorted by cpu_number and,
            // if we're running over the entire system, the array index
            // matches the cpu_number too.
            if (start < sApp->thread_count && device_info[start].cpu_number == start) {
                cpu = &device_info[start];
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

bool TopologyDetector::detect_topology_via_os(Topology::Thread *info, int cpufd)
{
    FILE *f;

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
        IGNORE_RETVAL(fgetc(f));

        assert(info->thread_id < MAX_HWTHREADS_PER_CORE);
    }
    fclose(f);

    if (std::optional apicid = proc_cpuinfo().number(info->cpu_number, "apicid", 10))
        info->hwid = *apicid;
    return true;
}

bool TopologyDetector::detect_via_os(Topology::Thread *info)
{
    auto_fd cpufd = open_sysfs_cpu_dir(info->cpu_number);
    if (cpufd < 0)
        return false;

    if (info->cache[0].cache_data < 0)
        detect_cache_via_os(info, cpufd);
    if (info->core_id < 0)
        detect_topology_via_os(info, cpufd);

    if (!detect_ucode_via_os(info, cpufd))
        detect_ucode_via_msr(info);

    if (info->package_id != last_package_id) {
        auto &pkginfo = package_for_id(info->package_id);
        if (!detect_ppin_via_os(&pkginfo, cpufd))
            detect_ppin_via_msr(&pkginfo, LogicalProcessor(info->cpu_number));
    }

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

bool TopologyDetector::detect_topology_via_os(LOGICAL_PROCESSOR_RELATIONSHIP relationships)
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

    cpu_info_t *const info = device_info;
    std::span infos(info, info + num_cpus());
    auto first_cpu_for_group = [infos](unsigned group) -> cpu_info_t * {
        for (cpu_info_t &info : infos) {
            if (info.cpu_number / CpusPerGroup == group)
                return &info;
        }
        return nullptr;
    };

    auto for_each_proc_in = [&](unsigned groupCount, GROUP_AFFINITY *groups, auto lambda) {
        // find the first CPU matching this group
        for (GROUP_AFFINITY &ga : std::span(groups, groupCount)) {
            cpu_info_t *info = first_cpu_for_group(ga.Group);
            if (!info)
                continue;

            KAFFINITY mask = ga.Mask;
            while (mask) {
                int n = std::countr_zero(mask);
                mask &= ~(KAFFINITY(1) << n);

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
                             [&](cpu_info_t *info) {
                                 info->package_id = pkg_id;
                             }
                );
            ++pkg_id;
            module_id = 0;
            core_id = 0;
            break;

        case RelationProcessorModule:
            for_each_proc_in(lpi->Processor.GroupCount, lpi->Processor.GroupMask,
                              [&](cpu_info_t *info) {
                                  info->module_id = module_id;
                              }
                 );
            ++module_id;
            break;

        case RelationProcessorCore:
            for_each_proc_in(lpi->Processor.GroupCount, lpi->Processor.GroupMask,
                             [&, thread_id = 0](cpu_info_t *info) mutable {
                                 info->core_id = core_id;
                                 info->thread_id = thread_id++;
                             }
                );
            ++core_id;
            break;

        case RelationCache: {
            auto &cache = *reinterpret_cast<CACHE_RELATIONSHIP_2 *>(&lpi->Cache);
            for_each_proc_in(cache.GroupCount, cache.GroupMasks,
                             [&](cpu_info_t *info) {
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

        case RelationNumaNode:
        case RelationNumaNodeEx: {
            // this only works for Windows 20H2 or later, otherwise GroupCount = 0
            auto &numa = *reinterpret_cast<NUMA_NODE_RELATIONSHIP_2 *>(&lpi->NumaNode);
            for_each_proc_in(numa.GroupCount, numa.GroupMasks,
                             [&](cpu_info_t *info) {
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
        for (cpu_info_t &cpu : infos)
            cpu.module_id = cpu.core_id;
    }
    return true;
}

bool TopologyDetector::detect_via_os(Topology::Thread *info)
{
    detect_ucode_via_os(info);
    if (info->core_id >= 0)
        return true;                // detect_via_cpuid() has succeeded
    if (info != &device_info[0])
        return info->core_id != -1; // we only need to run once

    return detect_topology_via_os(RelationAll);
}

bool TopologyDetector::detect_numa()
{
    if (device_info[0].numa_id >= 0)
        return true;            // already filled in above

    return detect_topology_via_os(RelationNumaNodeEx);
}
#else /* !__linux__ and !_WIN32 */
bool TopologyDetector::detect_via_os(Topology::Thread *info)
{
    return false;
}

bool TopologyDetector::detect_numa()
{
    // unimplemented
    return false;
}
#endif /* __linux__ */

#ifdef __x86_64__
void TopologyDetector::detect_family_via_cpuid()
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
    auto &family = sApp->hwinfo.family;
    auto &model = sApp->hwinfo.model;
    auto &stepping = sApp->hwinfo.stepping;

    eax = ebx = ecx = edx = 0;
    __cpuid(1, eax, ebx, ecx, edx);
    family = (eax >> 8) & 0xf;
    if (family == 0xf) family += (eax >> 20) & 0xff;
    model = (eax >> 4) & 0xf;
    if (family == 0xf || family == 0x6)
        model += ((eax >> (16-4)) & 0xf0);
    stepping = eax & 0xf;
}

bool TopologyDetector::detect_cache_via_cpuid(Topology::Thread *info,
                                              uint32_t *max_cpus_sharing_l2)
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

bool TopologyDetector::detect_hybrid_type_via_cpuid(Topology::Thread *info)
{
    if (is_hybrid) {
        uint32_t a, b, c, d;
        __cpuid_count(0x1a, 0, a, b, c, d);
        switch (a >> 24) {
        case 0x20:      // Intel Atom
            info->native_core_type = core_type_efficiency;
            break;
        case 0x40:      // Intel Core
            info->native_core_type = core_type_performance;
            break;

        // other values are reserved
        }
    }
    return true;
}

bool TopologyDetector::setup_cpuid_detection()
{
    if (SandstoneConfig::Debug) {
        if (char *str = getenv("SANDSTONE_USE_OS_TOPOLOGY"); str && *str)
            return false;
    }

    int8_t &leaf = topology_leaf;
    uint32_t a, b, c, d;

    __cpuid(0, a, b, c, d);
    leaf = -1;
    if (a >= 0x1f)
        leaf = 0x1f;        // use V2 Extended Topology
    else if (a >= 0x0b)
        leaf = 0x0b;        // use regular Extended Topology
    else
        return false;

    if (a >= 0x1a) {
        // is this a hybrid part?
        __cpuid_count(0x1a, 0, a, b, c, d);
        is_hybrid = (a != 0);
    }

    int subleaf = 0;
    __cpuid_count(leaf, subleaf, a, b, c, d);

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
        __cpuid_count(leaf, subleaf, a, b, c, d);
    }

    if (width(Domain::Logical) == 0 || width(Domain::Core) == 0
            || width(Package) == 0) [[unlikely]] {
        // no information on CPUID leaf; fallback to OS
        leaf = -1;
        return false;
    }
    return true;
}

bool TopologyDetector::detect_topology_via_cpuid(Topology::Thread *info)
{
    uint32_t a, b, c, apicid;
    uint32_t max_cpus_sharing_l2 = 0;

    if (!detect_cache_via_cpuid(info, &max_cpus_sharing_l2))
        return false;

    // get this processor's APIC ID
    assert(topology_leaf > 0);
    __cpuid_count(topology_leaf, 0, a, b, c, apicid);

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

[[maybe_unused]] bool TopologyDetector::detect_ucode_via_msr(Topology::Thread *info)
{
    uint64_t ucode = 0;

    if (!read_msr(info->cpu_number, 0x8B, &ucode))
        return false;
    info->microcode = (uint32_t)(ucode >> 32);

    return true;
}

#  if defined(__linux__)
bool TopologyDetector::detect_ppin_via_os(HardwareInfo::PackageInfo *info, int cpufd)
{
    if (AutoClosingFile f { fopenat(cpufd, "topology/ppin") }) {
        if (fscanf(f, "%" PRIx64, &info->ppin) > 0)
            return true;
    }
    return false;
}

bool TopologyDetector::detect_ucode_via_os(Topology::Thread *info, int cpufd)
{
    FILE *f;
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
}
#  elif defined(_WIN32)
bool TopologyDetector::detect_ucode_via_os(Topology::Thread *info)
{
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
}
#  endif // Linux or Windows

[[maybe_unused]]
bool TopologyDetector::detect_ppin_via_msr(HardwareInfo::PackageInfo *info, LogicalProcessor lp)
{
    info->ppin = 0;
    return read_msr(int(lp), 0x4F, &info->ppin); /* MSR_PPIN */
}

bool TopologyDetector::detect_via_cpuid(Topology::Thread *info)
{
    detect_hybrid_type_via_cpuid(info);
    return detect_topology_via_cpuid(info);     // does cache detection
}
#else // !x86-64
void TopologyDetector::detect_family_via_cpuid()
{
}

bool TopologyDetector::detect_ppin_via_msr(HardwareInfo::PackageInfo *, LogicalProcessor)
{
    return false;
}

bool TopologyDetector::detect_ucode_via_msr(Topology::Thread *)
{
    return false;
}

bool TopologyDetector::detect_ppin_via_os(HardwareInfo::PackageInfo *, int)
{
    return false;
}

bool TopologyDetector::detect_ucode_via_os(Topology::Thread *, int)
{
    return false;
}

bool TopologyDetector::setup_cpuid_detection()
{
    return false;
}

bool TopologyDetector::detect_via_cpuid(Topology::Thread *)
{
    assert(false && "Should not get here!");
    __builtin_unreachable();
    return false;
}
#endif // !x86-64

TopologyDetector::TopologyDetector()
{
}

void apply_deviceset_param(const char *param)
{
    struct MatchCpuInfoByCpuNumber {
        int cpu_number;
        bool operator()(const cpu_info_t &cpu)
        { return cpu.cpu_number == cpu_number; }
    };

    if (SandstoneConfig::RestrictedCommandLine)
        return;

    std::span<cpu_info_t> old_cpu_info(device_info, sApp->thread_count);
    std::vector<cpu_info_t> new_cpu_info;
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
        auto apply_to_set = [&](const cpu_info_t &cpu) {
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
        } else if (p == "odd" || p == "even"){
            int desired_remainder = (p == "odd" ? 1 : 0);
            for (cpu_info_t &cpu : old_cpu_info)
            {
                if (cpu.cpu_number % 2 == desired_remainder)
                    apply_to_set(cpu);
            }
        } else if (p.starts_with("type=")) {
            NativeCoreType expected = [&]() {
                std::string_view type = p;
                type.remove_prefix(strlen("type="));
                if (type == "e")
                    return core_type_efficiency;
                else if (type == "p")
                    return core_type_performance;

                fprintf(stderr, "%s: error: Invalid CPU set parameter: %s (unknown core type)\n",
                        program_invocation_name, orig_arg);
                exit(EX_USAGE);
                return core_type_unknown;    // unreachable
            }();

            for (const cpu_info_t &cpu : old_cpu_info) {
                if (cpu.native_core_type == expected)
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
            for (cpu_info_t &cpu : old_cpu_info) {
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

void TopologyDetector::detect(const LogicalProcessorSet &enabled_cpus)
{
    assert(sApp->thread_count);
    assert(sApp->thread_count == enabled_cpus.count());
    device_info = sApp->shmem->device_info;

    // detect this CPU's family - it's impossible for them to be different
    detect_family_via_cpuid();

    int count = sApp->thread_count;
    [[assume(count > 0)]];

    // fill in device_info first
    {
        cpu_info_t *info = &device_info[0];
        // -1 to indicate unknown yet
        info->package_id = -1;
        info->numa_id = -1;
        info->tile_id = -1;
        info->module_id = -1;
        info->core_id = -1;
        info->thread_id = -1;
        info->hwid = -1;

        std::fill(std::begin(info->cache), std::end(info->cache), cache_info_t{-1, -1});
    }
    // replicate device_info[0] over the entire range
    std::fill_n(&device_info[1], count - 1, device_info[0]);

    int i = 0;
    for (LogicalProcessor lp = enabled_cpus.next(); lp != LogicalProcessor::None; ++i) {
        // set the OS cpu id
        auto info = device_info + i;
        info->cpu_number = int(lp);
        lp = enabled_cpus.next(LogicalProcessor(int(lp) + 1));
    }
    assert(i == count);

    if (SandstoneConfig::Debug) {
        if (create_mock_topology(getenv("SANDSTONE_MOCK_TOPOLOGY")))
            return;
    }

    auto detect = [](void *ptr) -> void * {
        auto self = static_cast<TopologyDetector *>(ptr);
        int count = sApp->thread_count;
        [[assume(count > 0)]];
        for (Topology::Thread &cpu : std::span(device_info, count)) {
            pin_to_logical_processor(LogicalProcessor(cpu.cpu_number));
            self->detect_via_cpuid(&cpu);
            self->detect_via_os(&cpu);
            self->last_package_id = cpu.package_id;
        }
        return nullptr;
    };

    if (setup_cpuid_detection()) {
        // Do a per-CPU detection, which requires us to pin an auxiliary
        // thread to each CPU.
        pthread_t detection_thread;
        pthread_create(&detection_thread, nullptr, detect, this);
        pthread_join(detection_thread, nullptr);
    } else {
        // Use OS-level detection only (no pinning, no threads).
        for (Topology::Thread &cpu : std::span(device_info, count)) {
            detect_via_os(&cpu);
            last_package_id = cpu.package_id;
        }
    }

    detect_numa();
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
    cpu_info_t *info = device_info;
    const cpu_info_t *const end = device_info + num_cpus();

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
        Topology::Thread *groupfirst = info;
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

            // We consider different core types in a heterogeneous system to be a
            // different "NUMA" nodes.
            if (info->numa_id != groupfirst->numa_id
                    || info->native_core_type != groupfirst->native_core_type) {
                // start of a new NUMA or "NUMA" node inside of this Package
                populate_core_group(&pkg->numa_domains.emplace_back(), groupfirst, info);
                groupfirst = info;
            }
        }

        // populate the full core
        pkg->cores.reserve(core_count + 1);
        populate_core_group(pkg, first, info);

        // populate the last NUMA node/core type group, which may be the only one too
        Topology::NumaNode *numa = &pkg->numa_domains.emplace_back();
        if (pkg->numa_domains.size() == 1)
            numa->CoreGrouping::operator=(*pkg);    // just copy the Package
        else
            populate_core_group(numa, groupfirst, info);
    }

    return Topology(std::move(packages));
}

void slice_plan_init(int max_cores_per_slice)
{
    auto set_to_full_system = []() {
        // only one plan and that's the full system
        std::vector plan = { DeviceRange{ 0, num_cpus() } };
        sApp->slice_plans.plans.fill(plan);
        return;
    };
    for (std::vector<DeviceRange> &plan : sApp->slice_plans.plans)
        plan.clear();

    if (sApp->current_fork_mode() == SandstoneApplication::ForkMode::no_fork || max_cores_per_slice < 0)
        return set_to_full_system();

    // The heuristic is enabled by max_cores_per_slice == 0 and a valid
    // topology:
    // - if the CPU Set has less than or equal to MinimumCpusPerSocket (8)
    //   logical processors per socket (on average), we ignore the topology and
    //   will instead run in slices of up to DefaultMaxCoresPerSlice (32)
    //   logical processors.
    // - otherwise, we'll have at least one slice per socket
    //   * if the socket has more than 32 cores or is a hybrid part, we'll
    //     attempt to slice it, first according to core types and then at NUMA
    //     node boundaries
    //   * if a core group has more than 32 cores, we'll attempt to split it
    //     evenly so each slice has at most 32 cores (64 threads on a system with
    //     2 threads per core)
    // - we always keep the cores of a given module and threads of a core
    //   in the same slice
    //   * this means on some situations the slices may have more than 32 cores
    //     (i.e. the 32nd and 33rd core were part of the same module)
    //
    // If the user specifies a --max-cores-per-slice option in the
    // command-line, it will bypass the heuristic but keep the slice balancing
    // as described above. Be aware bypasses the minimum average processor per
    // socket check.

    int max_cpu = num_cpus();
    const Topology &topology = Topology::topology();
    while (topology.isValid()) {     // not a loop, just so we can use break
        using SlicePlans = SandstoneApplication::SlicePlans;
        static constexpr int MinimumCpusPerSocket = SlicePlans::MinimumCpusPerSocket;
        static constexpr int DefaultMaxCoresPerSlice = SlicePlans::DefaultMaxCoresPerSlice;

        if (max_cores_per_slice == 0) {
            // apply defaults
            int average_cpus_per_socket = max_cpu / topology.packages.size();
            max_cores_per_slice = DefaultMaxCoresPerSlice;
            if (average_cpus_per_socket <= MinimumCpusPerSocket)
                break;
        }

        // set up proper plans
        std::vector<DeviceRange> &isolate_socket = sApp->slice_plans.plans[SlicePlans::IsolateSockets];
        std::vector<DeviceRange> &isolate_numa = sApp->slice_plans.plans[SlicePlans::IsolateNuma];
        std::vector<DeviceRange> &split = sApp->slice_plans.plans[SlicePlans::Heuristic];
        auto push_to = [](std::vector<DeviceRange> &to, auto start, auto end) {
            int start_cpu = start[0].threads.front().cpu();
            int end_cpu = end[-1].threads.back().cpu();
            assert(end_cpu >= start_cpu);
            to.push_back(DeviceRange{ start_cpu, end_cpu + 1 - start_cpu });
        };

        for (const Topology::Package &p : topology.packages) {
            if (p.cores.size() == 0)
                continue;       // untested socket

            push_to(isolate_socket, p.cores.begin(), p.cores.end());

            // if we have to split, we'll try to split along NUMA node lines
            for (const Topology::NumaNode &n : p.numa_domains) {
                if (n.cores.size() == 0)
                    continue;   // untested node (shouldn't happen!)

                push_to(isolate_numa, n.cores.begin(), n.cores.end());

                auto begin = n.cores.begin();
                const auto end = n.cores.end();
                ptrdiff_t slice_count = n.cores.size() / max_cores_per_slice;
                if (n.cores.size() % max_cores_per_slice)
                    ++slice_count;  // round up (also makes at least 1)
                ptrdiff_t slice_size = (n.cores.size() + slice_count - 1) / slice_count;

                // populate slices of roughly slice_size cores, but keep
                // modules within the same slice
                while (end - begin > slice_size) {
                    auto e = begin + slice_size;
                    while (e != end && e[-1].threads[0].module_id == e[0].threads[0].module_id)
                        ++e;
                    push_to(split, begin, e);
                    begin = e;
                }
                if (begin != end)
                    push_to(split, begin, end);
            }
        }
        return;
    }

    if (max_cores_per_slice == 0) {
        set_to_full_system();
    } else {
        // dumb plan, not *cores*
        int slice_count = (max_cpu - 1) / max_cores_per_slice + 1;
        std::vector<DeviceRange> plan;
        plan.reserve(slice_count);

        int slice_size = max_cpu / slice_count;
        if (max_cpu % slice_count)
            ++slice_size;       // round up the slice size
        int cpu = 0;
        for ( ; cpu < max_cpu - slice_size; cpu += slice_size)
            plan.push_back(DeviceRange{ cpu, slice_size });
        plan.push_back(DeviceRange{ cpu, max_cpu - cpu });
        sApp->slice_plans.plans.fill(plan);
    }
}

const Topology &Topology::topology()
{
    return cached_topology();
}

Topology::Data Topology::clone() const
{
    Data result;
    result.all_threads.assign(device_info, device_info + num_cpus());
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

void update_topology(std::span<const cpu_info_t> new_cpu_info,
                     std::span<const Topology::Package> packages)
{
    cpu_info_t *end;
    if (packages.empty()) {
        // copy all
        end = std::copy(new_cpu_info.begin(), new_cpu_info.end(), device_info);
    } else {
        // copy only if matching the socket ID
        auto matching = [=](const cpu_info_t &ci) {
            for (const Topology::Package &p : packages) {
                if (p.id() == ci.package_id)
                    return true;
            }
            return false;
        };
        end = std::copy_if(new_cpu_info.begin(), new_cpu_info.end(), device_info, matching);
    }

    int new_thread_count = end - device_info;
    if (int excess = sApp->thread_count - new_thread_count; excess > 0)
        std::fill_n(end, excess, (cpu_info_t){});

    sApp->thread_count = new_thread_count;
    cached_topology() = build_topology();
}

template <>
LogicalProcessorSet detect_devices<LogicalProcessorSet>()
{
    LogicalProcessorSet result = ambient_logical_processor_set();
    sApp->thread_count = result.count();
    if (sApp->thread_count == 0) [[unlikely]] {
        fprintf(stderr, "%s: internal error: ambient logical processor set appears to be empty!\n",
                program_invocation_name);
        return result;
    }
    sApp->user_thread_data.resize(sApp->thread_count);
#ifdef M_ARENA_MAX
    mallopt(M_ARENA_MAX, sApp->thread_count * 2);
#endif

    return result;
}

template <>
void setup_devices<LogicalProcessorSet>(const LogicalProcessorSet &enabled_devices)
{
    TopologyDetector detector;
    detector.detect(enabled_devices);
    detector.sort();
    cached_topology() = build_topology();
}

void restrict_topology(DeviceRange range)
{
    assert(range.starting_device + range.device_count <= sApp->thread_count);
    auto old_cpu_info = std::exchange(device_info, sApp->shmem->device_info + range.starting_device);
    int old_thread_count = std::exchange(sApp->thread_count, range.device_count);

    Topology &topo = cached_topology();
    if (old_cpu_info != device_info || old_thread_count != sApp->thread_count ||
            topo.packages.size() == 0)
        topo = build_topology();
}

void analyze_test_failures_for_topology(const struct test *test, const PerThreadFailures &per_thread_failures)
{
    Topology topology  = Topology::topology();
    if (!topology.isValid()) {
        // can't use this information
        return;
    } else if (test->flags & test_failure_package_only) {
        // Failure cannot be attributed to a single thread or core.  Let's see if it
        // can be pinned down to a single package.
        logging_printf(LOG_LEVEL_VERBOSE(1), "# Topology analysis:\n");

        // Analysis is not needed if there's only a single package.
        if (topology.packages.size() == 1) {
            logging_printf(LOG_LEVEL_VERBOSE(1), "# - Failures localised to package %d\n",
                           topology.packages[0].id());
            return;
        }

        std::vector<int> pkg_failures(topology.packages.size(), -1);
        int failed_packages = 0;
        int last_bad_package = -1;
        for (size_t p = 0; p < topology.packages.size(); ++p) {
            Topology::Package *pkg = &topology.packages[p];
            for (size_t c = 0; c < pkg->cores.size(); ++c) {
                Topology::Core *core = &pkg->cores[c];
                for (const Topology::Thread &thr : core->threads) {
                    if (per_thread_failures[thr.cpu()] && (pkg_failures[p] == -1)) {
                        last_bad_package = pkg->id();
                        failed_packages++;
                        pkg_failures[p] = pkg->id();
                    }
                }
            }
        }
        if (failed_packages == 1) {
            logging_printf(LOG_LEVEL_VERBOSE(1), "# - Failures localised to package %d\n", last_bad_package);
        } else {
            logging_printf(LOG_LEVEL_VERBOSE(1), "# - Failure detected on multiple packages:\n");
            for (int p : pkg_failures) {
                if (pkg_failures[p] >= 0)
                    logging_printf(LOG_LEVEL_VERBOSE(1), "#   - Package %d failed\n", p);
            }
        }
    } else {
        // valid topology, we can do more a interesting analysis
        logging_printf(LOG_LEVEL_VERBOSE(1), "# Topology analysis:\n");
        for (size_t p = 0; p < topology.packages.size(); ++p) {
            Topology::Package *pkg = &topology.packages[p];
            for (size_t c = 0; c < pkg->cores.size(); ++c) {
                Topology::Core *core = &pkg->cores[c];
                bool all_threads_failed_once = true;
                bool all_threads_failed_equally = true;
                int nthreads = 0;
                PerThreadFailures::value_type fail_pattern = 0;
                for (const Topology::Thread &thr : core->threads) {
                    auto this_pattern = per_thread_failures[thr.cpu()];
                    if (this_pattern == 0)
                        all_threads_failed_once = false;
                    if (++nthreads == 1) {
                        // first thread of this core (maybe only)
                        fail_pattern = this_pattern;
                    } else {
                        if (this_pattern != fail_pattern)
                            all_threads_failed_equally = false;
                        if (this_pattern && !fail_pattern)
                            fail_pattern = this_pattern;
                    }
                }

                if (fail_pattern == 0) {
                    continue;       // no failure
                } else if (nthreads == 1) {
                    logging_printf(LOG_LEVEL_VERBOSE(1), "# - Only thread of package %d core %d\n",
                                   int(p), int(c));
                } else if (all_threads_failed_equally) {
                    logging_printf(LOG_LEVEL_VERBOSE(1), "# - All threads of package %d core %d failed exactly the same way\n",
                                   int(p), int(c));
                } else if (all_threads_failed_once) {
                    logging_printf(LOG_LEVEL_VERBOSE(1), "# - All threads of package %d core %d failed at least once\n",
                                   int(p), int(c));
                } else {
                    logging_printf(LOG_LEVEL_VERBOSE(1), "# - Some threads of package %d core %d failed but some others succeeded\n",
                                   int(p), int(c));
                }
            }
        }
    }
}

static char character_for_mask(uint32_t mask)
{
    static_assert((1 << MAX_HWTHREADS_PER_CORE) <= 36, "Cannot represent this many threads");
    return mask < 0xa ? '0' + mask : 'a' + mask - 0xa;
}

std::string Topology::build_failure_mask(const struct test *test) const
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

namespace {
// Creates a string containing all socket temperatures like: "P0:30oC P2:45oC"
std::string format_socket_temperature_string(const std::vector<int> & temps)
{
    std::string temp_string;
    for (int i = 0; i < temps.size(); ++i){
        if (temps[i] != INVALID_TEMPERATURE){
            char buffer[64];
            sprintf(buffer, "P%d:%.1foC", i, temps[i]/1000.0);
            temp_string += std::string(buffer) + " ";
        }
    }
    return temp_string;
}
} // end anonymous namespace

void print_temperature_of_device()
{
    if (sApp->thermal_throttle_temp < 0)
        return;     // throttle disabled

    std::vector<int> temperatures = ThermalMonitor::get_all_socket_temperatures();

    if (temperatures.empty()) return; // Cant find temperature files at all (probably on windows)

    int highest_temp = *std::max_element(temperatures.begin(), temperatures.end());

    while ((highest_temp > sApp->thermal_throttle_temp) && sApp->threshold_time_remaining > 0) {

        if ((sApp->threshold_time_remaining % 1000) == 0) {
            logging_printf(LOG_LEVEL_VERBOSE(1),
                           "# CPU temperature (%.1foC) above threshold (%.1foC), throttling (%.1f s remaining)\n",
                           highest_temp / 1000.0, sApp->thermal_throttle_temp / 1000.0,
                           sApp->threshold_time_remaining / 1000.0);
            logging_printf(LOG_LEVEL_VERBOSE(1),
                    "# All CPU temperatures: %s\n", format_socket_temperature_string(temperatures).c_str());
        }

        const int throttle_ms = 100;
        usleep(throttle_ms * 1000);
        sApp->threshold_time_remaining -= throttle_ms;

        temperatures = ThermalMonitor::get_all_socket_temperatures();
        highest_temp = *max_element(temperatures.begin(), temperatures.end());
    }

    logging_printf(LOG_LEVEL_VERBOSE(1),
                   "# CPU temperatures: %s\n", format_socket_temperature_string(temperatures).c_str());
}

std::string build_failure_mask_for_topology(const struct test* test)
{
    return Topology::topology().build_failure_mask(test);
}

uint32_t mixin_from_device_info(int thread_num)
{
    auto& info = device_info[thread_num];
    auto mixin = scramble(static_cast<uint32_t>(info.core_id), static_cast<uint32_t>(info.package_id));
    mixin ^= [=](){
        switch (info.thread_id & 3) {
        case 0:     return 0x00000000U; // 0b00
        case 1:     return 0x55555555U; // 0b01
        case 2:     return 0xaaaaaaaaU; // 0b10
        case 3:     return 0xffffffffU; // 0b11
        }
        __builtin_unreachable();
    }();
    return mixin;
}
