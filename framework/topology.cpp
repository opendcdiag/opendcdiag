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

struct cpu_info *cpu_info = nullptr;

static int topo_gen = 0; // topology version, incremented each time load_cpu_info is executed

#ifdef __linux__
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

static void reorder_cpus()
{
    static auto cpu_tuple = [](const struct cpu_info &c) {
        uint64_t h = (uint64_t(c.package_id) << 32) +
                unsigned(c.core_id);
        uint64_t l = ((uint64_t(c.thread_id)) << 32) +
                unsigned(c.cpu_number);
        return std::make_tuple(h, l);
    };

    auto cpu_compare = [](const struct cpu_info &cpu1, const struct cpu_info &cpu2) {
        return cpu_tuple(cpu1) < cpu_tuple(cpu2);
    };
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
    // similar to load_cpu_info's loop below
    int count = sApp->thread_count = std::min<int>(mock_topology.size(), enabled_cpus.count());
    for (int i = 0, curr_cpu = 0; i < count; ++i, ++curr_cpu) {
        while (!enabled_cpus.is_set(LogicalProcessor(curr_cpu))) {
            ++curr_cpu;
            assert(curr_cpu != MAX_THREADS);
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

static void init_cpu_info(struct cpu_info *info, int os_cpu) {
    memset(info, 0, sizeof(struct cpu_info));
    /* fill everything with -1 to indicate n/a and set the OS cpu id. */
    info->cpu_number = os_cpu;
    info->package_id = -1;
    info->core_id = -1;
    info->thread_id = -1;

    std::fill(std::begin(info->cache), std::end(info->cache), cache_info{-1, -1});
}

static int fill_topo_sysfs(struct cpu_info *info)
{
#ifdef __linux__
    FILE *f;

    auto_fd cpufd = open_sysfs_cpu_dir(info->cpu_number);
    if (cpufd < 0)
        return 1;

    // Read the topology
    f = fopenat(cpufd, "topology/physical_package_id");
    if (!f)
        return 1;
    IGNORE_RETVAL(fscanf(f, "%d", &info->package_id));
    fclose(f);

    f = fopenat(cpufd, "topology/core_id");
    if (!f)
        return 1;
    IGNORE_RETVAL(fscanf(f, "%d", &info->core_id));
    fclose(f);

    f = fopenat(cpufd, "topology/thread_siblings_list");
    if (!f)
        return 1;
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

    return 0;
#else /* __linux__ */
    return 1;
#endif /* __linux__ */

}

#ifdef __x86_64__
static int fill_family_cpuid(struct cpu_info *info)
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
        return 0;           // first logical processor, nothing to compare to

    assert(size_t(info - cpu_info) < size_t(num_cpus()));
    if (info->package_id == info[-1].package_id)
        return 0;           // same socket, so if there's a discrepancy it's already reported

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

    return 0;
}

static int fill_topo_cpuid(struct cpu_info *info)
{
    int curr_cpu = info->cpu_number;
    int subleaf = 0;
    uint32_t a, b, c, d;
    uint32_t smt_mask = 0,
             core_shift = 0,
             core_mask = 0,
             pkg_shift = 0;

    if (curr_cpu < 0)
        return 1;

    do {
        int lvl_type;
        __cpuid_count(0xb, subleaf, a, b, c, d);
        if (!b) break;
        lvl_type = (c >> 8) & 0xff;
        switch (lvl_type) {
            case 1:
                core_shift = a & 0xf;
                smt_mask = (1 << core_shift) - 1;
                info->thread_id = d & smt_mask;
                break;
            case 2:
                pkg_shift = a & 0xf;
                core_mask = (1 << (pkg_shift - core_shift)) - 1;
                info->core_id = (d >> core_shift) & core_mask;
                break;
            default:
                break;
        }
        subleaf++;
    } while (1);
    info->package_id = d >> pkg_shift;
    return 0;
}

static int fill_ucode_msr(struct cpu_info *info)
{
    uint64_t ucode = 0;

    if (!read_msr(info->cpu_number, 0x8B, &ucode)) return 1;
    info->microcode = (uint32_t)(ucode >> 32);

    return 0;
}
#else
constexpr auto fill_family_cpuid = nullptr;
constexpr auto fill_ucode_msr = nullptr;
constexpr auto fill_topo_cpuid = nullptr;
#endif // x86-64

static int fill_ucode_sysfs(struct cpu_info *info)
{
#ifdef __linux__
    FILE *f;
    auto_fd cpufd { open_sysfs_cpu_dir(info->cpu_number) };
    if (cpufd < 0)
        return 1;

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
    return info->microcode == 0 ? 0 : 1;
#elif defined(_WIN32)
    HKEY hKey = (HKEY)-1;
    LONG lResult = ERROR_SUCCESS;
    int rc = 1;
    
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
                
                rc = 0; // success
            }
        }
    }
    
    if (hKey)
    {
        RegCloseKey(hKey);
    }

    return rc;
#else
    return 1;
#endif /* __linux__ */
}

#ifdef __x86_64__
static int fill_ppin_msr(struct cpu_info *info)
{
    info->ppin = 0;
    return !read_msr(info->cpu_number, 0x4F, (uint64_t *)&info->ppin); /* MSR_PPIN */
}

static int fill_cache_info_cpuid(struct cpu_info *info) {
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

    return 0;
}
#else
constexpr auto fill_ppin_msr = nullptr;
constexpr auto fill_cache_info_cpuid = nullptr;
#endif // __x86_64__

static int fill_ppin_sysfs(struct cpu_info *info)
{
    int ret = 1;
#if defined(__linux__) && defined(__x86_64__)
    auto_fd cpufd = open_sysfs_cpu_dir(info->cpu_number);
    if (cpufd < 0)
        return 1;

    if (AutoClosingFile f { fopenat(cpufd, "topology/ppin") }) {
        if (fscanf(f, "%" PRIx64, &info->ppin) > 0)
            ret = 0;
    }
#endif

    return ret;
}

static int fill_cache_info_sysfs(struct cpu_info *info)
{
#ifdef __linux__
    FILE *f;
    char buf[256];  // size repeated in fscanf below

    sprintf(buf, "/sys/devices/system/cpu/cpu%d", info->cpu_number);
    auto_fd cpufd{open(buf, O_PATH | O_CLOEXEC)};
    if (cpufd < 0)
        return 1;

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
    return 0;
#else /* __linux__ */
    return 1;
#endif /*__linux__ */
}

template <auto &fnArray> static int try_detection(struct cpu_info *cpu)
{
    using DetectorFunction = std::decay_t<decltype(fnArray[0])>;
    if (std::size(fnArray) > 0) {
        if (std::size(fnArray) == 1) {
            // no need to cache, there's only one implementation
            DetectorFunction fn = fnArray[0];
            return fn ? fn(cpu) : 0;
        }

        static DetectorFunction cached_fn = nullptr;
        if (cached_fn)
            return cached_fn(cpu);

        for (DetectorFunction fn : fnArray) {
            if (!fn)
                continue;
            int r = fn(cpu);
            if (r == EXIT_SUCCESS) {
                cached_fn = fn;
                return r;
            }
        }
    }
    return EXIT_FAILURE;
}

typedef int (* fill_family_func)(struct cpu_info *);
typedef int (* fill_ppin_func)(struct cpu_info *);
typedef int (* fill_ucode_func)(struct cpu_info *);
typedef int (* fill_cache_info_func)(struct cpu_info *);
typedef int (* fill_topo_func)(struct cpu_info *);

static const fill_family_func family_impls[] = { fill_family_cpuid };
static const fill_ppin_func ppin_impls[] = { fill_ppin_sysfs, fill_ppin_msr };
/* prefer sysfs, fallback to MSR. the latter is not reliable and may require
 * root. */
static const fill_ucode_func ucode_impls[] = { fill_ucode_sysfs, fill_ucode_msr };
/* prefer CPUID, fallback to sysfs. */
static const fill_cache_info_func cache_info_impls[] = { fill_cache_info_cpuid, fill_cache_info_sysfs };
/* prefer CPUID, fallback to sysfs. */
static const fill_topo_func topo_impls[] = { fill_topo_cpuid, fill_topo_sysfs };

void apply_cpuset_param(char *param)
{
    if (SandstoneConfig::RestrictedCommandLine)
        return;
    LogicalProcessorSet sys_cpuset = ambient_logical_processor_set();
    int max_cpu_count = sys_cpuset.count();
    int total_matches = 0;
    if (cpu_info == nullptr)
        load_cpu_info(sys_cpuset);

    LogicalProcessorSet &result = sApp->shmem->enabled_cpus;
    result.clear();

    for (char *arg = strtok(param, ","); arg; arg = strtok(nullptr, ",")) {
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
        auto add_to_set = [&](LogicalProcessor lp) {
            if (!result.is_set(lp)) {
                result.set(lp);
                ++total_matches;
            }
        };

        char c = *arg;
        if (c >= '0' && c <= '9') {
            // logical processor number
            auto lp = LogicalProcessor(parse_int());
            if (!sys_cpuset.is_set(lp)) {
                fprintf(stderr, "%s: error: Invalid CPU set parameter: %s (no such logical processor)\n",
                        program_invocation_name, orig_arg);
                exit(EX_USAGE);
            }
            if (*arg != '\0') {
                fprintf(stderr, "%s: error: Invalid CPU set parameter: %s (could not parse)\n",
                        program_invocation_name, orig_arg);
                exit(EX_USAGE);
            }
            add_to_set(lp);
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
            for (int i = 0; i < max_cpu_count; ++i) {
                if (!sys_cpuset.is_set(LogicalProcessor(i)))
                    continue;
                if (package != -1 && cpu_info[i].package_id != package)
                    continue;
                if (core != -1 && cpu_info[i].core_id != core)
                    continue;
                if (thread != -1 && cpu_info[i].thread_id != thread)
                    continue;
                add_to_set(LogicalProcessor(i));
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

    assert(total_matches == result.count());
    sApp->thread_count = total_matches;
}

void load_cpu_info(const LogicalProcessorSet &enabled_cpus)
{
    sApp->thread_count = enabled_cpus.count();
    assert(sApp->thread_count);

    delete[] cpu_info;
    cpu_info = new struct cpu_info[sApp->thread_count];
    topo_gen++;

    if (SandstoneConfig::Debug) {
        static auto mock_topology = create_mock_topology(getenv("SANDSTONE_MOCK_TOPOLOGY"));
        if (mock_topology.size())
            return apply_mock_topology(mock_topology, enabled_cpus);
    }

    auto detect = [](void *ptr) -> void * {
        auto enabled_cpus = *static_cast<const LogicalProcessorSet *>(ptr);
        int curr_cpu = 0;
        for (int i = 0; i < sApp->thread_count; ++i, ++curr_cpu) {
            auto lp = LogicalProcessor(curr_cpu);
            while (!enabled_cpus.is_set(lp)) {
                lp = LogicalProcessor(++curr_cpu);
                assert(curr_cpu != MAX_THREADS);
            }

            pin_to_logical_processor(lp);
            init_cpu_info(&cpu_info[i], curr_cpu);
            try_detection<family_impls>(&cpu_info[i]);
            try_detection<ppin_impls>(&cpu_info[i]);
            try_detection<ucode_impls>(&cpu_info[i]);
            try_detection<cache_info_impls>(&cpu_info[i]);
            try_detection<topo_impls>(&cpu_info[i]);
        }
        return nullptr;
    };

    pthread_t detection_thread;
    pthread_create(&detection_thread, nullptr, detect, const_cast<LogicalProcessorSet *>(&enabled_cpus));
    pthread_join(detection_thread, nullptr);

    if (sApp->schedule_by == SandstoneApplication::ScheduleBy::Core)
        reorder_cpus();
}


static Topology build_topology()
{
    std::vector<Topology::Package> packages;

    bool valid_topology = true;
    for (int i = 0; i < num_cpus(); ++i) {
        struct cpu_info *info = &cpu_info[i];
        if (info->package_id < 0 || info->core_id < 0 || info->thread_id < 0) {
            valid_topology = false;
            break;
        }

        if (packages.size() <= size_t(info->package_id))
            packages.resize(info->package_id + 1);

        Topology::Package *pkg = &packages[info->package_id];
        if (pkg->id == -1) pkg->id = info->package_id;
        if (pkg->cores.size() <= size_t(info->core_id))
            pkg->cores.resize(info->core_id + 1);

        Topology::Core *core = &pkg->cores[info->core_id];
        if (core->id == -1) core->id = info->core_id;
        if (core->threads.size() <= size_t(info->thread_id))
            core->threads.resize(info->thread_id + 1);
        Topology::Thread *thr = &core->threads[info->thread_id];

        if (thr->cpu != -1) {
            valid_topology = false;
            break;
        }

        thr->cpu = i;
        thr->oscpu = info->cpu_number;
        thr->id = info->thread_id;
    }

    if (!valid_topology)
        packages.clear();

    return Topology(packages);
}

Topology Topology::topology()
{
    static int cached_topo_gen = -1;
    static Topology cached_topology = Topology({});

    if (cached_topo_gen != topo_gen) {
        cached_topology = build_topology();
        cached_topo_gen = topo_gen;
    }

    return cached_topology;
}

static char character_for_mask(uint32_t mask)
{
    static_assert((1 << MAX_HWTHREADS_PER_CORE) <= 36, "Cannot represent this many threads");
    return mask < 0xa ? '0' + mask : 'a' + mask - 0xa;
}

std::string Topology::build_falure_mask(const struct test *test)
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
            for (Thread &t : core.threads) {
                int cpu_id = t.cpu;
                if (cpu_id < 0)
                    continue;

                if (sApp->thread_data(cpu_id)->has_failed()) {
                    threadmask |= 1U << t.id;
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
