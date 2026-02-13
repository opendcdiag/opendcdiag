/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"
#include "sandstone_p.h"
#include "sandstone_system.h"
#include "sandstone_opts.hpp"
#include "sandstone_run.hpp"
#include "sandstone_tests.h"
#include "interrupt_monitor.hpp"
#if SANDSTONE_SSL_BUILD
#  include "sandstone_ssl.h"
#  include "sandstone_ssl_rand.h"
#endif

#include <algorithm>
#include <chrono>
#include <map>
#include <vector>

#include <sys/mman.h>
#include <sys/stat.h>

#ifdef __linux__
#  include <sys/prctl.h>
#endif

#ifdef _WIN32
#  include <windows.h>
#  include <pdh.h>

#  ifdef ftruncate
// MinGW's ftruncate64 tries to check free disk space and that fails on Wine,
// so use the the 32-bit offset version (which calls _chsize)
#    undef ftruncate
#  endif
#endif

using namespace std::chrono;
using namespace std::chrono_literals;

static SandstoneTestSet *test_set;

static void find_thyself(char *argv0)
{
#ifndef __GLIBC__
    program_invocation_name = argv0;
#endif

#if defined(AT_EXECPATH)          // FreeBSD
    std::string &path = sApp->path_to_self;
    path.resize(PATH_MAX);
    if (elf_aux_info(AT_EXECPATH, &path[0], path.size()) == 0)
        path.resize(strlen(path.c_str()));
    else
        path.clear();
#endif
}

static void perror_for_mmap(const char *msg)
{
#ifdef _WIN32
    win32_perror(msg);
#else
    perror(msg);
#endif
}

static void attach_shmem_internal(int fd, size_t size)
{
    void *base = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        perror_for_mmap("internal error: could not map the shared memory file to memory");
        exit(EX_IOERR);
    }

    sApp->shmem = static_cast<SandstoneApplication::SharedMemory *>(base);

    assert(sApp->shmem->thread_data_offset);
    assert(sApp->shmem->main_thread_count);
    auto ptr = reinterpret_cast<unsigned char *>(sApp->shmem);
    ptr += sApp->shmem->thread_data_offset;

    sApp->main_thread_data_ptr = reinterpret_cast<PerThreadData::Main *>(ptr);
    ptr += ROUND_UP_TO_PAGE(sizeof(PerThreadData::Main) * sApp->shmem->main_thread_count);
    sApp->test_thread_data_ptr = reinterpret_cast<PerThreadData::Test *>(ptr);
}

static void init_shmem()
{
    using namespace PerThreadData;
    static_assert(sizeof(PerThreadData::Main) == 64,
            "PerThreadData::Main size grew, please check if it was intended");
    static_assert(sizeof(PerThreadData::Test) == 64,
            "PerThreadData::Test size grew, please check if it was intended");
    assert(sApp->current_fork_mode() != SandstoneApplication::ForkMode::child_exec_each_test);
    assert(sApp->shmem == nullptr);
    assert(thread_count());

    unsigned per_thread_size = sizeof(PerThreadData::Main);
    per_thread_size = ROUND_UP_TO(per_thread_size, alignof(PerThreadData::Test));
    per_thread_size += sizeof(PerThreadData::Test) * thread_count();
    per_thread_size = ROUND_UP_TO_PAGE(per_thread_size);

    unsigned thread_data_offset = sizeof(SandstoneApplication::SharedMemory) +
            sizeof(Topology::Thread) * thread_count();
    thread_data_offset = ROUND_UP_TO_PAGE(thread_data_offset);

    size_t size = thread_data_offset;

    // our child (if we have one) will inherit this file descriptor
    int fd = open_memfd(MemfdInheritOnExec);
    if (fd < 0 || ftruncate(fd, size) < 0) {
        perror("internal error: could not create temporary file for sharing memory");
        exit(EX_CANTCREAT);
    }

    void *base = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        perror_for_mmap("internal error: could not map the shared memory file to memory");
        exit(EX_CANTCREAT);
    }

    sApp->shmemfd = fd;
    sApp->shmem = new (base) SandstoneApplication::SharedMemory;
    sApp->shmem->thread_data_offset = thread_data_offset;
    sApp->shmem->main_process_pid = getpid();
}

static void commit_shmem()
{
    // the most detailed plan is the last
    const std::vector<DeviceRange> &plan = sApp->slice_plans.plans.end()[-1];
    size_t main_thread_count = plan.size();
    sApp->shmem->main_thread_count = main_thread_count;
    sApp->shmem->total_thread_count = thread_count();

    // unmap the current area, because Windows doesn't allow us to have two
    // blocks for this file
    ptrdiff_t offset = sApp->shmem->thread_data_offset;
    munmap(sApp->shmem, offset);

    // enlarge the file and map the extra data
    size_t size = sizeof(PerThreadData::Main) * main_thread_count;
    size = ROUND_UP_TO_PAGE(size);
    size += sizeof(PerThreadData::Test) * thread_count();
    size = ROUND_UP_TO_PAGE(size);

    if (ftruncate(sApp->shmemfd, offset + size) < 0) {
        perror("internal error: could not enlarge temporary file for sharing memory");
        exit(EX_CANTCREAT);
    }
    attach_shmem_internal(sApp->shmemfd, offset + size);

    if (sApp->current_fork_mode() != SandstoneApplication::ForkMode::exec_each_test) {
        close(sApp->shmemfd);
        sApp->shmemfd = -1;
    }

    // sApp->shmem has probably moved
    restrict_topology({ 0, thread_count() });
}

static void attach_shmem(int fd)
{
    assert(sApp->current_fork_mode() == SandstoneApplication::ForkMode::child_exec_each_test);

    size_t size;
    if (struct stat st; fstat(fd, &st) >= 0) {
        size = st.st_size;
        assert(size == ROUND_UP_TO_PAGE(size));
    } else {
        fprintf(stderr, "internal error: could not get the size of shared memory (fd = %d): %m\n",
                fd);
        exit(EX_IOERR);
    }

    attach_shmem_internal(fd, size);
    close(fd);

    // barrier with the parent process
    sApp->main_thread_data()->thread_state.exchange(thread_not_started, std::memory_order_acquire);
}

static auto collate_test_groups()
{
    struct Group {
        const struct test_group *definition = nullptr;
        std::vector<const struct test *> entries;
    };
    std::map<std::string_view, Group> groups;
    for (const auto &ti : *test_set) {
        for (auto ptr = ti.test->groups; ptr && *ptr; ++ptr) {
            Group &g = groups[(*ptr)->id];
            g.definition = *ptr;
            g.entries.push_back(ti.test);
        }
    }

    return groups;
}

static void list_tests(const ProgramOptions& opts)
{
    auto groups = collate_test_groups();
    int i = 0;

    for (const auto &ti : *test_set) {
        struct test *test = ti.test;
        if (test->quality_level >= sApp->requested_quality) {
            if (opts.list_tests_include_tests) {
                if (opts.list_tests_include_descriptions) {
                    printf("%i %-20s \"%s\"\n", ++i, test->id, test->description);
                } else if (sApp->shmem->cfg.verbosity > 0) {
                    // don't report the FW minimum CPU features
                    device_features_t feats = test->compiler_minimum_device & ~device_compiler_features;
                    feats |= test->minimum_cpu;
                    printf("%-20s %s\n", test->id, device_features_to_string(feats).c_str());
                } else {
                    puts(test->id);
                }
            }
        }
    }

    if (opts.list_tests_include_groups && !groups.empty()) {
        if (opts.list_tests_include_descriptions)
            printf("\nGroups:\n");
        for (const auto &pair : groups) {
            const auto &g = pair.second;
            if (opts.list_tests_include_descriptions) {
                printf("@%-21s \"%s\"\n", g.definition->id, g.definition->description);
                for (auto test : g.entries)
                    if (test->quality_level >= sApp->requested_quality)
                        printf("  %s\n", test->id);
            } else {
                // just the group name
                printf("@%s\n", g.definition->id);
            }
        }
    }
}

static void list_group_members(const char *groupname)
{
    auto groups = collate_test_groups();
    for (auto pair : groups) {
        const auto &g = pair.second;
        if (groupname[0] == '@' && strcmp(g.definition->id, groupname + 1) == 0) {
            for (auto test : g.entries)
                printf("%s\n", test->id);
            return;
        }
    }

    fprintf(stderr, "No such group '%s'\n", groupname);
    exit(EX_USAGE);
}

// Called every time we restart the tests
static void restart_init(int iterations)
{
}

static bool should_start_next_iteration(void)
{
    static int iterations = 0;
    ++iterations;

    Duration elapsed_time = MonotonicTimePoint::clock::now() - sApp->starttime;
    Duration average_time(elapsed_time.count() / iterations);
    logging_printf(LOG_LEVEL_VERBOSE(2), "# Loop iteration %d finished, average time %g ms, total %g ms\n",
                   iterations, std::chrono::nanoseconds(average_time).count() / 1000. / 1000,
                   std::chrono::nanoseconds(elapsed_time).count() / 1000. / 1000);


    if (!sApp->shmem->cfg.use_strict_runtime) {
        /* do we have time for one more run? */
        MonotonicTimePoint end = sApp->endtime;
        if (end != MonotonicTimePoint::max())
            end -= average_time;
        if (wallclock_deadline_has_expired(end))
            return false;
    }
    /* start from the beginning again */
    restart_init(iterations);
    return true;
}

static int open_runtime_file_internal(const char *name, int flags, int mode)
{
    assert(strchr(name, '/') == nullptr);
#ifdef __unix__
    static int dfd = []() {
        uid_t uid = getuid();
        if (uid != geteuid())
            return -1;              // don't trust the environment if setuid

        // open the directory pointed by $RUNTIME_DIRECTORY (see
        // systemd.exec(5)) and confirm it belongs to us
        const char *runtime_directory = getenv("RUNTIME_DIRECTORY");
        if (!runtime_directory || !runtime_directory[0])
            return -1;
        if (runtime_directory[0] != '/') {
            fprintf(stderr, "%s: $RUNTIME_DIRECTORY is not an absolute path; ignoring.\n",
                    program_invocation_name);
            return -1;
        }

        int dfd = open(runtime_directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd < 0)
            return dfd;

        // confirm its ownership
        struct stat st;
        if (fstat(dfd, &st) == 0) {
            if (st.st_uid == uid && S_ISDIR(st.st_mode) && (st.st_mode & ACCESSPERMS) == S_IRWXU)
                return dfd;
        }
        close(dfd);
        return -1;
    }();
    if (dfd < 0)
        return -1;

    // open the file
    flags|= O_CLOEXEC;
    return openat(dfd, name, flags, mode);
#else
    (void) name;
    (void) flags;
    (void) mode;
    return -1;
#endif
}

static int create_runtime_file(const char *name, int mode = S_IRWXU)
{
    return open_runtime_file_internal(name, O_CREAT | O_RDWR, mode);
}

/* Setup of the performance counters we read to get getloadavg() on linux. */
#ifdef _WIN32

/* We dynamically open pdh.dll because it's not always present in all Windows
   installations (notably lacking from WinPE). */
namespace {
struct PdhFunctions {
    decltype(&::PdhOpenQueryA) PdhOpenQueryA;
    decltype(&::PdhAddEnglishCounterA) PdhAddEnglishCounterA;
    decltype(&::PdhCollectQueryDataEx) PdhCollectQueryDataEx;
    decltype(&::PdhGetFormattedCounterValue) PdhGetFormattedCounterValue;

    bool load_library();
};
}
static PdhFunctions pdh;

/* Performance counters we are going to read */
static const char PQL_COUNTER_PATH[] = "\\System\\Processor Queue Length";
static HCOUNTER pql_counter;

static const char PT_COUNTER_PATH[]  = "\\Processor(_Total)\\% Processor Time";
static HCOUNTER pt_counter;


static constexpr unsigned TOTAL_5MIN_SAMPLES_COUNT = ((5u * 60u) / 5u);
static constexpr unsigned SAMPLE_INTERVAL_SECONDS = 5u;
static constexpr double   EXP_LOADAVG = exp(5.0 / (5.0 * 60.0)); // exp(5sec/5min)

static std::atomic<double> loadavg = 0.0;
static double last_tick_seconds;

bool PdhFunctions::load_library()
{
    HMODULE pdhDll = LoadLibraryExA("pdh.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!pdhDll)
        return false;

    auto getProc = [&](auto &pfn, const char *name) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
        pfn = reinterpret_cast<decltype(+pfn)>(GetProcAddress(pdhDll, name));
#pragma GCC diagnostic pop
        return pfn != nullptr;
    };

    if (getProc(PdhOpenQueryA, "PdhOpenQueryA")
            && getProc(PdhAddEnglishCounterA, "PdhAddEnglishCounterA")
            && getProc(PdhCollectQueryDataEx, "PdhCollectQueryDataEx")
            && getProc(PdhGetFormattedCounterValue, "PdhGetFormattedCounterValue"))
        return true;

    /* failed somehow */
    FreeLibrary(pdhDll);
    *this = {};
    return false;
}

static void loadavg_windows_callback(PVOID, BOOLEAN)
{
    PDH_FMT_COUNTERVALUE vpql, vpt;

    if (pdh.PdhGetFormattedCounterValue((PDH_HCOUNTER)pql_counter, PDH_FMT_DOUBLE, 0, &vpql) != ERROR_SUCCESS) {
        return;
    }

    if (pdh.PdhGetFormattedCounterValue((PDH_HCOUNTER)pt_counter, PDH_FMT_DOUBLE, 0, &vpt) != ERROR_SUCCESS) {
        return;
    }

    // We calculate current average load as average instantaenous cpu load plus amount of
    // tasks that are ready to run but cannot be scheduled because CPUs are already
    // running other tasks.
    //
    // We divide by 100.0 to get value in range (0.0;1.0) instead of percents.
    //
    // We also mutliply by number of cpus to make the metric behave more like the
    // /proc/loadavg from Linux, so we get value from range (0.0;thread_count()), where
    // thread_count() value means all cores at 100% utilization.
    const double current_avg_cpu_usage = (vpt.doubleValue * thread_count() / 100.0);
    const double current_proc_queue    = vpql.doubleValue;
    const double current_avg_load      = current_avg_cpu_usage + current_proc_queue;

    // Calculate how many sample windows we missed and adjust.
    const double current_tick_seconds  = GetTickCount64() / 1000.0;
    const double tick_diff_seconds     = current_tick_seconds - last_tick_seconds;
    const double sample_windows_count  = tick_diff_seconds / static_cast<double>(SAMPLE_INTERVAL_SECONDS);
    const double efactor               = 1.0 / pow(EXP_LOADAVG, sample_windows_count);

    // Exponential moving average, but don't allow values outside of range (0.0;thread_count()*2)
    double loadavg_ = loadavg.load(std::memory_order::relaxed);
    loadavg_ = loadavg_ * efactor + current_avg_load * (1.0 - efactor);
    loadavg_ = std::clamp(loadavg_, 0.0, static_cast<double>(thread_count()*2));

    last_tick_seconds = current_tick_seconds;
    loadavg.store(loadavg_, std::memory_order::relaxed);
}

static int setup_windows_loadavg_perf_counters()
{
    HQUERY load_query;
    HANDLE load_event;

    if (!pdh.load_library()) {
        win32_perror("Failed to load pdh.dll to determine when the system is idle");
        return 1;
    }

    last_tick_seconds = GetTickCount64() / 1000.0;

    if (pdh.PdhOpenQueryA(NULL, 0, &load_query) != ERROR_SUCCESS) {
        win32_perror("PdhOpenQueryA");
        return 2;
    }

    if (pdh.PdhAddEnglishCounterA(load_query, PQL_COUNTER_PATH, 0, &pql_counter)) {
        win32_perror("PdhAddEnglishCounterA on Processor Queue Length");
        return 3;
    }

    if (pdh.PdhAddEnglishCounterA(load_query, PT_COUNTER_PATH, 0, &pt_counter)) {
        win32_perror("PdhAddEnglishCounterA on Processor Time");
        return 4;
    }

    load_event = CreateEventA(NULL, FALSE, FALSE, "AvgLoad5sEvent");
    if (load_event == NULL) {
        win32_perror("CreateEvent");
        return 5;
    }

    if (pdh.PdhCollectQueryDataEx(load_query, SAMPLE_INTERVAL_SECONDS, load_event) != ERROR_SUCCESS) {
        win32_perror("PdhCollectQueryDataEx");
        return 6;
    }

    HANDLE h; // Dummy handle, we don't ever use it, It's closed by the system when the program exits.
    const int register_callback_status =
        RegisterWaitForSingleObject(&h, load_event, (WAITORTIMERCALLBACK)loadavg_windows_callback, NULL, INFINITE, WT_EXECUTEDEFAULT);

    if (register_callback_status == 0) {
        win32_perror("RegisterWaitForSingleObject");
        return 7;
    }

    return 0;
}
#endif // _WIN32

static void background_scan_init()
{
    using namespace SandstoneBackgroundScanConstants;
    struct FileLayout {
        std::atomic<int> initialized;
        std::atomic<int> dummy;
        std::array<MonotonicTimePoint::rep, 24> timestamp;
    };

    if (!sApp->service_background_scan)
        return;

    void *memblock = MAP_FAILED;
    int prot = PROT_READ | PROT_WRITE;
    int fd = create_runtime_file("timestamps");
    if (fd >= 0 && ftruncate(fd, sizeof(FileLayout)) >= 0) {
        int flags = MAP_SHARED;
        memblock = mmap(nullptr, sizeof(FileLayout), prot, flags, fd, 0);
    }
    if (memblock == MAP_FAILED) {
        // create an anonymous block, since we can't have a file
        int flags = MAP_ANONYMOUS | MAP_PRIVATE;
        memblock = mmap(nullptr, sizeof(FileLayout), prot, flags, -1, 0);
    }

    auto file = new (memblock) FileLayout;
    sApp->background_scan.timestamp = {
        reinterpret_cast<MonotonicTimePoint *>(file->timestamp.data()), file->timestamp.size()
    };
    if (file->initialized.exchange(true, std::memory_order_relaxed) == false) {
        // init timestamps to more than the batch testing time - this quickstarts
        // testing on first run
        MonotonicTimePoint now = MonotonicTimePoint::clock::now();
        std::fill(sApp->background_scan.timestamp.begin(), sApp->background_scan.timestamp.end(),
                  now - DelayBetweenTestBatch);
    }

    if (fd >= 0)
        close(fd);

#ifdef _WIN32
    if (setup_windows_loadavg_perf_counters() != 0) {
        // If setting up performance counters fail, assume system is never idle.
        loadavg.store(std::numeric_limits<double>::infinity(), std::memory_order_relaxed);
    }
#endif // _WIN32
}

static void preinit_tests()
{
    struct GroupReplacementEntry {
        decltype(test_group::group_init) group_init;
        initfunc replacement;
    };
    std::vector<GroupReplacementEntry> group_replacement_cache;
    auto cached_replacement = [&group_replacement_cache](const struct test_group *group) {
        if (!group->group_init)
            return initfunc(nullptr);

        auto it = std::ranges::find(group_replacement_cache, group->group_init,
                                    [](const GroupReplacementEntry &e) { return e.group_init; });
        if (it != group_replacement_cache.end())
            return it->replacement;

        // call the group init and cache the result
        GroupReplacementEntry e = { group->group_init, group->group_init() };
        group_replacement_cache.emplace_back(e);
        return e.replacement;
    };

    static const initfunc preinit_replacement = [](struct test*) {
        log_skip(RuntimeSkipCategory, "Skip replacement from preinit");
        return EXIT_SKIP;
    };
    int preinit_ret = EXIT_SUCCESS;

    for (test_cfg_info &cfg : *test_set) {
        struct test *test = cfg.test;
        preinit_ret = EXIT_SUCCESS;
        if (test->test_preinit) {
            preinit_ret = test->test_preinit(test);
            test->test_preinit = nullptr;   // don't rerun in case the test is re-added
        }

        // If the group_init function decides that the group cannot run at all,
        // it will return a pointer to a replacement function that will in turn
        // cause the test to fail or skip during test_init().
        bool group_init_failed = false;
        if (test->groups) {
            for (auto ptr = test->groups; *ptr; ++ptr) {
                const struct test_group *group = *ptr;
                initfunc group_init_replacement = cached_replacement(group);
                if (!group_init_replacement)
                    continue;
                group_init_failed = true;
                test->test_init = group_init_replacement;
                test->flags = test->flags | test_init_in_parent;
                break;
            }
        }

        // Skip from group init has precendence over preinit.
        if (!group_init_failed && preinit_ret != EXIT_SUCCESS) {
            test->test_init = preinit_replacement;
            test->flags = test->flags | test_init_in_parent; // for -fexec
        }
    }
}

static void postcleanup_tests()
{
    for (test_cfg_info &cfg : *test_set) {
        struct test *test = cfg.test;
        if (test->test_postcleanup) {
            auto ret = test->test_postcleanup(test);

            assert(ret == EXIT_SUCCESS && "Internal error: test_postcleanup must return EXIT_SUCCESS");
            PerThreadData::Main *main = sApp->main_thread_data();
            assert(!main->has_skipped() && !main->has_failed() && "Internal error: test_postcleanup must not cause test skip or fail");
        }
    }
}

static SandstoneTestSet::EnabledTestList::iterator get_first_test()
{
    logging_print_iteration_start();
    test_set->maybe_reshuffle();
    auto it = test_set->begin();
    while (it != test_set->end() && (it->test->quality_level < 0 && sApp->requested_quality >= 0))
        ++it;
    return it;
}

static SandstoneTestSet::EnabledTestList::iterator
get_next_test(SandstoneTestSet::EnabledTestList::iterator next_test)
{
    if (sApp->shmem->cfg.use_strict_runtime && wallclock_deadline_has_expired(sApp->endtime))
        return test_set->end();

    ++next_test;
    while (next_test != test_set->end() && (next_test->test->quality_level < 0 && sApp->requested_quality >= 0))
        ++next_test;
    if (next_test == test_set->end()) {
        if (should_start_next_iteration()) {
            return get_first_test();
        } else {
            return test_set->end();
        }
    }

    assert(next_test->test->id);
    assert(strlen(next_test->test->id));
    assert(SandstoneConfig::NoLogging || next_test->test->description);
    return next_test;
}

static bool wait_delay_between_tests()
{
    useconds_t useconds = duration_cast<microseconds>(sApp->delay_between_tests).count();
    // make the system call even if delay_between_tests == 0
    return usleep(useconds) == 0;
}

static int exec_mode_run(int argc, char **argv)
{
    if (argc < 4)
        return EX_DATAERR;

    auto parse_int = [](const char *arg) {
        char *end;
        long n = strtol(arg, &end, 10);
        if (__builtin_expect(int(n) != n || n < 0 || *end, false)) {
#if defined(_WIN32) && !defined(NDEBUG)
           if (*arg == 'h') {
               // a handle
               n = _open_osfhandle(strtoll(arg + 1, &end, 16), O_RDWR);
               if (n >= 0)
                   return int(n);
               perror("_open_osfhandle");
           }
#endif
            exit(EX_DATAERR);
        }
        return int(n);
    };
    int child_number = parse_int(argv[3]);

    attach_shmem(parse_int(argv[2]));
    device_info = sApp->shmem->device_info;
    sApp->thread_count = sApp->shmem->total_thread_count;
    sApp->user_thread_data.resize(sApp->thread_count);

    test_set = new SandstoneTestSet({ .is_selftest = sApp->shmem->cfg.selftest, }, SandstoneTestSet::enable_all_tests);
    std::vector<struct test *> tests_to_run = test_set->lookup(argv[0]);
    if (tests_to_run.size() != 1) return EX_DATAERR;

    logging_init_global_child();
    random_init_global(argv[1]);

    return test_result_to_exit_code(child_run(tests_to_run.at(0), child_number));
}

static void background_scan_update_load_threshold(MonotonicTimePoint now)
{
    using namespace SandstoneBackgroundScanConstants;

    hours time_from_last_test =
        duration_cast<hours>(now - sApp->background_scan.timestamp.front());

    // scale our idle threshold value from 0.2 base, to 0.8 after 12h
    // every hour adds 0.05 to the threshold value
    sApp->background_scan.load_idle_threshold =
        sApp->background_scan.load_idle_threshold_init +
        (time_from_last_test.count() * sApp->background_scan.load_idle_threshold_inc_val);

    // prevent the idle threshold form rising above 0.8
    if(sApp->background_scan.load_idle_threshold > sApp->background_scan.load_idle_threshold_max)
        sApp->background_scan.load_idle_threshold = sApp->background_scan.load_idle_threshold_max;
}

static float system_idle_load()
{
#ifdef __linux__
    FILE *loadavg;
    float load_5;
    int ret;

    // Look at loadavg for hints whether the system is reasonably idle or not
    // any error and we assume it's busy/under load for simplicity

    loadavg = fopen("/proc/loadavg", "r");
    if (!loadavg)
        return std::numeric_limits<float>::infinity();

    ret = fscanf(loadavg, "%*f %f %*f", &load_5);
    fclose(loadavg);

    if (ret == 1)
       return load_5;
#elif defined(_WIN32)
    return loadavg.load(std::memory_order::relaxed);
#else //__linux__
    return std::numeric_limits<float>::lowest();
#endif

    // this shouldn't happen!
    // assume the system isn't idle
    return std::numeric_limits<float>::infinity();
}

// Don't run tests unless load is low or it's time to run a test anyway
static bool background_scan_wait()
{
    auto as_seconds = [](Duration d) -> int { return duration_cast<seconds>(d).count(); };

    auto do_wait = [](Duration base_wait, Duration variable) -> bool {
        microseconds ubase = duration_cast<microseconds>(base_wait);
        microseconds uvar = duration_cast<microseconds>(variable);

        // randomize the delay by multiplying it between -1.0 and 1.0
        float random_factor = frandomf_scale(2.0) - 1.0f;
        auto deviation = duration_cast<microseconds>(uvar * random_factor);
        microseconds sleep_time = ubase + deviation;

        return usleep(sleep_time.count()) == 0;
    };
    using namespace SandstoneBackgroundScanConstants;

    // move all timestaps except the oldest one
    auto array_data = sApp->background_scan.timestamp.data();
    std::move(array_data, array_data + sApp->background_scan.timestamp.size() - 1,
              array_data + 1);

    MonotonicTimePoint now = MonotonicTimePoint::clock::now();
    sApp->background_scan.timestamp.front() = now;

    // Don't run too many tests in a short period of time
    Duration elapsed = now - sApp->background_scan.timestamp.back();
    if (Duration expected_start = DelayBetweenTestBatch - elapsed; expected_start > 0s) {
        expected_start += MinimumDelayBetweenTests;
        logging_printf(LOG_LEVEL_VERBOSE(2), "# Background scan: %zu tests completed in "
                                             "%d s, waiting %d +/- %d s\n",
                       sApp->background_scan.timestamp.size(), as_seconds(elapsed),
                       as_seconds(expected_start), as_seconds(MinimumDelayBetweenTests));
        if (!do_wait(expected_start, MinimumDelayBetweenTests)) {
            return false;
        }
        goto skip_wait;
    }

    logging_printf(LOG_LEVEL_VERBOSE(3), "# Background scan: waiting %d +/- 10%% s\n",
                   as_seconds(MinimumDelayBetweenTests));
    while (1) {
        if (!do_wait(MinimumDelayBetweenTests, MinimumDelayBetweenTests / 10)) {
            return false;
        }

skip_wait:
        now = MonotonicTimePoint::clock::now();
        background_scan_update_load_threshold(now);

        // if the system is idle, run a test
        float idle_load = system_idle_load();
        if (idle_load < sApp->background_scan.load_idle_threshold) {
            logging_printf(LOG_LEVEL_VERBOSE(2), "# Background scan: system is sufficiently idle "
                                                 "(%.2f; below %.2f), executing next test\n",
                           idle_load, sApp->background_scan.load_idle_threshold);
            break;
        }

        // if we haven't run *any* tests in the last x hours, run a test
        // because of day/night cycles, 12 hours should help typical data center
        // duty cycles.
        if (now > (sApp->background_scan.timestamp.front() + MaximumDelayBetweenTests)) {
            logging_printf(LOG_LEVEL_VERBOSE(2), "# Background scan: system has gone too long"
                                                 " without a test -- forcing one now\n");
            break;
        }

        logging_printf(LOG_LEVEL_VERBOSE(3), "# Background scan: system is not idle "
                                             "(%.2f; above %.2f), waiting %d +/- 10%% s\n",
                       idle_load, sApp->background_scan.load_idle_threshold,
                       as_seconds(MinimumDelayBetweenTests));
    }
    return true;
}

__attribute__((weak, noclone, noinline)) void print_application_banner()
{
}

__attribute__((weak, noclone, noinline)) void device_specific_init()
{
}

int main(int argc, char **argv)
{
    // initialize the main application
    new (sApp) SandstoneApplication;

    int total_failures = 0;
    int total_successes = 0;
    int total_skips = 0;

    thread_num = -1;            /* indicate main thread */
    find_thyself(argv[0]);
    setup_stack_size(argc, argv);
#ifdef __linux__
    prctl(PR_SET_TIMERSLACK, 1, 0, 0, 0);
#endif

    if (argc > 1 && strcmp(argv[1], "-x") == 0) {
        /* exec mode is when a brand new child is launched for each test, as opposed to
         * just forked. set when the child is launched with '-x' option by the parent
         * running with '-f exec' or on Windows. */
        sApp->fork_mode = SandstoneApplication::ForkMode::child_exec_each_test;

        return exec_mode_run(argc - 2, argv + 2);
    }

    bool any_device = false;
    {
        auto enabled_devices = detect_devices<EnabledDevices>();
        if (!enabled_devices.empty()) {
            any_device = true;
            init_shmem();
            setup_devices(std::move(enabled_devices));
        }
    }

    ProgramOptions opts;
    if (int ret = parse_cmdline(argc, argv, sApp, opts); ret != EXIT_SUCCESS) {
        return ret;
    }
    if (any_device) {
        // copy data from cfg that needs to be in shared memory
        sApp->shmem->cfg = std::move(opts.shmem_cfg);
    }

    if (opts.test_tests) {
        sApp->enable_test_tests();
        if (sApp->test_tests_enabled()) {
            // disable other options that don't make sense in this mode
            sApp->retest_count = 0;
        }
    }

    if (!opts.deviceset.empty() && any_device) {
        for (auto& d : opts.deviceset) {
            apply_deviceset_param(d);
        }
    }

    static auto check_and_exit_for_no_device = [&]() {
        if (!any_device) {
            fprintf(stderr, "%s: error: no devices found\n",
                    program_invocation_name);
            exit(EX_OSERR);
        }
    };

    switch (opts.action) {
    case Action::dump_cpu_info:
        check_and_exit_for_no_device();
        dump_device_info();
        return EXIT_SUCCESS;
    case Action::list_tests:
        test_set = new SandstoneTestSet(opts.test_set_config, SandstoneTestSet::enable_all_tests);
        list_tests(opts);
        return EXIT_SUCCESS;
    case Action::list_group:
        test_set = new SandstoneTestSet(opts.test_set_config, SandstoneTestSet::enable_all_tests);
        list_group_members(opts.list_group_name.c_str());
        return EXIT_SUCCESS;
    case Action::version:
        logging_print_version();
        return EXIT_SUCCESS;
    case Action::exit:
        return EXIT_SUCCESS;
    case Action::run:
        check_and_exit_for_no_device();
        break; // continue program
    }
    sApp->device_scheduler = make_rescheduler(sApp->shmem->cfg.reschedule_mode);

    if (sApp->current_fork_mode() == SandstoneApplication::ForkMode::exec_each_test) {
        if (sApp->shmem->cfg.log_test_knobs) {
            fprintf(stderr, "%s: error: --test-option is not supported in this configuration\n",
                    program_invocation_name);
            return EX_USAGE;
        }
        if (sApp->device_scheduler) {
            sApp->device_scheduler = nullptr;
            logging_printf(LOG_LEVEL_VERBOSE(1), "# WARNING: --reschedule is not supported in this configuration\n");
        }
    }

    if (sApp->total_retest_count < -1 || sApp->retest_count == 0)
        sApp->total_retest_count = 10 * sApp->retest_count; // by default, 100

    if (unsigned(opts.thread_count) < unsigned(sApp->thread_count))
        restrict_topology({ 0, opts.thread_count });
    slice_plan_init(opts.max_cores_per_slice);
    commit_shmem();

    signals_init_global();
    resource_init_global();
    random_init_global(opts.seed);
    debug_init_global(opts.on_hang_arg, opts.on_crash_arg);
    background_scan_init();
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, nullptr);

    if (opts.enabled_tests.size() || opts.builtin_test_list_name || opts.test_list_file_path) {
        /* if anything other than the "all tests" has been specified, start with
         * an empty list. */
        test_set = new SandstoneTestSet(opts.test_set_config, 0);
    } else {
        /* otherwise, start with all the applicable tests (self tests or
         * regular. */
        test_set = new SandstoneTestSet(opts.test_set_config, SandstoneTestSet::enable_all_tests);
    }

    /* Add all the tests we were told to enable. */
    if (opts.enabled_tests.size()) {
        for (auto name : opts.enabled_tests) {
            auto tis = test_set->add(name);
            if (!tis.size() && !opts.test_set_config.ignore_unknown_tests) {
                fprintf(stderr, "%s: Cannot find matching tests for '%s'\n", program_invocation_name, name);
                exit(EX_USAGE);
            }
        }
    }

    /* Add the test list file */
    if (opts.test_list_file_path) {
        std::vector<std::string> errors;
        test_set->add_test_list(opts.test_list_file_path, errors);
        if (!errors.empty()) {
            fprintf(stderr, "Error loading test list file %s:\n", opts.test_list_file_path);
            for (auto i = errors.begin(); i != errors.end(); i++) {
                fprintf(stderr, "    %s\n", (*i).c_str());
            }
            exit(EX_USAGE);
        }
    }

    if (opts.builtin_test_list_name) {
        std::vector<std::string> errors;
        test_set->add_builtin_test_list(opts.builtin_test_list_name, errors);
        if (!errors.empty()) {
            // FIXME: handle errors
            ;
            exit(EX_USAGE);
        }
    }

    /* Add device-specific monitoring tests to the set. They will be kept last by
     * SandstoneTestSet in case randomization is requested. */
    for (auto special_test : test_set->get_special_tests()) {
        if (special_test != &mce_test || (special_test == &mce_test && !sApp->ignore_mce_errors))
            test_set->add(special_test);
    }

    /* Remove all the tests we were told to disable */
    if (opts.disabled_tests.size()) {
        for (auto name : opts.disabled_tests) {
            test_set->remove(name);
        }
    }

    if (sApp->shmem->cfg.verbosity < LOG_LEVEL_QUIET) {
        sApp->shmem->cfg.verbosity = LOG_LEVEL_QUIET;
        if (sApp->requested_quality < SandstoneApplication::DefaultQualityLevel)
            sApp->shmem->cfg.verbosity = LOG_LEVEL_VERBOSE(1);
    }

    if (InterruptMonitor::InterruptMonitorWorks && test_set->contains(&mce_test)) {
        if (sApp->current_fork_mode() == SandstoneApplication::ForkMode::exec_each_test) {
            test_set->remove(&mce_test);
        } else if (InterruptMonitor::get_mce_interrupt_counts().empty()) {
            logging_printf(LOG_LEVEL_QUIET, "# WARNING: Cannot detect MCE events - you may be running in a VM - MCE checking disabled\n");
            test_set->remove(&mce_test);
        }
    }

    if (thread_count() < 2 && sApp->device_scheduler)
        logging_printf(LOG_LEVEL_QUIET, "# WARNING: --reschedule is only useful with at least 2 threads\n");

#if SANDSTONE_FREQUENCY_MANAGER
    if (sApp->vary_frequency_mode || sApp->vary_uncore_frequency_mode)
        sApp->frequency_manager = std::make_unique<FrequencyManager>();

    //if --vary-frequency mode is used, do a initial setup for running different frequencies
    if (sApp->vary_frequency_mode)
        sApp->frequency_manager->initial_core_frequency_setup();

    //if --vary-uncore-frequency mode is used, do a initial setup for running different frequencies
    if (sApp->vary_uncore_frequency_mode)
        sApp->frequency_manager->initial_uncore_frequency_setup();
#endif

    print_application_banner();
    logging_init_global();
    device_specific_init();

#ifndef __OPTIMIZE__
    logging_printf(LOG_LEVEL_VERBOSE(1), "THIS IS AN UNOPTIMIZED BUILD: DON'T TRUST TEST TIMING!\n");
#endif

#if SANDSTONE_SSL_BUILD
    if (SANDSTONE_SSL_LINKED || sApp->current_fork_mode() != SandstoneApplication::ForkMode::exec_each_test) {
        sandstone_ssl_init();
        sandstone_ssl_rand_init();
    }
#endif

    logging_print_header(argc, argv, test_duration(), test_timeout(test_duration()));

    PerThreadFailures per_thread_failures;

    sApp->current_test_count = 0;
    int total_tests_run = 0;
    TestResult lastTestResult = TestResult::Skipped;

    preinit_tests();
    for (auto it = get_first_test(); it != test_set->end(); it = get_next_test(it)) {
        if (lastTestResult != TestResult::Skipped) {
            if (sApp->service_background_scan) {
                if (!background_scan_wait()) {
                    logging_printf(LOG_LEVEL_VERBOSE(2), "# Background scan: waiting between tests interrupted\n");
                    break;
                }
            } else {
                if (!wait_delay_between_tests()) {
                    logging_printf(LOG_LEVEL_VERBOSE(2), "# Test execution interrupted between tests\n");
                    break;
                }
            }
        }

        lastTestResult = run_one_test(*it, per_thread_failures);

        total_tests_run++;
        if (lastTestResult == TestResult::Failed) {
            ++total_failures;
            if (opts.fatal_errors)
                break;
        } else if (lastTestResult == TestResult::Passed) {
            ++total_successes;
        } else if (lastTestResult == TestResult::Skipped) {
            ++total_skips;
            if (sApp->fatal_skips)
                break;
        }
        if (total_tests_run >= sApp->max_test_count)
            break;
    }
    postcleanup_tests();

    if (total_failures) {
        logging_print_footer();
    } else if (sApp->shmem->cfg.verbosity == 0 && sApp->shmem->cfg.output_format == SandstoneApplication::OutputFormat::tap) {
        logging_printf(LOG_LEVEL_QUIET, "Ran %d tests without error (%d skipped)\n",
                       total_successes, total_tests_run - total_successes);
    }

    int exit_code = EXIT_SUCCESS;
    if (total_failures || (total_skips && sApp->fatal_skips))
        exit_code = EXIT_FAILURE;

    // done running all the tests, clean up and exit
    return cleanup_global(exit_code, std::move(per_thread_failures));
}
