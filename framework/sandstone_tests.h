/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_SANDSTONE_TESTS_H
#define INC_SANDSTONE_TESTS_H

#include <cstring>
#include <iterator>
#include <map>
#include <stddef.h>
#include "sandstone.h"

#ifdef __cplusplus
#include <span>

extern "C" {
#endif

struct weighted_run_info
{
    struct test *test;
    int weight;
    int duration_ms;

    // populated at runtime
    unsigned int test_index;
};

extern struct test __start_tests;
extern struct test __stop_tests;

#ifdef __cplusplus

enum WeightedTestLength : int8_t {
    ShortenedTestrunTimes,
    NormalTestrunTimes,
    LongerTestrunTimes,
};

enum WeightedTestScheme : int8_t {
    Repeating,
    NonRepeating,
    Prioritized,
    Alphabetical,
    Ordered,
};

__attribute__((weak)) extern const struct test_group __start_test_group;
__attribute__((weak)) extern const struct test_group __stop_test_group;

inline std::span<struct test> regular_tests = { &__start_tests, &__stop_tests };
extern const std::span<struct test> selftests;

#if defined(__linux__) && defined(__x86_64__)
extern struct test mce_test;
#else
// no MCE test outside Linux
static_assert(!InterruptMonitor::InterruptMonitorWorks);
struct test mce_test = {
#ifdef TEST_ID_mce_check
    .id = SANDSTONE_STRINGIFY(TEST_ID_mce_check),
    .description = nullptr,
#else
    .id = "mce_check",
    .description = "Machine Check Exceptions/Events count",
#endif
    .quality_level = TEST_QUALITY_SKIP
};
#endif


class SandstoneTestSet
{
    using TestSet = std::vector<struct test *>;
public:
    enum InitSet {
        REGULAR_TESTS,
        SELF_TESTS,
        NO_TESTS,
    };

    SandstoneTestSet() : SandstoneTestSet(REGULAR_TESTS) {
    };

    SandstoneTestSet(enum InitSet init_set) : is_selftest(init_set == SELF_TESTS) {
        if (init_set == NO_TESTS) return;
        std::span<struct test> source = !is_selftest ? regular_tests : selftests;
        for (struct test &test : source) {
            struct test_info *ti = new struct test_info;
            ti->st = TEST_ENABLED;
            ti->test = &test;
            test_map[test.id] = ti;
            test_set.push_back(&test);
        }
    };

    TestSet::iterator begin() { return test_set.begin(); };
    TestSet::iterator end () { return test_set.end(); };

    struct test *get_by_name(const char *name);
    int disable(struct test test);
    std::vector<struct test *> disable(const char *name);
    int enable(struct test test);
    std::vector<struct test *> enable(const char *name);
    inline bool is_disabled(const char *name) { return test_map.contains(name) ? (test_map[name]->st == TEST_DISABLED) : true; };
    inline bool is_enabled(const char *name) { return !is_disabled(name); };
    
    static void init(enum InitSet);
    static std::vector<struct test *> lookup(const char *name);

    struct cstr_cmp
    {
        bool operator() (char const *a, char const *b) const { return std::strcmp(a, b) < 0; }
    };


private:
    bool is_selftest;
    TestSet test_set;

    typedef enum {
        TEST_ENABLED,
        TEST_DISABLED,
    } test_rt_status;

    struct test_info {
        struct test *test;
        test_rt_status st;
    };

    std::map<const char *, struct test_info *, cstr_cmp> test_map;
};


}
#endif

#endif /* INC_SANDSTONE_TESTS_H */
