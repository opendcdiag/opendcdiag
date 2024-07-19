/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_SANDSTONE_TESTS_H
#define INC_SANDSTONE_TESTS_H

#include <stddef.h>

#include "sandstone.h"
#include "sandstone_p.h"
#include <sandstone_test_lists.h>

#ifdef __cplusplus
#include <algorithm>
#include <iterator>
#include <map>
#include <span>

extern "C" {
#endif

extern struct test __start_tests;
extern struct test __stop_tests;

extern struct test mce_test;

struct test_set_cfg {
    bool ignore_unknown_tests;  /* whether an error should be reported if
                                   there's no test matching the specified name,
                                   either on command-line or in a test list. */
    bool randomize;             /* iterate through the tests in random order. */
    bool cycle_through;         /* start over when an iteration through the test
                                   set has finished. */
    bool is_selftest;           /* whether to use regular or selftests as the
                                   source of the tests. */
};

struct test_cfg_info {
    enum test_status {
        disabled = 0,
        enabled = 1,
        not_found = -1,
    };
    struct test *test = nullptr;
    std::string attribute;
    test_status status = not_found;

    /* implicit */ test_cfg_info(struct test *test = nullptr) : test(test) {}
};

#ifdef __cplusplus

__attribute__((weak)) extern const struct test_group __start_test_group;
__attribute__((weak)) extern const struct test_group __stop_test_group;

inline std::span<struct test> regular_tests = { &__start_tests, &__stop_tests };
#ifdef NO_SELF_TESTS
constexpr const std::span<struct test> selftests = {};
#else
extern const std::span<struct test> selftests;
#endif

class SandstoneTestSet
{
public:
    using TestSet = std::vector<struct test *>;
    using EnabledTestList = std::vector<test_cfg_info>;

    enum Flag {
        enable_all_tests    = 1 << 0,
    };

    /* searches the test by name in all the available tests. */
    TestSet lookup(const char *name);

    SandstoneTestSet(struct test_set_cfg cfg, unsigned int flags);

    // note: not idempotent, we may shuffle every time! */
    EnabledTestList::iterator begin() noexcept
    {
        if (cfg.randomize) {
            /* Do not shuffle mce_check if present. */
            auto end = test_set.end();
            auto last = end[-1].test == &mce_test ? end - 1 : end;
            std::shuffle(test_set.begin(), last, SandstoneURBG());
        }
        return test_set.begin();
    };

    EnabledTestList::iterator end() noexcept { return test_set.end(); }

    int disable(const char *name);
    int disable(const struct test *t);

    std::vector<struct test_cfg_info> enable(const char *name);
    struct test_cfg_info enable(test_cfg_info t);

    bool is_enabled(struct test *test) const
    {
        return std::any_of(test_set.begin(), test_set.end(), [&](const test_cfg_info &ti) {
            return ti.test == test;
        });
    }

    std::vector<struct test_cfg_info> add_test_list(const char *name, std::vector<std::string> &errors);

    std::vector<struct test_cfg_info> add_builtin_test_list(const char *name, std::vector<std::string> &errors);

private:
    /* Make a Uniform Random Bit Generator to use our own random as opposed to
     * standard library's. */
    struct SandstoneURBG {
        using result_type = uint32_t;
        static constexpr result_type min() { return 0; };
        static constexpr result_type max() { return UINT32_MAX; };
        result_type operator()() { return random32(); };
    };

    /* list of all available tests. */
    TestSet all_tests;
    /* maps group name to a vector of tests it contains. */
    std::map<std::string_view, std::vector<struct test *>> all_group_map;

    /* actual set of tests that is included in this instance. */
    EnabledTestList test_set;

    test_set_cfg cfg;
    unsigned int flags;

    void load_all_tests();
};

}
#endif

#endif /* INC_SANDSTONE_TESTS_H */
