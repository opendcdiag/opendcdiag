/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_SANDSTONE_TESTS_H
#define INC_SANDSTONE_TESTS_H

#include <stddef.h>
#include "sandstone.h"

#ifdef __cplusplus
#include <span>
#include <cstring>
#include <iterator>
#include <map>

extern "C" {
#endif

extern struct test __start_tests;
extern struct test __stop_tests;

extern struct test mce_test;

typedef enum {
    TEST_ENABLED,
    TEST_DISABLED,
} test_rt_status;

struct test_rt_info {
    struct test *test;
    test_rt_status st;
};

#ifdef __cplusplus

__attribute__((weak)) extern const struct test_group __start_test_group;
__attribute__((weak)) extern const struct test_group __stop_test_group;

inline std::span<struct test> regular_tests = { &__start_tests, &__stop_tests };
extern const std::span<struct test> selftests;

class SandstoneTestSet
{
public:
    using TestSet = std::vector<struct test *>;

    static std::vector<struct test *> lookup(const char *name);

    SandstoneTestSet() : SandstoneTestSet(false) {
    };

    SandstoneTestSet(bool all_tests) : SandstoneTestSet(true, false) {
    };

    SandstoneTestSet(bool all_tests, bool is_selftest);

    TestSet::iterator begin() { return test_set.begin(); };
    TestSet::iterator end () { return test_set.end(); };

    struct test *get_by_name(const char *name);

    std::vector<struct test_rt_info> disable(const char *name);
    struct test_rt_info disable(struct test *t);

    std::vector<struct test_rt_info> enable(const char *name);
    struct test_rt_info enable(struct test *t);

    inline bool is_disabled(const char *name) { return test_map.contains(name) ? (test_map[name].st == TEST_DISABLED) : true; };
    inline bool is_enabled(const char *name) { return !is_disabled(name); };

    TestSet add_test_list(const char *name);

    struct cstr_cmp
    {
        bool operator() (char const *a, char const *b) const { return std::strcmp(a, b) < 0; }
    };


private:
    bool is_selftest;
    TestSet test_set;

    std::map<const char *, struct test_rt_info, cstr_cmp> test_map;
};


}
#endif

#endif /* INC_SANDSTONE_TESTS_H */
