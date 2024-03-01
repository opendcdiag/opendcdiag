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

    /* A custom iterator is needed to be able to wrap around (cycle through)
     * the test set when needed. If end, a pointer to test_set.end(), is
     * specified, then it will wrap when *end is reached. Otherwise, it would
     * behave as a normal forward iterator. */
    struct TestSetIterator
    {
        using iterator_category = std::forward_iterator_tag;
        using difference_type = ptrdiff_t;
        using value_type = struct test *;
        using pointer = struct test **;
        using reference = struct test *&;

        TestSetIterator(TestSet::iterator it, TestSet::iterator *end) noexcept : it(it), start(it), end(end) {};

        reference operator*() const noexcept { return *it; };
        pointer operator->() noexcept { return &(*it); };

        TestSetIterator& operator++() noexcept { next(); return *this; };
        TestSetIterator operator++(int) noexcept { TestSetIterator ret = *this; ++(*this); return ret; };

        friend bool operator== (const TestSetIterator &a, const TestSetIterator &b) noexcept { return a.it == b.it; };
        friend bool operator!= (const TestSetIterator &a, const TestSetIterator &b) noexcept { return a.it != b.it; };

    private:
        TestSet::iterator it;
        TestSet::iterator start; /* the state the iterator would wrap around to. */
        TestSet::iterator *end; /* if not a nullptr, indicates an infinite iterator. */

        void next() noexcept {
            if (end && it + 1 == *end) {
                it = start;
                /* whenever we're restarting, print the header for the next
                 * iteration. */
                logging_print_iteration_start();
            }
            else
                it++;
        }
    };

    enum Flag {
        enable_all_tests    = 1 << 0,
    };

    /* searches the test by name in all the available tests. */
    TestSet lookup(const char *name);

    SandstoneTestSet(struct test_set_cfg cfg, unsigned int flags);

    TestSetIterator begin() {
        TestSet::iterator end = test_set.end();
        if (cfg.randomize) {
            /* Do not shuffle mce_check if present. */
            auto last = *(end - 1) == &mce_test ? end - 1 : end;
            std::shuffle(test_set.begin(), last, SandstoneURBG());
        }
        return TestSetIterator(test_set.begin(), cfg.cycle_through ? &end : nullptr);
    };

    TestSetIterator end() {
        return TestSetIterator(test_set.end(), nullptr);
    };

    std::vector<struct test_cfg_info> disable(const char *name);
    struct test_cfg_info disable(struct test *t);

    std::vector<struct test_cfg_info> enable(const char *name);
    struct test_cfg_info enable(struct test *t);

    bool is_disabled(const char *name) { auto it = test_map.find(name); return (it != test_map.end() ? (it->second).status == test_cfg_info::disabled : true); };
    bool is_enabled(const char *name) { return !is_disabled(name); };

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
    std::map<std::string_view, TestSet> all_group_map;
    /* maps test name to current instance configuration. */
    std::map<std::string_view, struct test_cfg_info> test_map;

    /* actual set of tests that is included in this instance. */
    TestSet test_set;

    test_set_cfg cfg;
    unsigned int flags;

    void load_all_tests();
};

}
#endif

#endif /* INC_SANDSTONE_TESTS_H */
