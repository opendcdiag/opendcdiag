/*
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * NOTE: This is a private include file of the sandstone framework and should
 * be included only by sandstone.cpp
 */

#include "sandstone_p.h"

#include <array>
#include <initializer_list>

#if SANDSTONE_RESTRICTED_CMDLINE
#  define TEST_GROUP(name, descr)   .id = nullptr, .description = nullptr
#else
#  define TEST_GROUP(name, descr)   .id = name, .description = descr
#endif

constexpr struct test_group group_compression = {
    TEST_GROUP("compression",
               "Tests that drive compression routines in various libraries"),
};

constexpr struct test_group group_math = {
    TEST_GROUP("math",
               "Tests that perform math using, e.g., Eigen"),
};

static constexpr std::initializer_list<const test_group *> all_test_groups = {
    &group_compression,
    &group_math
};

static constexpr size_t count_groups_with_init()
{
    size_t n = 0;
    for (const test_group *group : all_test_groups)
        n += group->group_init ? 1 : 0;
    return n;
}

static constexpr auto test_groups_with_init()
{
    std::array<const test_group *, count_groups_with_init()> result = {};
    size_t i = 0;
    for (const test_group *group : all_test_groups)
        if (group->group_init)
            result[i++] = group;
    return result;
}

static constexpr auto test_group_inits()
{
    std::array<decltype(test_group::group_init), count_groups_with_init()> result = {};
    size_t i = 0;
    for (const test_group *group : all_test_groups)
        if (group->group_init)
            result[i++] = group->group_init;
    return result;
}
