/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __WEIGHTEDTESTRUNSELECTOR_H
#define __WEIGHTEDTESTRUNSELECTOR_H

#include <span>

// Include base class
#include "TestrunSelectorBase.h"

inline void disable_test(struct test *test)
{
    test->quality_level = TEST_QUALITY_SKIP;
}

void add_test(std::vector<struct test *> &test_list, /*nonconst*/ struct test *test);
void add_tests(std::span<struct test> test_set, std::vector<struct test *> &test_list,
               const char *name);
void disable_tests(std::span<struct test> test_set, const char *name);
void generate_test_list(std::vector<struct test *> &test_list, std::span<struct test> test_set,
                               int min_quality = sApp->requested_quality);

extern TestrunSelector * setup_test_selector(
        WeightedTestScheme         selectScheme,
        WeightedTestLength         lengthScheme,
        std::vector<struct test *> tests,
        struct weighted_run_info * weight_info);

extern TestrunSelector * create_list_file_test_selector(std::vector<struct test *> tests, std::string file_path, int first_index, int last_index, bool randomize);

#endif //__WEIGHTEDTESTRUNSELECTOR_H

