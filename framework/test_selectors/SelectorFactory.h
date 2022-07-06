/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __WEIGHTEDTESTRUNSELECTOR_H
#define __WEIGHTEDTESTRUNSELECTOR_H

// Include base class
#include "TestrunSelectorBase.h"

extern TestrunSelector * setup_test_selector(
        WeightedTestScheme         selectScheme,
        WeightedTestLength         lengthScheme,
        std::vector<struct test *> tests,
        struct weighted_run_info * weight_info);

extern TestrunSelector * create_list_file_test_selector(std::vector<struct test *> tests, std::string file_path, int first_index, int last_index, bool randomize);
extern TestrunSelector * create_builtin_test_selector(std::vector<struct test *> tests, int first_index, int last_index);

#endif //__WEIGHTEDTESTRUNSELECTOR_H

