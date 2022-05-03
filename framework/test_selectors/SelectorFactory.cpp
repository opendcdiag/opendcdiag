/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <unordered_map>
#include <vector>
#include "sandstone.h"
#include "SelectorFactory.h"

#include "weighted_runs.h"

using namespace std;

// TODO: Next steps are to relocate this functionality so this file is nothing but #include statements

extern TestrunSelector * setup_test_selector(
        WeightedTestScheme         selectScheme,
        WeightedTestLength         lengthScheme,
        std::vector<struct test *> tests,
        struct weighted_run_info * weight_info)
{
    TestrunSelector * selector;

    switch (selectScheme){
        case Repeating:
            selector = new RepeatingWeightedTestrunSelector();
            selector->set_test_list(tests);
            ((WeightedTestrunSelector *) selector)->load_weights(weight_info, lengthScheme);
            break;
        case NonRepeating:
            selector = new NonRepeatingWeightedTestrunSelector();
            selector->set_test_list(tests);
            ((WeightedTestrunSelector *) selector)->load_weights(weight_info, lengthScheme);
            break;
        case Prioritized:
            selector = new PrioritizedTestrunSelector();
            selector->set_test_list(tests);
            ((WeightedTestrunSelector *) selector)->load_weights(weight_info, lengthScheme);
            break;
        case Alphabetical:
            selector = new AlphabeticalTestSelector();
            selector->set_test_list(tests);
            break;
        case Ordered:
            selector = new OrderedTestSelector();
            selector->set_test_list(tests);
            break;
        default:
            fprintf(stderr, "ERROR: Cannot run with testrunner type (%d)", selectScheme);
            exit(EX_USAGE);
    }

    return selector;
}

// TODO: Next cleanup - change this from test selector to simply a test_list fileter
//       That way it can be used with any selector :-)
extern TestrunSelector * create_list_file_test_selector(std::vector<struct test *> tests, string file_path, int first_index, int last_index, bool randomize){
    auto selector = new ListFileTestSelector();
    selector->set_test_list(std::move(tests));
    selector->load_from_file(file_path);
    selector->set_selection_range(first_index, last_index, randomize);
    return selector;
}

extern TestrunSelector * create_builtin_test_selector(std::vector<struct test *> tests, int first_index, int last_index)
{
    auto selector = new ListFileTestSelector();
    selector->set_test_list(std::move(tests));
    selector->load_from_array(weighted_testlist);
    selector->set_selection_range(first_index, last_index, true);
    return selector;
}

