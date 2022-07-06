/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "SelectorFactory.h"

#include "ListFileSelector.h"
#include "OrderedSelector.h"
#include "PrioritizedSelector.h"
#include "WeightedNonRepeatingSelector.h"
#include "WeightedRepeatingSelector.h"

#include <unordered_map>
#include <vector>
#include "sandstone.h"
#include "sandstone_p.h"

#include "weighted_runs.h"

using namespace std;

// TODO: Next steps are to relocate this functionality so this file is nothing but #include statements

extern TestrunSelector * setup_test_selector(
        WeightedTestScheme         selectScheme,
        WeightedTestLength         lengthScheme,
        std::vector<struct test *> tests,
        struct weighted_run_info * weight_info)
{
    switch (selectScheme) {
    case Alphabetical:
    case Ordered:
        return new OrderedTestSelector(std::move(tests), selectScheme);
    default:
        break;
    }

    if constexpr (SandstoneConfig::RestrictedCommandLine) {
        SANDSTONE_UNREACHABLE("Should not have reached here");
        return nullptr;
    }

    WeightedTestrunSelector *selector;
    switch (selectScheme){
        case Repeating:
            selector = new RepeatingWeightedTestrunSelector(std::move(tests));
            break;
        case NonRepeating:
            selector = new NonRepeatingWeightedTestrunSelector(std::move(tests));
            break;
        case Prioritized:
            selector = new PrioritizedTestrunSelector(std::move(tests));
            break;
        default:
            fprintf(stderr, "ERROR: Cannot run with testrunner type (%d)", selectScheme);
            exit(EX_USAGE);
    }
    selector->load_weights(weight_info, lengthScheme);

    return selector;
}

// TODO: Next cleanup - change this from test selector to simply a test_list fileter
//       That way it can be used with any selector :-)
TestrunSelector *create_list_file_test_selector(std::vector<struct test *> tests, string file_path,
                                                int first_index, int last_index, bool randomize)
{
    if constexpr (SandstoneConfig::RestrictedCommandLine) {
        SANDSTONE_UNREACHABLE("Should not have reached here");
        return nullptr;
    }

    auto selector = new ListFileTestSelector(std::move(tests));
    selector->load_from_file(file_path);
    selector->set_selection_range(first_index, last_index, randomize);
    return selector;
}

extern TestrunSelector * create_builtin_test_selector(std::vector<struct test *> tests, int first_index, int last_index)
{
    auto selector = new ListFileTestSelector(std::move(tests));
    selector->load_from_array(weighted_testlist);
    selector->set_selection_range(first_index, last_index, true);
    return selector;
}

