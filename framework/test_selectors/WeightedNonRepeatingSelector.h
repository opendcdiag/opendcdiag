/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Non-repeating test selector
 *    This test selector will use the test weights to select tests but will not
 *    allow a test to be selected again until after all other tests have also been
 *    selected.
 */

#ifndef SANDSTONE_WEIGHTEDNONREPEATINGSELECTOR_H
#define SANDSTONE_WEIGHTEDNONREPEATINGSELECTOR_H

#include "WeightedSelectorBase.h"


// ===================================================================================================================
//
//   Non-Repeating Weighted Testrun selector:
//
//       This selector is designed to pick the tests in weighted order but go through all tests
//       before coming back around and allowing a duplicate test to be selected
//
// ===================================================================================================================
class NonRepeatingWeightedTestrunSelector : public WeightedTestrunSelector
{
protected:
    std::list<weighted_run_info *> saved_weighted_runinfo;
    int saved_sum_of_weights = -1;


public:
    NonRepeatingWeightedTestrunSelector(std::vector<test *> _tests)
        : WeightedTestrunSelector(std::move(_tests))
    {
    }

    void load_weights(weighted_run_info *runinfo, WeightedTestLength length_adjustment) override {
        general_setup_from_structs(runinfo, length_adjustment);
        saved_weighted_runinfo = weighted_runinfo;
        saved_sum_of_weights = sum_of_weights;
    }

    weighted_run_info * select_test() override {
        if (sum_of_weights <= 0) {
            reset_selector();
            return nullptr;  // Signals end of test list
        }
        return pick_entry_using_weighted_value(random32() % sum_of_weights);
    }

    void mark_entry_selected(std::list<weighted_run_info *>::iterator &item) override {
        sum_of_weights -= (*item)->weight;
        weighted_runinfo.erase(item);
    }

    void reset_selector() override {
        weighted_runinfo = saved_weighted_runinfo;  // restore the test list
        sum_of_weights = saved_sum_of_weights;  // restore the sum of the weights
    }

    std::unordered_map<std::string, int>  test_selection_distribution(int num_trials, int reset_interval) {
        std::unordered_map<std::string, int> counts;

        for(const auto &p : testid_to_index_map)
            counts[p.first] = 0;

        for (int i = 0; i < num_trials; i++) {
            if (i % reset_interval == 0)
                reset_selector();
            counts[select_test()->test->id]++;
        }

        return counts;
    }
};


#endif //SANDSTONE_WEIGHTEDNONREPEATINGSELECTOR_H
