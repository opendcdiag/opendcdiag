/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Prioritized Test Selector
 *    This test selector will run all the tests whose weight is higher than
 *    SCREEN_PRIORITY_TEST_WEIGHT_THRESHOLD and then select tests based on the
 *    non-repeating test selector until it is finished.
 */

#ifndef SANDSTONE_PRIORITIZEDSELECTOR_H
#define SANDSTONE_PRIORITIZEDSELECTOR_H

#include "WeightedSelectorBase.h"
#include "WeightedNonRepeatingSelector.h"

#define SCREEN_PRIORITY_TEST_WEIGHT_THRESHOLD  20


// ===================================================================================================================
//
//   Prioritized Weighted Testrun selector:
//
//       This selector is designed to pick the tests in weighted order but run a subset of
//       high priority tests before it begins randomly picking tests
//
// ===================================================================================================================
class PrioritizedTestrunSelector : public NonRepeatingWeightedTestrunSelector {
protected:
    std::list<weighted_run_info *> high_priority_tests;

public:

    void load_weights(weighted_run_info *runinfo, WeightedTestLength length_adjustment) override {
        NonRepeatingWeightedTestrunSelector::load_weights(runinfo, length_adjustment);
        populate_priority_test_list();
    }


    weighted_run_info * select_test() override {
        if (high_priority_tests.empty()) {
            return NonRepeatingWeightedTestrunSelector::select_test();
        } else {
            auto entry = high_priority_tests.front();
            high_priority_tests.pop_front();
            return entry;
        }
    }


    void populate_priority_test_list() {
        for (auto iter = weighted_runinfo.begin(); iter != weighted_runinfo.end(); ){
            auto entry = *iter;
            if (entry->weight >= SCREEN_PRIORITY_TEST_WEIGHT_THRESHOLD){
                high_priority_tests.emplace_back(entry);

                // Ensure test does not get randomly selected on first iteration
                // make_entry_selected will delete the current item in the list so
                // we need to do this little dance with the iterator pointer to
                // prevent a seg-fault on advancing the pointer.
                auto temp = iter;
                iter++;
                mark_entry_selected(temp);

            } else {
                iter++;
            }
        }
    }

};


#endif //SANDSTONE_PRIORITIZEDSELECTOR_H
