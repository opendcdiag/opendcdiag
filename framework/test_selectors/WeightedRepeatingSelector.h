/*
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Repeating test selector
 *    This test selector will use the test weights to select tests without regard
 *    to repeated selections.  Note that this selector will never return NULL which
 *    is normally used by the framework to detect the end of the list.  This means
 *    using this selector without using the -T option to limit the execution will result
 *    in the program running forever.
 */

#ifndef SANDSTONE_WEIGHTEDREPEATINGSELECTOR_H
#define SANDSTONE_WEIGHTEDREPEATINGSELECTOR_H

#include "WeightedSelectorBase.h"

// ===================================================================================================================
//
//   Repeating Weighted Testrun selector
//
//       This selector grabs a test based on weighted average but will allow tests
//       to be selected without regard to repeated selections
//
// ===================================================================================================================
class RepeatingWeightedTestrunSelector : public WeightedTestrunSelector {
public:
    weighted_run_info *select_test() override {
        if (sum_of_weights == 0) {
            fprintf(stderr, "SANITY ERROR: Should Never get here - weighted test selector failed to find test to run"
                            " because no weights have been loaded or all weights were 0");
            exit(EX_SOFTWARE);
        }
        return pick_entry_using_weighted_value(random32() % sum_of_weights);
    }

    void load_weights(weighted_run_info *runinfo, WeightedTestLength length_adjustment) override {
        general_setup_from_structs(runinfo, length_adjustment);
    }

    void mark_entry_selected(std::list<weighted_run_info *>::iterator &item) override {
        /* Do nothing - no need to mark selection on repeating selector.  We want to allow repeated selections*/
    }

    // Used by self-checking test to determine proper distribution of test selections
    std::unordered_map<std::string, int> test_selection_distribution(int num_trials) {
        std::unordered_map<std::string, int> counts;

        for(const auto &p : testid_to_index_map)
            counts[p.first] = 0;

        for (int i = 0; i < num_trials; i++)
            counts[ select_test()->test->id]++;

        return counts;
    }
};


#endif //SANDSTONE_WEIGHTEDREPEATINGSELECTOR_H
