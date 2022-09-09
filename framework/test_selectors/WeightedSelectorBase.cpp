/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "WeightedSelectorBase.h"

using namespace std;

void WeightedTestrunSelector::general_setup_from_structs(weighted_run_info *weights, WeightedTestLength length_adjust) {
    this->test_length_scheme = length_adjust;
    add_all_weights(weights);
    adjust_runinfo();
}

// Adjust the runinfo to put defaults in place for unspecified fields
void WeightedTestrunSelector::adjust_runinfo() {
    for (auto & info : weighted_runinfo)
        info->duration_ms = adjust_runinfo_duration(info);
}

int WeightedTestrunSelector::lookup_test_index(const char * test_id_string)  {
    if (auto it = testid_to_index_map.find(test_id_string); it != testid_to_index_map.end()) {
        return it->second;
    } else {
        fprintf(stderr, "ERROR: Attempted to access non-existent test index\n");
        exit(EX_USAGE);
    }
}

unsigned int WeightedTestrunSelector::adjust_runinfo_duration(weighted_run_info * runinfo_ptr) {
    unsigned int duration;
    test * testinfo_ptr = runinfo_ptr->test;
    // If the duration is specified in the runinfo structure (duration_ms > 0) then
    // we use that value as the duration, otherwise we use the test struct value
    duration = (runinfo_ptr->duration_ms > 0) ? runinfo_ptr->duration_ms : testinfo_ptr->desired_duration;

    if (test_length_scheme == ShortenedTestrunTimes)
        duration /= 2;

    else if (test_length_scheme == LongerTestrunTimes)
        duration = max(testinfo_ptr->desired_duration, runinfo_ptr->duration_ms);

    else if (test_length_scheme == NormalTestrunTimes)
        duration = runinfo_ptr->duration_ms;

    return duration;
}

// This map is needed to quickly get the test structure from the test id
// TODO: Move this to a TestRegistry class that all can use
void WeightedTestrunSelector::create_testid_to_index_map()
{
    for(int test_index=0; test_index < testinfo.size(); test_index++) {
        testid_to_index_map[testinfo[test_index]->id] = test_index;
    }
}

void WeightedTestrunSelector::add_all_weights(weighted_run_info *runinfo)
{
    if (!runinfo)
        return;

    // We need to create runinfo entries for tests that are not listed in the test weights list
    // We do this because unspecified tests still need to be run - we just weight them low
    // We start off by saying all tests are unspecified and remove them from the list as we go
    auto map_of_unspecified_tests = testid_to_index_map;

    for(int i=0; runinfo[i].test != NULL; i++){
        map_of_unspecified_tests.erase(runinfo[i].test->id); // Remove test from unspecified test list

        if (should_add_weight(&runinfo[i])) {
            runinfo[i].test_index = lookup_test_index(runinfo[i].test->id);
            add_weighted_runinfo(&runinfo[i]);
        }

    }

    create_weight_entries_for_unspecified_tests(map_of_unspecified_tests);
}

void WeightedTestrunSelector::create_weight_entries_for_unspecified_tests(const unordered_map<string, int> &map_of_unspecified_tests) {
    for (const auto &[key, test_index] : map_of_unspecified_tests){
        weighted_run_info * entry = create_default_runinfo_entry(test_index);
        if (should_add_weight(entry)){
            add_weighted_runinfo(entry);
        } else {
            delete entry;
        }
    }
}

weighted_run_info * WeightedTestrunSelector::create_default_runinfo_entry(int test_index) const {
    auto entry = new weighted_run_info();
    entry->test_index = test_index;
    entry->test = testinfo[test_index];
    entry->weight = 1;
    entry->duration_ms = WEIGHTED_TESTRUNNER_DEFAULT_DURATION;
    return entry;
}

bool WeightedTestrunSelector::should_add_weight(const weighted_run_info * runinfo)
{

    if (testid_to_index_map.find(runinfo->test->id) == testid_to_index_map.end()) return false;
    if (runinfo->test->quality_level < sApp->requested_quality) return false;
    if (runinfo->weight <= 0)  return false;

    return true;
}

void WeightedTestrunSelector::add_weighted_runinfo(weighted_run_info * info)
{
    weighted_runinfo.push_back(info);
    sum_of_weights += info->weight;
}

// Review Question: Is this the proper return type here - should it be a * or &
weighted_run_info * WeightedTestrunSelector::pick_entry_using_weighted_value(unsigned int weighted_value)
{
    uint32_t count = 0;
    list<weighted_run_info *>::iterator  iter;
    for (iter = weighted_runinfo.begin(); iter != weighted_runinfo.end(); ++iter){
        count += (*iter)->weight;
        if (count > weighted_value) {    // Never make this >= because it will break the distribution
            auto selected_entry = *iter; // need to save because mark_entry_selected may delete the entry
            mark_entry_selected(iter);   // Need iterator to be passed, so I have to do this here!
            return selected_entry;
        }
    }
    fprintf(stderr, "SANITY_ERROR: Should never get here!. Weighted test selector failed to find test (count=%d sum_of_weights=%d)\n", count, sum_of_weights);
    exit(EX_CONFIG);
}
