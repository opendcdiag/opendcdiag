/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_WEIGHTEDSELECTORBASE_H
#define SANDSTONE_WEIGHTEDSELECTORBASE_H

#include <list>
#include <vector>
#include <unordered_map>

#include "TestrunSelectorBase.h"

#define WEIGHTED_TESTRUNNER_DEFAULT_DURATION  300

class WeightedTestrunSelector : public TestrunSelector {
protected:
    std::list<weighted_run_info *> weighted_runinfo;
    uint32_t sum_of_weights = 0;

    // TODO: Move this out to a separate TestRegistry class that everyone can use
    std::unordered_map<std::string, int>  testid_to_index_map;

    WeightedTestLength  test_length_scheme;

public:


    struct test * get_next_test() override{
        auto weighted_info = this->select_test();
        test * next_test = testinfo[weighted_info->test_index];
        if (next_test != nullptr)
            next_test->desired_duration = weighted_info->duration_ms;
        return next_test;

    }
    void set_test_list(std::vector<struct test *> _tests) override {
        TestrunSelector::set_test_list(_tests);
        create_testid_to_index_map();
    }

    virtual weighted_run_info * select_test() = 0;

    void general_setup_from_structs(weighted_run_info *weights, WeightedTestLength length_adjust);
    void add_weighted_runinfo(weighted_run_info * info);

    weighted_run_info * pick_entry_using_weighted_value(unsigned int weighted_value);
    bool should_add_weight(const weighted_run_info * runinfo);

    void create_testid_to_index_map();
    void add_all_weights(weighted_run_info *runinfo);
    void adjust_runinfo();


    unsigned int adjust_runinfo_duration(weighted_run_info * runinfo_ptr);
    int lookup_test_index(const char * test_id_string);
    weighted_run_info *create_default_runinfo_entry(int test_index) const;
    void create_weight_entries_for_unspecified_tests(const std::unordered_map<std::string, int> &map_of_unspecified_tests);

    // For testing purposes only!!!
    std::list<weighted_run_info *> get_weighted_runinfo_list(){ return weighted_runinfo; }

    // virtual functions to be overridden
    virtual void load_weights(weighted_run_info *runinfo, WeightedTestLength length_adjustment) = 0;
    virtual void mark_entry_selected(std::list<weighted_run_info *>::iterator &item) = 0;
};


#endif //SANDSTONE_WEIGHTEDSELECTORBASE_H
