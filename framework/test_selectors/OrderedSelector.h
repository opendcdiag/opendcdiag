/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_ORDEREDSELECTOR_H
#define SANDSTONE_ORDEREDSELECTOR_H
#include "TestrunSelectorBase.h"

class OrderedTestSelector : public TestrunSelector {
public:
    int current_test_index = 0;

    void set_test_list(std::vector<struct test *> _tests) override {
        TestrunSelector::set_test_list(_tests);
    }

    struct test *get_next_test() override {
        if (current_test_index == testinfo.size()) {
            current_test_index = 0;
            return nullptr;
        }
        return testinfo[current_test_index++];
    }
};



#endif //SANDSTONE_ORDEREDSELECTOR_H
