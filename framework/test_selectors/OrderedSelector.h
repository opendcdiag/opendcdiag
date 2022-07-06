/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_ORDEREDSELECTOR_H
#define SANDSTONE_ORDEREDSELECTOR_H

#include "TestrunSelectorBase.h"
#include <algorithm>

class OrderedTestSelector : public TestrunSelector
{
    int current_test_index = 0;
public:
    OrderedTestSelector(std::vector<struct test *> _tests, WeightedTestScheme scheme = Ordered)
        : TestrunSelector(std::move(_tests))
    {
        if (scheme == Alphabetical) {
            // sort the list
            std::sort(testinfo.begin(), testinfo.end(), [](const test *a, const test *b) {
                // Returns true if a should be before b
                // Note: mce_check always has to be last.
                extern test mce_test;
                if (a == &mce_test)
                    return false;
                if (b == &mce_test)
                    return true;

                return strcmp(a->id, b->id) < 0;
            });
        }
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
