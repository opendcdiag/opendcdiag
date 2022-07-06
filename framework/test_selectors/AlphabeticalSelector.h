/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Alphabetical test selector
 *    Will return tests in alphabetical order by test->id
 */

#ifndef SANDSTONE_ALPHABETICALSELECTOR_H
#define SANDSTONE_ALPHABETICALSELECTOR_H

#include "TestrunSelectorBase.h"
#include <string>
#include <algorithm>

class AlphabeticalTestSelector : public TestrunSelector {
public:
    AlphabeticalTestSelector(std::vector<struct test *> _tests)
        : OrderedTestSelector(std::move(_tests))
    {
        sort(testinfo.begin(), testinfo.end(), sortByID);
    }


    static bool sortByID(const test *a, const test *b) {
        // Returns true if a should be before b
        // Note: mce_check always has to be last.
        extern test mce_test;
        if (a == &mce_test)
            return false;
        if (b == &mce_test)
            return true;

        return strcmp(a->id, b->id) < 0;
    }


    struct test *get_next_test() override {
        if (current_test_index == testinfo.size()) {
            current_test_index = 0;
            return nullptr;
        }
        return testinfo[current_test_index++];
    }
};


#endif //SANDSTONE_ALPHABETICALSELECTOR_H
