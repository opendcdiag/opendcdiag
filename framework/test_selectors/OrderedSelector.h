/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_ORDEREDSELECTOR_H
#define SANDSTONE_ORDEREDSELECTOR_H
#include "TestrunSelectorBase.h"

class OrderedTestSelector : public TestrunSelector
{
    int current_test_index = 0;
public:
    OrderedTestSelector(std::vector<struct test *> _tests)
        : TestrunSelector(std::move(_tests))
    {
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
