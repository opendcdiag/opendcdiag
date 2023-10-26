/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_TESTRUNSELECTORBASE_H
#define SANDSTONE_TESTRUNSELECTORBASE_H

#include <vector>
#include <unordered_map>
#include "sandstone_p.h"
#include "sandstone_tests.h"
#include "sandstone_utils.h"

class TestrunSelector {
protected:
    std::vector<struct test *> testinfo;

    TestrunSelector() = default;
    TestrunSelector(std::vector<struct test *> _tests)
        : testinfo(std::move(_tests))
    {
    }

    // in sandstone.cpp
    struct test * testid_to_test(const char *id, bool silent);

public:

    virtual ~TestrunSelector() = default;
    virtual struct test * get_next_test() = 0;
    virtual void reset_selector() {};
};


#endif //SANDSTONE_TESTRUNSELECTORBASE_H
