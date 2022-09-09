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

    struct test * testid_to_test(const char *id, bool silent)
    {
        for (struct test *test: testinfo) {
            if (strcmp(id, test->id) == 0) {
                // check the quality level
                if (test->quality_level >= sApp->requested_quality)
                    return test;

                // silently skip if the requested quality is too high
                return nullptr;
            }
        }
        if (!silent) {
            fprintf(stderr, "\nERROR: Attempt to specify non-existent test id [%s] in list file\n", id);
            exit(EX_USAGE);
        }
        return nullptr;
    }

public:
    virtual ~TestrunSelector() = default;
    virtual struct test * get_next_test() = 0;
    virtual void reset_selector() {};
    virtual size_t get_test_count() const { return testinfo.size(); };

};


#endif //SANDSTONE_TESTRUNSELECTORBASE_H
