/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_TESTRUNSELECTORBASE_H
#define SANDSTONE_TESTRUNSELECTORBASE_H

#include <vector>
#include <unordered_map>
#include "sandstone.h"
#include "sandstone_tests.h"
#include "sandstone_utils.h"

class TestrunSelector {
protected:
    std::vector<struct test *> testinfo;
    std::unordered_map<std::string, struct test *> test_by_id;

public:
    virtual ~TestrunSelector() = default;
    virtual void set_test_list(std::vector<struct test *> _tests){
        testinfo = std::move(_tests);

        for (auto & i : testinfo){
            test_by_id[i->id] = i;
        }
    }

    struct test * testid_to_test(const char * id, bool silent){
        if (test_by_id.count(id) == 0){
            if (!silent) {
                fprintf(stderr, "\nERROR: Attempt to specify non-existent test id [%s] in list file\n", id);
                exit(EX_USAGE);
            }
            return nullptr;
        }
        return test_by_id[id];
    }

    virtual struct test * get_next_test() = 0;
    virtual void reset_selector() {};
    virtual size_t get_test_count() const { return testinfo.size(); };

};


#endif //SANDSTONE_TESTRUNSELECTORBASE_H
