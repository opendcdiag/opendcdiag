/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __INCLUDE_GUARD_RANDOM_MOCKER_HPP_
#define __INCLUDE_GUARD_RANDOM_MOCKER_HPP_

#include <vector>

/// A class that mocks RNG to provide predefined values for random_xxx().
#ifndef SANDSTONE_UNITTESTS
#error "This file should be included only with unit tests"
#endif

extern "C" {
// random() replacement with mocking
#define random random_mocked
int random_mocked();

uint8_t get_random_bits8(uint32_t range);
}

namespace RandomMocker {

template<typename T>
class Mock {
public:
    static Mock* get_instance() {
        return instance;
    }

    Mock(std::initializer_list<T> vals):
        values(vals)
    {
        assert(instance == nullptr && "Only one instance of Mock can exist at a time");
        instance = this;
    }
    Mock(const std::vector<T>& vals):
        values(vals)
    {
        assert(instance == nullptr && "Only one instance of Mock can exist at a time");
        instance = this;
    }
    ~Mock() {
        if (instance == this) {
            instance = nullptr;
        }
    }
    T get_value() {
        assert((index < values.size()) && "Ran out of mocked random values");
        return *(values.begin() + index++);
    }
    bool all_values_used() const {
        return index >= values.size();
    }
private:
    static Mock* instance;
    const std::vector<T> values;
    size_t index = 0;
};

} // RandomMocker

#endif // __INCLUDE_GUARD_RANDOM_MOCKER_HPP_
