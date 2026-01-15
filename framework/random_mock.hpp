/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __INCLUDE_GUARD_SANDSTONE_RANDOM_MOCKER_HPP_
#define __INCLUDE_GUARD_SANDSTONE_RANDOM_MOCKER_HPP_

#include <vector>

/// A class that mocks RNG to provide predefined values for random_xxx().
#ifndef SANDSTONE_UNITTESTS
#error "This file should be included only when SANDSTONE_UNITTESTS is defined"
#endif

// random() replacement with mocking
extern "C" {
#define random random_mocked
int random_mocked();
}

template<typename T>
class SandstoneRandomMocker {
public:
    static SandstoneRandomMocker* get_instance() {
        return instance;
    }

    SandstoneRandomMocker(std::initializer_list<T> vals):
        values(vals)
    {
        assert(instance == nullptr && "Only one instance of SandstoneRandomMocker can exist at a time");
        instance = this;
    }
    SandstoneRandomMocker(const std::vector<T>& vals):
        values(vals)
    {
        assert(instance == nullptr && "Only one instance of SandstoneRandomMocker can exist at a time");
        instance = this;
    }
    ~SandstoneRandomMocker() {
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
    static SandstoneRandomMocker* instance;
    const std::vector<T> values;
    size_t index = 0;
};

#endif // __INCLUDE_GUARD_SANDSTONE_RANDOM_MOCKER_HPP_
