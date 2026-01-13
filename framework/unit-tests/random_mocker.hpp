/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __INCLUDE_GUARD_RANDOM_MOCKER_HPP_
#define __INCLUDE_GUARD_RANDOM_MOCKER_HPP_

#include <vector>

// Keep original random() accessible to mocks to avoid infinite recursion
extern "C" {
extern int random_lib();
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
    virtual ~Mock() {
        if (instance == this) {
            instance = nullptr;
        }
    }
    virtual T get_value() {
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


class Counting: public Mock<int> {
public:
    Counting(void):
        Mock<int>({0})
    {}

    int get_value() override {
        counter++;
        // original random() must be called to avoid infinite recursion
        return random_lib();
    }

    size_t get_count() const {
        return counter;
    }

private:
    size_t counter{ 0 };
};

} // RandomMocker

#endif // __INCLUDE_GUARD_RANDOM_MOCKER_HPP_
