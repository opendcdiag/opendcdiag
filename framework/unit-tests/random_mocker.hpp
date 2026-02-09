/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __INCLUDE_GUARD_RANDOM_MOCKER_HPP_
#define __INCLUDE_GUARD_RANDOM_MOCKER_HPP_

#include <vector>
#include <assert.h>

namespace RandomMocker {

template<typename T>
struct IMock {
    static IMock* get_instance() {
        return instance;
    }

    IMock() {
        assert(instance == nullptr && "Only one instance of Mock<T> can exist at a time");
        instance = this;
    }
    virtual ~IMock();
    virtual T get_value() = 0;

private:
    static IMock* instance;
};

template<typename T>
struct Mock: public IMock<T> {
    Mock(std::initializer_list<T> vals):
        IMock<T>(),
        values(vals)
    {}
    Mock(const std::vector<T>& vals):
        IMock<T>(),
        values(vals)
    {}
    T get_value() override {
        assert((index < values.size()) && "Ran out of mocked random values");
        return *(values.begin() + index++);
    }
    bool all_values_used() const {
        return index >= values.size();
    }

private:
    const std::vector<T> values;
    size_t index = 0;
};


class Counting: public IMock<int> {
public:
    Counting(void):
        IMock<int>(),
        counter(0)
    {}

    int get_value() override {
        counter++;
        // call original random() to get the value
        return -1;
    }

    size_t get_count() const {
        return counter;
    }

private:
    size_t counter;
};

} // RandomMocker

#endif // __INCLUDE_GUARD_RANDOM_MOCKER_HPP_
