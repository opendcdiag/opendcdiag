/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_TEST_CLASS_CPU_H
#define INC_TEST_CLASS_CPU_H

#include "test_base.hpp"

namespace SandstoneTest {

class Cpu : public Base
{
public:
    using BaseClass = Cpu;

private:
    friend class Base;
    template <TestClass T>
    static constexpr void _apply_parameters(struct test *test)
    {
        Base::_apply_parameters_base<T>(test);
        test->compiler_minimum_device = device_compiler_features ;
        if constexpr (requires { T::parameters; }) {
            test->minimum_cpu = T::parameters.minimum_device;
        }
    }
};
} // namespace SandstoneTest

#endif // INC_TEST_CLASS_CPU_H
