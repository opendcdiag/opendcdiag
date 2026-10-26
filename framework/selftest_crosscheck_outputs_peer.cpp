/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck.h"
#include "selftest_crosscheck_outputs.h"

#include <array>
#include <cstdint>
#include <vector>

#include "fp_vectors/Floats.h"

void selftest_crosscheck_outputs_cpp_peer(bool conflict)
{
    if (conflict) {
        DECLARE_CROSS_CHECK_OUTPUT(output_wrapper, float);
        const float values[] = {1.0f, -0.0f};
        capture_output(output_wrapper, values, nullptr);
    } else {
        DECLARE_CROSS_CHECK_OUTPUT(output_wrapper, Float32);
        const std::array<Float32, 2> values = {Float32(1.0f), Float32(-0.0f)};
        capture_output(output_wrapper, values, nullptr);
        capture_output(output_wrapper, values.data(), values.size(), "ignored peer description");
        DECLARE_CROSS_CHECK_OUTPUT(output_wrapper64, Float64);
        const std::vector<Float64> wide = {Float64(1.0), Float64(-0.0)};
        capture_output(output_wrapper64, wide, nullptr);
        capture_output(output_wrapper64, wide, "ignored wide description");
    }
}
