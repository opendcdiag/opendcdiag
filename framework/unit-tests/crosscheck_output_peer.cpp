/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck_output_peer.hpp"

#include <cstdint>

#include "fp_vectors/Floats.h"

using SandstoneCrossCheck::make_captured_slot;
using SandstoneCrossCheck::CapturedSlot;

CapturedSlot crosscheck_output_peer_bool()
{
    const bool value = true;
    return make_captured_slot(&value, 1, nullptr);
}

CapturedSlot crosscheck_output_peer_byte()
{
    const uint8_t value = 1;
    return make_captured_slot(&value, 1, nullptr);
}

CapturedSlot crosscheck_output_peer_float()
{
    const float value = 1.0f;
    return make_captured_slot(&value, 1, nullptr);
}

CapturedSlot crosscheck_output_peer_wrapper()
{
    const Float32 value = {};
    return make_captured_slot(&value, 1, nullptr);
}
