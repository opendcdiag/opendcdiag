/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CROSSCHECK_OUTPUT_PEER_HPP
#define CROSSCHECK_OUTPUT_PEER_HPP

#include "crosscheck_state.hpp"

SandstoneCrossCheck::CapturedSlot crosscheck_output_peer_bool();
SandstoneCrossCheck::CapturedSlot crosscheck_output_peer_byte();
SandstoneCrossCheck::CapturedSlot crosscheck_output_peer_float();
SandstoneCrossCheck::CapturedSlot crosscheck_output_peer_wrapper();

#endif // CROSSCHECK_OUTPUT_PEER_HPP
