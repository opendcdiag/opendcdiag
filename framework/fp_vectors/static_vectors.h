/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __SIMPLE_VECTORS_H__
#define  __SIMPLE_VECTORS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "Floats.h"

// ================================================
// Use these to get interesting pure random values:
// ================================================
Float16 random_float16(int pct_fixed);
Float32 random_float32(int pct_fixed);
Float64 random_float64(int pct_fixed);
Float80 random_float80(int pct_fixed);

Float16 new_random_float16();
Float32 new_random_float32();
Float64 new_random_float64();
Float80 new_random_float80();



// =================================
// Float 16 static vector interface
// =================================
extern Float16  simple_vectors_float16[];
extern int num_simple_vectors_float16;

int num_float16_vectors();
Float16 get_float16_vector(int idx);
Float16 pick_float16_vector();
Float16 randomize_sign_and_exponent_float16(Float16 f);
Float16 randomize_sign_and_exponent_in_range_float16(Float16 f, int low_expon, int high_expon);
Float16 get_randomized_float16_vector(int idx);
Float16 pick_randomized_float16_vector();

// =================================
// Float 32 static vector interface
// =================================
extern Float32  simple_vectors_float32[];
extern int num_simple_vectors_float32;

int num_float32_vectors();
Float32 get_float32_vector(int idx);
Float32 pick_float32_vector();
Float32 randomize_sign_and_exponent_float32(Float32 f);
Float32 randomize_sign_and_exponent_in_range_float32(Float32 f, int low_expon, int high_expon);
Float32 get_randomized_float32_vector(int idx);
Float32 pick_randomized_float32_vector();

// =================================
// Float 64 static vector interface
// =================================
extern Float64  simple_vectors_float64[];
extern int num_simple_vectors_float64;

int num_float64_vectors();
Float64 get_float64_vector(int idx);
Float64 pick_float64_vector();
Float64 randomize_sign_and_exponent_float64(Float64 f);
Float64 randomize_sign_and_exponent_in_range_float64(Float64 f, int low_expon, int high_expon);
Float64 get_randomized_float64_vector(int idx);
Float64 pick_randomized_float64_vector();

// =================================
// Float 80 static vector interface
// =================================
extern Float80  simple_vectors_float80[];
extern int num_simple_vectors_float80;

int num_float80_vectors();
Float80 get_float80_vector(int idx);
Float80 pick_float80_vector();
Float80 randomize_sign_and_exponent_float80(Float80 f);
Float80 randomize_sign_and_exponent_in_range_float80(Float80 f, int low_expon, int high_expon);
Float80 get_randomized_float80_vector(int idx);
Float80 pick_randomized_float80_vector();

#ifdef __cplusplus
} // extern "C"
#endif


#endif
