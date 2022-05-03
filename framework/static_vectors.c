/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fp_vectors/Floats.h"
#include "fp_vectors/static_vectors.h"
#include <sandstone.h>


Float32 random_float32(int pct_fixed){
    return (random32() % 100 < pct_fixed) ? pick_randomized_float32_vector() : new_random_float32();
}

Float64 random_float64(int pct_fixed){
    return (random32() % 100 < pct_fixed) ? pick_randomized_float64_vector() : new_random_float64();
}

Float80 random_float80(int pct_fixed){
    return (random32() % 100 < pct_fixed) ? pick_randomized_float80_vector() : new_random_float80();
}



//-------------------------------------------------
// FLOAT 32 region
//-------------------------------------------------
int num_float32_vectors(){
    return num_simple_vectors_float32;
}

Float32 randomize_sign_and_exponent_float32(Float32 f) {
    Float32 f2 = f;
    f2.sign = random32() % 2;
    f2.exponent = (random32() % FLOAT32_EXPONENT_BIAS) + (random32() % FLOAT32_EXPONENT_BIAS);  // bell curve around bias
    return f2;
}

Float32 randomize_sign_and_exponent_in_range_float32(Float32 f, int low_expon, int high_expon) {
    Float32 f2 = f;
    f2.sign = random32() % 2;
    f2.exponent = ((random32() % (high_expon - low_expon + 1)) + low_expon) & FLOAT32_EXPONENT_MASK;
    return f2;
}

Float32 get_float32_vector(int idx){
    return simple_vectors_float32[idx];
}

Float32 get_randomized_float32_vector(int idx){
    return randomize_sign_and_exponent_float32(get_float32_vector(idx));
}

Float32 pick_float32_vector(){
    return get_float32_vector(random32() % num_simple_vectors_float32);
}

Float32 pick_randomized_float32_vector(){
    Float32 f32 = pick_float32_vector();
    return randomize_sign_and_exponent_float32(f32);
}


//-------------------------------------------------
// FLOAT 64 region
//-------------------------------------------------
int num_float64_vectors(){
    return num_simple_vectors_float64;
}

Float64 randomize_sign_and_exponent_float64(Float64 f) {
    Float64 f2 = f;
    f2.sign = random32() % 2;
    f2.exponent = (random32() % FLOAT64_EXPONENT_BIAS) + (random32() % FLOAT64_EXPONENT_BIAS);  // bell curve around bias
    return f2;
}

Float64 randomize_sign_and_exponent_in_range_float64(Float64 f, int low_expon, int high_expon) {
    Float64 f2 = f;
    f2.sign = random32() % 2;
    f2.exponent = ((random32() % (high_expon - low_expon + 1)) + low_expon) & FLOAT64_EXPONENT_MASK;
    return f2;
}

Float64 get_float64_vector(int idx){
    return simple_vectors_float64[idx];
}

Float64 get_randomized_float64_vector(int idx){
    return randomize_sign_and_exponent_float64(get_float64_vector(idx));
}

Float64 pick_float64_vector(){
    return get_float64_vector(random32() % num_simple_vectors_float64);
}

Float64 pick_randomized_float64_vector(){
    Float64 f32 = pick_float64_vector();
    return randomize_sign_and_exponent_float64(f32);
}


//-------------------------------------------------
// FLOAT 80 region
//-------------------------------------------------
int num_float80_vectors(){
    return num_simple_vectors_float80;
}

Float80 randomize_sign_and_exponent_float80(Float80 f) {
    Float80 f2 = f;
    f2.sign = random32() % 2;
    f2.exponent = (random32() % FLOAT80_EXPONENT_BIAS) + (random32() % FLOAT80_EXPONENT_BIAS); // bell curve around bias
    return f2;
}

Float80 randomize_sign_and_exponent_in_range_float80(Float80 f, int low_expon, int high_expon) {
    Float80 f2 = f;
    f2.sign = random32() % 2;
    f2.exponent = ((random32() % (high_expon - low_expon + 1)) + low_expon) & FLOAT80_EXPONENT_MASK;
    return f2;
}

Float80 get_float80_vector(int idx){
    return simple_vectors_float80[idx];
}

Float80 get_randomized_float80_vector(int idx){
    return randomize_sign_and_exponent_float80(get_float80_vector(idx));
}

Float80 pick_float80_vector(){
    return get_float80_vector(random32() % num_simple_vectors_float80);
}

Float80 pick_randomized_float80_vector(){
    Float80 f = pick_float80_vector();
    return randomize_sign_and_exponent_float80(f);
}


