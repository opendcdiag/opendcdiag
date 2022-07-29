/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * NOTE: This is a private include file of the sandstone framework to configure Eigen library
 * and should be included only by the test using Eigen. Must be very first included file
 * (with prior definition of SANDSTONE_EIGEN_VECTORIZATION)
 */

#ifndef SANDSTONE_EIGEN_CONFIGURATOR_H
#define SANDSTONE_EIGEN_CONFIGURATOR_H

#define SANDSTONE_EIGEN_DEFAULT      0
#define SANDSTONE_EIGEN_AVX          1
#define SANDSTONE_EIGEN_AVX2         2
#define SANDSTONE_EIGEN_AVX512       3
#define SANDSTONE_EIGEN_AVX512_DQ_ER 4
#define SANDSTONE_EIGEN_FP16         5


#ifdef SANDSTONE_EIGEN_VECTORIZATION
    // disable eigen's configurator
    #define EIGEN_DONT_VECTORIZE

    // common vector operations
    #define EIGEN_VECTORIZE
    #define EIGEN_VECTORIZE_SSE
    #define EIGEN_VECTORIZE_SSE2

    #ifdef __SSE3__
    #define EIGEN_VECTORIZE_SSE3
    #endif
    #ifdef __SSSE3__
    #define EIGEN_VECTORIZE_SSSE3
    #endif
    #ifdef __SSE4_1__
    #define EIGEN_VECTORIZE_SSE4_1
    #endif
    #ifdef __SSE4_2__
    #define EIGEN_VECTORIZE_SSE4_2
    #endif

    #if (SANDSTONE_EIGEN_VECTORIZATION == SANDSTONE_EIGEN_DEFAULT)
        #warning Default compiler handling is used

    #elif (SANDSTONE_EIGEN_VECTORIZATION == SANDSTONE_EIGEN_AVX)
        #if !defined(__AVX__)
            #error AVX feature is not available
        #elif !defined(__FMA__)
            #error FMA feature is not available
        #elif defined(__AVX2__)
            #error AVX2 feature is available
        #elif defined(__AVX512F__)
            #error AVX512F feature is available
        #else
            #define EIGEN_VECTORIZE_AVX
            #define EIGEN_VECTORIZE_FMA
            #define EIGEN_MAX_ALIGN_BYTES 32
        #endif

    #elif (SANDSTONE_EIGEN_VECTORIZATION == SANDSTONE_EIGEN_AVX2)
        #if !defined(__AVX__)
            #error AVX feature is not available
        #elif !defined(__AVX2__)
            #error AVX2 feature is not available
        #elif !defined(__FMA__)
            #error FMA feature is not available
        #elif defined(__AVX512F__)
            #error AVX512F feature is available
        #else
            #define EIGEN_VECTORIZE_AVX
            #define EIGEN_VECTORIZE_AVX2
            #define EIGEN_VECTORIZE_FMA
            #define EIGEN_MAX_ALIGN_BYTES 32
        #endif

    #elif (SANDSTONE_EIGEN_VECTORIZATION == SANDSTONE_EIGEN_AVX512)
        #if !defined(__AVX__)
            #error AVX feature is not available
        #elif !defined(__AVX2__)
            #error AVX2 feature is not available
        #elif !defined(__FMA__)
            #error FMA feature is not available
        #elif !defined(__AVX512F__)
            #error AVX512F feature is not available
        #else
            #define EIGEN_VECTORIZE_AVX
            #define EIGEN_VECTORIZE_AVX2
            #define EIGEN_VECTORIZE_FMA
            #define EIGEN_VECTORIZE_AVX512
            // horizontal ADD is not enabled
            #define EIGEN_MAX_ALIGN_BYTES 64
        #endif

    #elif (SANDSTONE_EIGEN_VECTORIZATION == SANDSTONE_EIGEN_AVX512_DQ_ER)
        #if !defined(__AVX__)
            #error AVX feature is not available
        #elif !defined(__AVX2__)
            #error AVX2 feature is not available
        #elif !defined(__FMA__)
            #error FMA feature is not available
        #elif !defined(__AVX512F__)
            #error AVX512F feature is not available
        #elif !defined(__AVX512DQ__)
            #error AVX512DQ feature is not available
        #elif !defined(__AVX512ER__)
            #error AVX512ER feature is not available
        #else
            #define EIGEN_VECTORIZE_AVX
            #define EIGEN_VECTORIZE_AVX2
            #define EIGEN_VECTORIZE_FMA
            #define EIGEN_VECTORIZE_AVX512
            #define EIGEN_VECTORIZE_AVX512DQ
            #define EIGEN_VECTORIZE_AVX512ER
            #define EIGEN_MAX_ALIGN_BYTES 64
        #endif

    #elif (SANDSTONE_EIGEN_VECTORIZATION == SANDSTONE_EIGEN_FP16)
        #if !defined(__AVX__)
            #error AVX feature is not available
        #elif !defined(__AVX2__)
            #error AVX2 feature is not available
        #elif !defined(__FMA__)
            #error FMA feature is not available
        #elif !defined(__AVX512F__)
            #error AVX512F feature is not available
        #elif !defined(__AVX512FP16__)
            #error AVX512FP16 feature is not available
        #else
            #define EIGEN_VECTORIZE_AVX
            #define EIGEN_VECTORIZE_AVX2
            #define EIGEN_VECTORIZE_FMA
            #define EIGEN_VECTORIZE_AVX512
            #define EIGEN_VECTORIZE_AVX512FP16
            // horizontal ADD is not enabled
            #define EIGEN_MAX_ALIGN_BYTES 64
        #endif

    #else
        #error Not handled vectorization requested
    #endif

#endif // SANDSTONE_EIGEN_VECTORIZATION
#endif // SANDSTONE_EIGEN_CONFIGURATOR_H
