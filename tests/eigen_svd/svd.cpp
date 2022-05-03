/**
 * @file
 *
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b eigen_svd
 * @parblock
 * This piece of code aims to stress test the FMA execution units of
 * the CPU, among others, by repetitively solving the singular value
 * decomposition problem on given input matrices, which involve a lot
 * of matrix multiplication operations underneath.
 *
 * The logic comes from the 3rd party library Eigen. The first thread
 * that gets to run computes a "golden value" of the results, those
 * being output matrices "U" and "V". Subsequent runs have results
 * contrasted to those golden values and, whenever they differ, an
 * error is flagged.
 *
 * This particular version of the Eigen SVD tests go for single
 * precision input matrices and the (divide and conquer)
 * bi-diagonalization SVD algorithm.
 *
 * @note This test requires at least 2 threads to run.
 * @endparblock
 */

#include "sandstone_eigen_common.h"

using namespace Eigen;

typedef Matrix < float, Dynamic, Dynamic > Mat;
typedef Eigen::BDCSVD < Mat > SVD;

#define M_DIM 256

using eigen_svd_test = EigenSVDTest<SVD, M_DIM>;
DECLARE_TEST(eigen_svd, "Eigen SVD (Singular Value Decomposition) solving payload, which issues a bunch of matrix multiplies underneath")
  .groups = DECLARE_TEST_GROUPS(&group_math),
  .test_init = eigen_svd_test::init,
  .test_run = eigen_svd_test::run,
  .test_cleanup = eigen_svd_test::cleanup,
  .fracture_loop_count = 2,
  .quality_level = TEST_QUALITY_PROD,
END_DECLARE_TEST
