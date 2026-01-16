/**
 * @file
 *
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b eigen_svd_double
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
 * This particular version of the Eigen SVD tests go for double
 * precision input matrices and the (divide and conquer)
 * bi-diagonalization SVD algorithm.
 *
 * @note This test requires at least 2 threads to run.
 * @endparblock
 */

#include "sandstone_eigen_common.h"

using namespace Eigen;

using SVD = BDCSVD<Matrix<double, Dynamic, Dynamic>, ComputeFullU | ComputeFullV>;

#define M_DIM 256

using eigen_svd_double_test = EigenSVDTest<SVD, M_DIM>;
DECLARE_TEST(eigen_svd_double, "Eigen SVD (Singular Value Decomposition) solving payload,  which issues a bunch of matrix multiplies underneath, now operating on doubles")
  .groups = DECLARE_TEST_GROUPS(&group_math),
  .test_init = eigen_svd_double_test::init,
  .test_run = eigen_svd_double_test::run,
  .test_cleanup = eigen_svd_double_test::cleanup,
  .fracture_loop_count = 5,
  .quality_level = TEST_QUALITY_PROD,
END_DECLARE_TEST

#define M_DIM2 128

using eigen_svd_double2_test = EigenSVDTest<SVD, M_DIM2>;
DECLARE_TEST(eigen_svd_double2, "Eigen SVD (Singular Value Decomposition) solving payload,  which issues a bunch of matrix multiplies underneath, now operating on doubles")
  .groups = DECLARE_TEST_GROUPS(&group_math),
  .test_init = eigen_svd_double2_test::init,
  .test_run = eigen_svd_double2_test::run,
  .test_cleanup = eigen_svd_double2_test::cleanup,
  .fracture_loop_count = 5,
  .quality_level = TEST_QUALITY_PROD,
END_DECLARE_TEST
