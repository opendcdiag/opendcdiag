/**
 * @file
 *
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b eigen_svd_jacobi
 * @parblock
 * This piece of code aims to stress test the FMA execution units of
 * the CPU, among others, by repetitively solving the singular value
 * decomposition problem on given input matrices, which involve a lot
 * of matrix multiplication operations underneath.
 *
 * The logic comes from the 3rd party library Eigen. Init and workers get
 * the input matrix and compute and submit output matrices "U" and "V"
 * for cross-checking. Each worker's later results must match its first.
 * Init's results participate in verification, not as trusted references.
 *
 * This particular version of the Eigen SVD tests go for single
 * precision input matrices and the "Jacobi" SVD algorithm.
 *
 * @note One successful worker plus init provides cross-check coverage.
 * @endparblock
 */

#include "eigen_svd/sandstone_eigen_common.h"

using namespace Eigen;

typedef Matrix < float, Dynamic, Dynamic > Mat;
typedef Eigen::JacobiSVD < Mat > SVD;

#define M_DIM 256

using eigen_svd_jacobi_test = EigenSVDTest<SVD, M_DIM>;
DECLARE_TEST(eigen_svd_jacobi, "Eigen SVD (Singular Value Decomposition, Jacobi algorithm) solving payload, which issues a bunch of matrix multiplies underneath")
  .groups = DECLARE_TEST_GROUPS(&group_math),
  .test_init = eigen_svd_jacobi_test::init,
  .test_run = eigen_svd_jacobi_test::run,
  .quality_level = TEST_QUALITY_SKIP,
END_DECLARE_TEST
