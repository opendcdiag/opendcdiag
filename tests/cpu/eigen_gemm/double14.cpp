/**
 * @file
 *
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b eigen_gemm_double14
 * @parblock
 * This piece of code aims to stress test the exec (in particular FMA)
 * by repetitively solving general matrix matrix multiplication.  The
 * multiplication function is from the 3rd party library Eigen.  A
 * pair of random matrices are generated as inputs and then multiplied
 * using Eigen's gemm. Init and workers submit multiplication results for
 * cross-checking, and each worker's later results must match its first.
 * Init's result participates in verification, not as a trusted reference.
 * This particular version of the test goes for double precision input
 * matrices. This variation adds extra copies and consistency checks.
 *
 * @note One successful worker plus init provides cross-check coverage.
 * @endparblock
 */

#include <sandstone.h>
#include "crosscheck.h"

#include <Eigen/Core>
using namespace Eigen;

#define M_DIM 256

typedef Matrix < double, Dynamic, Dynamic > Mat;

CROSSCHECK_INPUT(gemm_double14_lhs, double);
CROSSCHECK_INPUT(gemm_double14_rhs, double);
CROSSCHECK_OUTPUT(gemm_double14_lhs_copy, double);
CROSSCHECK_OUTPUT(gemm_double14_rhs_copy, double);
CROSSCHECK_OUTPUT(gemm_double14_product, double);

static int eigen_gemm_double14_init(struct test *test) {
    try {
        Mat scratch = Mat::Random(M_DIM, M_DIM);
        set_input(gemm_double14_lhs, scratch.data(), scratch.size(), "Left operand");
        scratch = Mat::Random(M_DIM, M_DIM);
        set_input(gemm_double14_rhs, scratch.data(), scratch.size(), "Right operand");

        auto lhs_input = get_input(gemm_double14_lhs);
        auto rhs_input = get_input(gemm_double14_rhs);
        Mat lhs = Map<const Mat>(lhs_input.data(), M_DIM, M_DIM);
        Mat rhs = Map<const Mat>(rhs_input.data(), M_DIM, M_DIM);
        Mat prod = lhs * rhs;
        submit_output(gemm_double14_lhs_copy, lhs_input, "Left operand copy");
        submit_output(gemm_double14_rhs_copy, rhs_input, "Right operand copy");
        submit_output(gemm_double14_product, prod.data(), prod.size(), "Matrix product");
    } catch (...) {
        report_fail_msg("Exception on Eigen code, most probably OOM");
    }
    return EXIT_SUCCESS;
}

static int eigen_gemm_double14_run(struct test *test, int cpu) {
    auto lhs_input = get_input(gemm_double14_lhs);
    auto rhs_input = get_input(gemm_double14_rhs);
    Mat lhs = Map<const Mat>(lhs_input.data(), M_DIM, M_DIM);
    Mat rhs = Map<const Mat>(rhs_input.data(), M_DIM, M_DIM);
    do {
        Mat _x;
        _x = lhs;
        Mat _y;
        _y = rhs;
        Mat _prod;
        _prod = _x * _y;

        submit_output(gemm_double14_lhs_copy, _x.data(), _x.size(), "Left operand copy");
        submit_output(gemm_double14_rhs_copy, _y.data(), _y.size(), "Right operand copy");
        submit_output(gemm_double14_product, _prod.data(), _prod.size(), "Matrix product");
    } while (test_time_condition(test));
    return EXIT_SUCCESS;
}

DECLARE_TEST(eigen_gemm_double14, "Eigen GEMM payload (double, dynamic, square)")
  .groups = DECLARE_TEST_GROUPS(&group_math),
  .test_init = eigen_gemm_double14_init,
  .test_run = eigen_gemm_double14_run,
  .fracture_loop_count = 4,
  .quality_level = TEST_QUALITY_PROD,
END_DECLARE_TEST
