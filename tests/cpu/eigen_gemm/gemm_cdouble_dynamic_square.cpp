/**
 * @file
 *
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b eigen_gemm_cdouble_dynamic_square
 * @parblock
 * This piece of code aims to stress test the exec (in particular FMA)
 * by repetitively solving general matrix matrix multiplication.  The
 * multiplication function is from the 3rd party library Eigen.  A
 * pair of random matrices are generated as inputs and then multiplied
 * using Eigen's gemm. Init and workers submit multiplication results for
 * cross-checking, and each worker's later results must match its first.
 * Init's result participates in verification, not as a trusted reference.
 * This particular version of the test goes for double precision, complex
 * numbers input matrices.
 *
 * @note One successful worker plus init provides cross-check coverage.
 * @endparblock
 */

#include <sandstone.h>
#include "crosscheck.h"

#include <Eigen/Core>
using namespace Eigen;

#define M_DIM 221 // weird dim on purpose

typedef Matrix < std::complex < double >, Dynamic, Dynamic > Mat;

CROSSCHECK_INPUT(gemm_cdouble_lhs, double);
CROSSCHECK_INPUT(gemm_cdouble_rhs, double);
CROSSCHECK_OUTPUT(gemm_cdouble_product, double);

static Mat matrix_from_input(std::span<const double> input)
{
    // Captured doubles are not std::complex<double> objects.
    Mat result(M_DIM, M_DIM);
    for (Index i = 0; i < result.size(); ++i)
        result.data()[i] = std::complex<double>(input[2 * i], input[2 * i + 1]);
    return result;
}

static int eigen_gemm_cdouble_dynamic_square_init(struct test *test) {
    try {
        Mat scratch = Mat::Random(M_DIM, M_DIM);
        set_input(gemm_cdouble_lhs, reinterpret_cast<const double *>(scratch.data()),
                  2 * scratch.size(), "Left operand (interleaved real/imaginary)");
        scratch = Mat::Random(M_DIM, M_DIM);
        set_input(gemm_cdouble_rhs, reinterpret_cast<const double *>(scratch.data()),
                  2 * scratch.size(), "Right operand (interleaved real/imaginary)");

        Mat lhs = matrix_from_input(get_input(gemm_cdouble_lhs));
        Mat rhs = matrix_from_input(get_input(gemm_cdouble_rhs));
        Mat prod = lhs * rhs;
        submit_output(gemm_cdouble_product, reinterpret_cast<const double *>(prod.data()),
                      2 * prod.size(), "Matrix product (interleaved real/imaginary)");
    } catch (...) {
        report_fail_msg("Exception on Eigen code, most probably OOM");
    }
    return EXIT_SUCCESS;
}

static int eigen_gemm_cdouble_dynamic_square_run(struct test *test, int cpu) {
    Mat lhs = matrix_from_input(get_input(gemm_cdouble_lhs));
    Mat rhs = matrix_from_input(get_input(gemm_cdouble_rhs));
    do {
        Mat x;
        x = lhs * rhs;

        submit_output(gemm_cdouble_product, reinterpret_cast<const double *>(x.data()),
                      2 * x.size(), "Matrix product (interleaved real/imaginary)");
    } while (test_time_condition(test));
    return EXIT_SUCCESS;
}

DECLARE_TEST(eigen_gemm_cdouble_dynamic_square, "Eigen GEMM payload (cplx double, dynamic, square)")
  .groups = DECLARE_TEST_GROUPS(&group_math),
  .test_init = eigen_gemm_cdouble_dynamic_square_init,
  .test_run = eigen_gemm_cdouble_dynamic_square_run,
  .fracture_loop_count = 5,
  .quality_level = TEST_QUALITY_PROD,
END_DECLARE_TEST
