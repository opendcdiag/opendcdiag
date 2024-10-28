/**
 * @file
 *
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b eigen_gemm_double_dynamic_square
 * @parblock
 * This piece of code aims to stress test the exec (in particular FMA)
 * by repetitively solving general matrix matrix multiplication.  The
 * multiplication function is from the 3rd party library Eigen.  A
 * pair of random matrices are generated as inputs and then multiplied
 * using Eigen's gemm. The multiplication result is compared against a
 * golden result that is computed during init.  This particular
 * version of the test goes for double precision input matrices.
 *
 * @note Although the test should run fine on a single thread, it is
 * only expected to catch defects if run on at least 2 cores.
 * @endparblock
 */

#include <sandstone.h>

#include <Eigen/Core>
using namespace Eigen;

#define M_DIM 256

typedef Matrix < double, Dynamic, Dynamic > Mat;

namespace {
struct eigen_test_data {
    Mat lhs;
    Mat rhs;
    Mat prod;
};
}

#define CAST(_x) static_cast<struct eigen_test_data *>(_x)

static int eigen_gemm_double_dynamic_square_init(struct test *test) {
    test->data = new(eigen_test_data);
    try {
        CAST(test->data)->lhs = Mat::Random(M_DIM, M_DIM);
        CAST(test->data)->rhs = Mat::Random(M_DIM, M_DIM);
        CAST(test->data)->prod = CAST(test->data)->lhs * CAST(test->data)->rhs;
    } catch (...) {
        report_fail_msg("Exception on Eigen code, most probably OOM");
    }
    return EXIT_SUCCESS;
}

static int eigen_gemm_double_dynamic_square_run(struct test *test, int cpu) {
    //int i=0;
    do {
        //++i;
        auto testdata = CAST(test->data);
        Mat x;
        x = testdata->lhs * testdata->rhs;

        memcmp_or_fail(x.data(), testdata->prod.data(), M_DIM * M_DIM);
    } while (test_time_condition(test));
    //log_info("Num iters = %i\n", i);
    return EXIT_SUCCESS;
}

static int eigen_gemm_double_dynamic_square_finish(struct test *test) {
    delete(CAST(test->data));
    return EXIT_SUCCESS;
}

DECLARE_TEST(eigen_gemm_double_dynamic_square, "Eigen GEMM payload (double, dynamic, square)")
  .groups = DECLARE_TEST_GROUPS(&group_math),
  .test_init = eigen_gemm_double_dynamic_square_init,
  .test_run = eigen_gemm_double_dynamic_square_run,
  .test_cleanup = eigen_gemm_double_dynamic_square_finish,
  .quality_level = TEST_QUALITY_PROD,
END_DECLARE_TEST
