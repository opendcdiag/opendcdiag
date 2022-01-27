/**
 * @file
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b eigen_svd_jacobi_fvectors
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
 * precision input matrices and the "Jacobi" SVD algorithm. Moreover,
 * the selected numbers will come, on their majority, from a pool of
 * known interesting floating point vectors (CPU/HW point of view).
 *
 * This test requires at least 2 threads to run.
 * @endparblock
 */

#include "eigen_svd/sandstone_eigen_common.h"

#include "fp_vectors/static_vectors.h"

using namespace Eigen;

typedef Matrix < float, Dynamic, Dynamic > Mat;
typedef Eigen::JacobiSVD < Mat > SVD;

#define M_DIM 512

using eigen_svd_jacobi_fvectors_test = EigenSVDTest<SVD, M_DIM>;

static int eigen_svd_jacobi_fvectors_init(struct test *test) {
    auto d = new eigen_svd_jacobi_fvectors_test::eigen_test_data;
    d->orig_matrix =
            Mat::NullaryExpr(M_DIM, M_DIM,[&]() {
        Float32 ret = random_float32(80);
        return ret.as_float;
    }
    );

    eigen_svd_jacobi_fvectors_test::calculate_once(d->orig_matrix, d->u_matrix, d->v_matrix);
    test->data = d;
    return EXIT_SUCCESS;
}

DECLARE_TEST(eigen_svd_jacobi_fvectors, "Eigen SVD (Singular Value Decomposition, Jacobi algorithm) solving payload, which issues a bunch of matrix multiplies underneath, now operating fixed FP32 vectors in the framework")
  .groups = DECLARE_TEST_GROUPS(&group_math),
  .test_init = eigen_svd_jacobi_fvectors_init,
  .test_run = eigen_svd_jacobi_fvectors_test::run,
  .test_cleanup = eigen_svd_jacobi_fvectors_test::cleanup,
  .quality_level = TEST_QUALITY_SKIP,
END_DECLARE_TEST
