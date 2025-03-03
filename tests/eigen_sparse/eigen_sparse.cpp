/**
 * @file
 *
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b eigen_sparse
 * @parblock
 * This piece of code aims to stress test the exec (in particular FMA)
 * by repetitively solving the set of linear equations represented by
 * Ax=b where A is a sparse real symmetric matrix uings Cholskey method.
 * The decomposition function is from the 3rd party library Eigen.
 * A random double precision sparse real symmetric matrix (A) and a
 * random vector (b) are generated as inputs and then
 * Eigen::SimplicialCholesky is used to solve the problem Ax=b. The
 * result vector is compared against a golden result that is computed
 * during init.
 *
 * @note Although the test should run fine on a single thread, it is
 * only expected to catch defects if run on at least 2 cores.
 * @endparblock
 */

#include <memory>

#include <sandstone.h>

#include <Eigen/Sparse>


constexpr size_t n=256;
namespace {
struct EigenSparseTestData {
    Eigen::SparseMatrix<double> A{n,n};
    Eigen::VectorXd b{n};
    Eigen::VectorXd golden{n};
};
}

static int initialize_problem(EigenSparseTestData *d)
{
    try {
        std::vector<Eigen::Triplet<double>> trip;
        for(size_t i=0; i<n; ++i) {
            for(size_t j=i+1; j<n; ++j) {
                double x = frandom_scale(1.0);
                if(x < 0.1) {
                    trip.push_back(Eigen::Triplet<double>(i,j,x));
                    if (j>i)
                        trip.push_back(Eigen::Triplet<double>(j,i,x));
                }
            }
        }
        for(size_t i=0; i<n; ++i) {
            double x = fabs(frandom_scale(1.0)) + 0.05;
            trip.push_back(Eigen::Triplet<double>(i,i,x));
        }
        d->A.setFromTriplets(trip.begin(), trip.end());
        d->b = Eigen::VectorXd::Random(n);
    } catch (...) {
        log_skip(TestResourceIssueSkipCategory, "Exception on Eigen code, most probably OOM");
        return EXIT_SKIP;
    }

    return 0;
}

static int eigen_sparse_init(struct test *test) {
    auto d = std::make_unique<EigenSparseTestData>();
    int ret = initialize_problem(d.get());
    if (ret)
        return ret;
    Eigen::SimplicialCholesky<Eigen::SparseMatrix<double>> solver;
    try {
        d->golden = solver.compute(d->A).solve(d->b);
    } catch (...) {
        log_skip(TestResourceIssueSkipCategory, "Exception on Eigen code, most probably OOM");
        return EXIT_SKIP;
    }
    if (solver.info() != Eigen::Success) {
        report_fail(test);
        return EXIT_FAILURE;
    }

    test->data = d.release();
    return EXIT_SUCCESS;
}

static int eigen_sparse_cleanup(struct test *test) {
    delete static_cast<EigenSparseTestData *>(test->data);
    return EXIT_SUCCESS;
}

static int eigen_sparse_run(struct test *test, int cpu) {
    auto d = static_cast<EigenSparseTestData *>(test->data);
    TEST_LOOP(test, 1) {
        Eigen::SimplicialCholesky<Eigen::SparseMatrix<double>> solver;
        Eigen::VectorXd x;
        try {
            x = solver.compute(d->A).solve(d->b);
        } catch (...) {
            report_fail_msg("Exception on Eigen code, most probably OOM");
        }
        if (solver.info() != Eigen::Success) {
            report_fail(test);
            return EXIT_FAILURE;
        }
        if (x != d->golden) {
            report_fail(test);
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

DECLARE_TEST(eigen_sparse, "Eigen sparse linear algebra payload. Solve Ax=b using Cholskey (real symmetric A)")
  .groups = DECLARE_TEST_GROUPS(&group_math),
  .test_init = eigen_sparse_init,
  .test_run = eigen_sparse_run,
  .test_cleanup = eigen_sparse_cleanup,
  .desired_duration = -1,
  .quality_level = TEST_QUALITY_PROD,
END_DECLARE_TEST
