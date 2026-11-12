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
 * Eigen::SimplicialCholesky is used to solve the problem Ax=b. Init and
 * workers submit solution vectors for cross-checking, and each worker's
 * later results must match its first. Init's result participates in
 * verification, not as a trusted reference.
 *
 * @note One successful worker plus init provides cross-check coverage.
 * @endparblock
 */

#include <sandstone.h>
#include "crosscheck.h"

#include <Eigen/Sparse>


constexpr size_t n=256;
namespace {
using SparseMatrix = Eigen::SparseMatrix<double>;

struct EigenSparseProblem {
    SparseMatrix A{n,n};
    Eigen::VectorXd b{n};
};
}

CROSSCHECK_INPUT(eigen_sparse_values, double);
CROSSCHECK_INPUT(eigen_sparse_outer_indices, SparseMatrix::StorageIndex);
CROSSCHECK_INPUT(eigen_sparse_inner_indices, SparseMatrix::StorageIndex);
CROSSCHECK_INPUT(eigen_sparse_rhs, double);
CROSSCHECK_OUTPUT(eigen_sparse_solution, double);

static EigenSparseProblem get_problem()
{
    auto values = get_input(eigen_sparse_values);
    auto outer = get_input(eigen_sparse_outer_indices);
    auto inner = get_input(eigen_sparse_inner_indices);
    auto rhs = get_input(eigen_sparse_rhs);

    EigenSparseProblem d;
    d.A = Eigen::Map<const SparseMatrix>(n, n, values.size(), outer.data(), inner.data(), values.data());
    d.b = Eigen::Map<const Eigen::VectorXd>(rhs.data(), rhs.size());
    return d;
}

static int initialize_problem()
{
    try {
        EigenSparseProblem d;
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
        d.A.setFromTriplets(trip.begin(), trip.end());
        d.A.makeCompressed();
        d.b = Eigen::VectorXd::Random(n);

        set_input(eigen_sparse_values, d.A.valuePtr(), d.A.nonZeros(), "Sparse matrix values");
        set_input(eigen_sparse_outer_indices, d.A.outerIndexPtr(), d.A.outerSize() + 1,
                  "Sparse matrix column offsets");
        set_input(eigen_sparse_inner_indices, d.A.innerIndexPtr(), d.A.nonZeros(),
                  "Sparse matrix row indices");
        set_input(eigen_sparse_rhs, d.b.data(), d.b.size(), "Right-hand side vector");
    } catch (...) {
        log_skip(TestResourceIssueSkipCategory, "Exception on Eigen code, most probably OOM");
        return EXIT_SKIP;
    }

    return 0;
}

static int eigen_sparse_init(struct test *test) {
    int ret = initialize_problem();
    if (ret)
        return ret;
    try {
        auto d = get_problem();
        Eigen::SimplicialCholesky<SparseMatrix> solver;
        Eigen::VectorXd golden = solver.compute(d.A).solve(d.b);
        if (solver.info() != Eigen::Success) {
            report_fail(test);
            return EXIT_FAILURE;
        }
        submit_output(eigen_sparse_solution, golden.data(), golden.size(), "Solution vector");
    } catch (...) {
        log_skip(TestResourceIssueSkipCategory, "Exception on Eigen code, most probably OOM");
        return EXIT_SKIP;
    }
    return EXIT_SUCCESS;
}

static int eigen_sparse_run(struct test *test, int cpu) {
    try {
        auto d = get_problem();
        do {
            Eigen::SimplicialCholesky<SparseMatrix> solver;
            Eigen::VectorXd x = solver.compute(d.A).solve(d.b);
            if (solver.info() != Eigen::Success) {
                report_fail(test);
                return EXIT_FAILURE;
            }
            submit_output(eigen_sparse_solution, x.data(), x.size(), "Solution vector");
        } while (test_time_condition(test));
    } catch (...) {
        report_fail_msg("Exception on Eigen code, most probably OOM");
    }
    return EXIT_SUCCESS;
}

DECLARE_TEST(eigen_sparse, "Eigen sparse linear algebra payload. Solve Ax=b using Cholskey (real symmetric A)")
  .groups = DECLARE_TEST_GROUPS(&group_math),
  .test_init = eigen_sparse_init,
  .test_run = eigen_sparse_run,
  .desired_duration = -1,
  .quality_level = TEST_QUALITY_PROD,
END_DECLARE_TEST
