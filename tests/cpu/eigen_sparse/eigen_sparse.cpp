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
 * Ax=b where A is a sparse real symmetric matrix uings Cholesky method.
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

#include <sandstone.h>

#include <test_class_cpu.hpp>

#include <Eigen/Sparse>

#include <memory>

namespace {
class EigenSparseTest : public SandstoneTest::Cpu
{
    int initialize_problem()
    {
        try {
            std::vector<Eigen::Triplet<double>> trip;
            for (size_t i = 0; i < n; ++i) {
                for (size_t j = i + 1; j < n; ++j) {
                    double x = frandom_scale(1.0);
                    if (x < 0.1) {
                        trip.push_back(Eigen::Triplet<double>(i, j, x));
                        if (j > i)
                            trip.push_back(Eigen::Triplet<double>(j, i, x));
                    }
                }
            }
            for (size_t i=  0; i < n; ++i) {
                double x = fabs(frandom_scale(1.0)) + 0.05;
                trip.push_back(Eigen::Triplet<double>(i,i,x));
            }
            A.setFromTriplets(trip.begin(), trip.end());
            b = Eigen::VectorXd::Random(n);
        } catch (...) {
            log_skip(TestResourceIssueSkipCategory, "Exception on Eigen code, most probably OOM");
            return EXIT_SKIP;
        }
        return EXIT_SUCCESS;
    }

public:
    static constexpr auto groups = DECLARE_TEST_GROUPS(&group_math);
    static constexpr auto quality_level = TestQuality::Production;
    static constexpr char description[] = "Eigen sparse linear algebra payload. Solve Ax=b using Cholesky (real symmetric A)";
    static constexpr SandstoneTest::Base::Parameters parameters{
        .desired_duration = -1,
    };

    int init(struct test* test)
    {
        int ret = initialize_problem();
        if (ret != EXIT_SUCCESS)
            return ret;
        Eigen::SimplicialCholesky<Eigen::SparseMatrix<double>> solver;
        try {
            golden = solver.compute(A).solve(b);
        } catch(...) {
            log_skip(TestResourceIssueSkipCategory, "Exception on Eigen code, most probably OOM");
            return EXIT_SKIP;
        }
        if (solver.info() != Eigen::Success) {
            report_fail(test);
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    int run(struct test* test)
    {
        test_loop<1>([&] {
            Eigen::SimplicialCholesky<Eigen::SparseMatrix<double>> solver;
            Eigen::VectorXd x;
            try {
                x = solver.compute(A).solve(b);
            } catch (...) {
                report_fail_msg("Exception on Eigen code, most probably OOM");
            }
            if (solver.info() != Eigen::Success) {
                report_fail(test);
                throw Failed();
            }
            if (x != golden) {
                report_fail(test);
                throw Failed();
            }
        });
        return EXIT_SUCCESS;
    }

private:
    static constexpr size_t n = 256;

    Eigen::SparseMatrix<double> A{n,n};
    Eigen::VectorXd b{n};
    Eigen::VectorXd golden{n};
};
} // end anonymous namespace

DECLARE_TEST_CLASS(eigen_sparse, EigenSparseTest);
