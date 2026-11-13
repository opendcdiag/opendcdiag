/**
 * @file
 *
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_EIGEN_COMMON_H
#define SANDSTONE_EIGEN_COMMON_H

/* Disable deprecation warnings in case the library used is >= 3.5.x. Once
 * majority of the distros move to 3.5 or higher,
 * https://github.com/opendcdiag/opendcdiag/pull/941 should be adopted. */
#define EIGEN_NO_DEPRECATED_WARNING

#include <sandstone.h>
#include "crosscheck.h"

#include <boost/type_traits/is_complex.hpp>
#include <Eigen/Eigenvalues>

namespace {
template <typename SVD, int Dim> struct EigenSVDTest
{
    using Mat = typename SVD::MatrixType;
    using Scalar = typename Mat::Scalar;
    using RealScalar = typename Mat::RealScalar;
    static constexpr bool IsComplex = boost::is_complex<Scalar>::value;

    CROSSCHECK_INPUT(eigen_svd_original, RealScalar);
    CROSSCHECK_OUTPUT(eigen_svd_u, RealScalar);
    CROSSCHECK_OUTPUT(eigen_svd_v, RealScalar);

    [[gnu::noinline]] static void calculate_once(const Mat &orig_matrix, Mat &u, Mat &v)
    {
        SVD fullSvd(orig_matrix, Eigen::ComputeFullU | Eigen::ComputeFullV);
        u = fullSvd.matrixU();
        v = fullSvd.matrixV();
    }

    static const RealScalar *matrix_data(const Mat &matrix)
    {
        return reinterpret_cast<const RealScalar *>(matrix.data());
    }

    static Mat original_matrix()
    {
        auto input = get_input(eigen_svd_original);
        if constexpr (IsComplex) {
            // Captured real components are not complex objects.
            Mat result(Dim, Dim);
            for (Eigen::Index i = 0; i < result.size(); ++i)
                result.data()[i] = Scalar(input[2 * i], input[2 * i + 1]);
            return result;
        } else {
            return Eigen::Map<const Mat>(input.data(), Dim, Dim);
        }
    }

    static void submit_matrices(const Mat &u, const Mat &v)
    {
        submit_output(eigen_svd_u, matrix_data(u), (IsComplex ? 2 : 1) * u.size(), "Matrix U");
        submit_output(eigen_svd_v, matrix_data(v), (IsComplex ? 2 : 1) * v.size(), "Matrix V");
    }

    static int init_matrix(const Mat &matrix)
    {
        set_input(eigen_svd_original, matrix_data(matrix), (IsComplex ? 2 : 1) * matrix.size(),
                  "Original matrix");
        Mat original = original_matrix();
        Mat u, v;
        calculate_once(original, u, v);
        submit_matrices(u, v);
        return EXIT_SUCCESS;
    }

    static int init(struct test *)
    {
        return init_matrix(Mat::Random(Dim, Dim));
    }

    static int run(struct test *test, int)
    {
        Mat original = original_matrix();
        do {
            Mat u, v;
            calculate_once(original, u, v);
            submit_matrices(u, v);
        } while (test_time_condition(test));
        return EXIT_SUCCESS;
    }
};

} // unnamed namespace

#endif // SANDSTONE_EIGEN_COMMON_H
