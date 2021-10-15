/**
 * @file
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_EIGEN_COMMON_H
#define SANDSTONE_EIGEN_COMMON_H

#include <sandstone.h>

#include <boost/type_traits/is_complex.hpp>
#include <Eigen/Eigenvalues>

namespace {
template <typename SVD, int Dim> struct EigenSVDTest
{
    using Mat = typename SVD::MatrixType;
    struct eigen_test_data {
        Mat orig_matrix;
        Mat u_matrix;
        Mat v_matrix;
    };

    [[gnu::noinline]] static void calculate_once(const Mat &orig_matrix, Mat &u, Mat &v)
    {
        SVD fullSvd(orig_matrix, Eigen::ComputeFullU | Eigen::ComputeFullV);
        u = fullSvd.matrixU();
        v = fullSvd.matrixV();
    }

    template <typename FP> static inline std::enable_if_t<boost::is_complex<FP>::value>
    compare_or_fail(const FP *actual, const FP *expected, const char *name)
    {
        memcmp_or_fail(reinterpret_cast<const typename FP::value_type *>(actual),
                       reinterpret_cast<const typename FP::value_type *>(expected),
                       2 * Dim * Dim, name);
    }

    template <typename FP> static inline std::enable_if_t<!boost::is_complex<FP>::value>
    compare_or_fail(const FP *actual, const FP *expected, const char *name)
    {
        memcmp_or_fail(actual, expected, Dim * Dim, name);
    }

    static int init(struct test *test)
    {
        auto d = new eigen_test_data;
        d->orig_matrix = Mat::Random(Dim, Dim);
        calculate_once(d->orig_matrix, d->u_matrix, d->v_matrix);
        test->data = d;
        return EXIT_SUCCESS;
    }

    static int cleanup(struct test *test)
    {
        delete static_cast<eigen_test_data *>(test->data);
        return EXIT_SUCCESS;
    }

    static int run(struct test *test, int)
    {
        auto d = static_cast<eigen_test_data *>(test->data);
        do {
            Mat u, v;
            calculate_once(d->orig_matrix, u, v);

            compare_or_fail(u.data(), d->u_matrix.data(), "Matrix U");
            compare_or_fail(v.data(), d->v_matrix.data(), "Matrix V");
        } while (test_time_condition(test));
        return EXIT_SUCCESS;
    }
};

} // unnamed namespace

#endif // SANDSTONE_EIGEN_COMMON_H
