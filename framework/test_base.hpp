/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_TEST_BASE_H
#define INC_TEST_BASE_H

#include <sandstone.h>

#include <concepts>
#include <type_traits>

#ifdef __cpp_lib_format
#  include <format>
#endif

namespace SandstoneTest {
class Base;
template <typename T> concept TestClass =
        // must derive from Base
        std::derived_from<T, Base> &&
        // must be default constructible or constructible from `struct test *`
        (std::is_default_constructible_v<T> || std::is_constructible_v<T, struct test *>) &&
        // must provide a const char *description member
        requires { static_cast<const char *>(T::description); } &&
        // must provide a quality level
        std::is_enum_v<decltype(T::quality_level)>;

class Base
{
public:
    using BaseClass = Base; // "hack" to make "inheritance" in static _apply_parameters() work

    struct Device
    {
        // generic
        int id;
    };
    struct Parameters
    {
        // common
        /*std::chrono::milliseconds*/ int desired_duration;
        int fracture_loop_count;

        device_features_t minimum_device;
    };

    enum class TestQuality
    {
        Skipped,
        Beta,
        Production,
        Optional,
    };

    static constexpr struct test_group* const* groups = nullptr;

protected:
    template <int N, typename Lambda> void test_loop(Lambda &&l)
    {
        static_assert(std::is_same_v<decltype(l()), void>, "test_loop lambda must return void");
        static_assert(N > 0, "N must be positive");     \
        test_loop_start();                              \
        do {
            for (int i = 0; i < N; ++i)
                l();
        } while (_internal_loop_continue());
        test_loop_end();
    }

    struct Failed : std::exception
    {
        const char* msg; // TODO reconsider storing the msg (issue for no-logging builds)

        Failed(const char* msg = nullptr, ...) : msg{msg} {};

        const char *what() const noexcept override
        {
            return msg;
        }
    };

    struct Skipped : std::exception
    {
        SkipCategory cat;
        const char* msg; // TODO ditto

        Skipped(SkipCategory cat, const char* msg = nullptr, ...) : cat{cat}, msg{msg} {};

        SkipCategory skip_category() const noexcept
        {
            return cat;
        }

        const char *what() const noexcept override
        {
            return msg;
        }
    };

    bool _internal_loop_continue() noexcept
    {
        return test_time_condition();
    }

    template <TestClass T>
    static constexpr void _apply_parameters_base(struct test *test)
    {
        // handles only base parameters
        if constexpr (requires { T::parameters; }) {
            test->desired_duration = T::parameters.desired_duration;
            test->fracture_loop_count = T::parameters.fracture_loop_count;
        }
    }

    // emit this specialization only for tests inheriting directly from Base, e.g. smi_count
    template <TestClass T, std::enable_if_t<std::is_same_v<typename T::BaseClass, Base>, bool> = true>
    static constexpr void _apply_parameters(struct test *test)
    {
        Base::_apply_parameters_base<T>(test);
    }

    template <TestClass T> struct CallbackAdapter
    {
        static Base *factory(struct test *test)
        {
            if constexpr (std::is_constructible_v<T, struct test *>) {
                return new T(test);
            } else {
                return new T();
            }
        }

        static int preinit(struct test *test)
        {
            try {
                if constexpr (requires { T::preinit(test); }) {
                    return T::preinit(test);
                } else if constexpr (requires { T::preinit(); }) {
                    return T::preinit();
                } else {
                    return EXIT_SUCCESS;
                }
            } catch (Skipped& e) {
                log_skip(e.skip_category(), "%s", e.what());
                return EXIT_SKIP;
            } catch (Failed &e) {
                log_error("%s", e.what());
                return EXIT_FAILURE;
            }
        }

        static int init(struct test *test)
        {
            Base* this_test;
            // Test constructor can throw with either skip or fail
            try {
                this_test = factory(test);
            } catch (Skipped &e) {
                log_skip(e.skip_category(), "%s", e.what());
                return EXIT_SKIP;
            } catch (Failed &e) {
                log_error("%s", e.what());
                return EXIT_FAILURE;
            }
            test->data = this_test;
            try {
                if constexpr (requires { static_cast<T*>(this_test)->init(test); }) {
                    return static_cast<T*>(this_test)->init(test);
                } else if constexpr (requires { static_cast<T*>(this_test)->init(); }) {
                    return static_cast<T*>(this_test)->init();
                } else {
                    return EXIT_SUCCESS;
                }
            } catch (Skipped& e) {
                log_skip(e.skip_category(), "%s", e.what());
                return EXIT_SKIP;
            } catch (Failed &e) {
                log_error("%s", e.what());
                return EXIT_FAILURE;
            }
        }

        static int cleanup(struct test *test)
        {
            T *this_test = static_cast<T*>(test->data);
            auto ret = EXIT_SUCCESS;
            try {
                if constexpr (requires { this_test->cleanup(test); }) {
                    ret = this_test->cleanup(test);
                } else if constexpr (requires { this_test->cleanup(); }) {
                    ret = this_test->cleanup();
                }
            } catch (Skipped& e) {
                log_skip(e.skip_category(), "%s", e.what());
                ret = EXIT_SKIP;
            } catch (Failed &e) {
                log_error("%s", e.what());
                ret = EXIT_FAILURE;
            }
            delete this_test;
            test->data = nullptr;
            return ret;
        }

        static int run(struct test *test, int device_id)
        {
            T* this_test = static_cast<T*>(test->data);
            Device this_device{device_id};
            try {
                if constexpr (requires { this_test->run(test, this_device); }) {
                    return this_test->run(test, this_device);
                } else if constexpr (requires { this_test->run(test); }) {
                    return this_test->run(test);
                } else if constexpr (requires { this_test->run(this_device); }) {
                    return this_test->run(this_device);
                } else { // We expect that any run() definition would exist
                    return this_test->run();
                }
            } catch (Skipped& e) {
                log_skip(e.skip_category(), "%s", e.what());
                return EXIT_SKIP;
            } catch (Failed &e) {
                log_error("%s", e.what());
                return EXIT_FAILURE;
            }
        }
    };

public:
    template <TestClass T> static consteval struct test create_test_class(const char *id);
};

template <TestClass T> consteval struct test Base::create_test_class(const char *id)
{
    struct test res = {};
    res.id = id;
    res.description = T::description;
    res.groups = T::groups;
    res.test_preinit = &CallbackAdapter<T>::preinit;
    res.test_init = &CallbackAdapter<T>::init;
    res.test_cleanup = &CallbackAdapter<T>::cleanup;
    res.test_run = &CallbackAdapter<T>::run;
    if (T::quality_level == Base::TestQuality::Skipped)
        res.quality_level = TEST_QUALITY_SKIP;
    else if (T::quality_level == Base::TestQuality::Beta)
        res.quality_level = TEST_QUALITY_BETA;
    else
        res.quality_level = TEST_QUALITY_PROD;

    T::template _apply_parameters<T>(&res);
    return res;
}

} // namespace SandstoneTest

#ifndef SANDSTONE_TEST_STRINGIFY
#  define SANDSTONE_TEST_STRINGIFY(x)       SANDSTONE_STRINGIFY(x)
#endif

#define DECLARE_TEST_CLASS(test_id, ...)            \
    __attribute__((aligned(alignof(void*)), used, section(SANDSTONE_SECTION_PREFIX "tests"))) \
    constinit struct test _test_ ## test_id =       \
        SandstoneTest::Base::create_test_class<__VA_ARGS__>(SANDSTONE_TEST_STRINGIFY(test_id))

#endif // INC_TEST_BASE_H
