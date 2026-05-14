---
applyTo: "**"
---
# sandstone.h — C++ API

## TestRunner<T>

`TestRunner<T>` is a static helper class that manages the lifecycle of a C++ test
class `T` through `test->data`.

```cpp
// T must provide:
//   T(struct test *test)          constructor
//   int init(struct test *test)   return EXIT_SKIP or EXIT_SUCCESS
//   int run(struct test *test, int cpu)
//   int cleanup(struct test *test)

DECLARE_TEST(mytest, "description")
    .test_init    = TestRunner<MyTest>::init,
    .test_run     = TestRunner<MyTest>::run,
    .test_cleanup = TestRunner<MyTest>::cleanup,
END_DECLARE_TEST
```

**Ownership rules:**
- `TestRunner<T>::init` heap-allocates `T` and stores the pointer in `test->data`.
  It asserts that `test->data` is null on entry — do not pre-set `test->data` when
  using `TestRunner`.
- `TestRunner<T>::cleanup` deletes `T` and sets `test->data = nullptr`.
- `TestRunner<T>::run` and `TestRunner<T>::cleanup` assert `test->data != nullptr`.

## CpuNotSupported / OsNotSupported

Convenience classes for use with `TestRunner` when a test cannot run on the
current CPU or OS:

```cpp
// skip unconditionally with the appropriate SkipCategory
.test_init = TestRunner<CpuNotSupported>::init,
.test_init = TestRunner<OsNotSupported>::init,
```

Both call `log_skip` with the corresponding category and return `EXIT_SKIP`.
Their `run` methods call `__builtin_unreachable()`.

Note: `CpuNotSupported::init` logs the message `"Not supported on this OS"` — this
is a known copy-paste error in the header; the skip category (`CpuNotSupportedSkipCategory`)
is correct.

## operator| for test_flags

```cpp
constexpr test_flags operator|(test_flag f1, test_flag f2);
```

Allows combining flags without a cast:
```cpp
.flags = test_schedule_sequential | test_is_optional,
```

## C++ install_failure_callback

```cpp
template <typename Callback>
void install_failure_callback(Callback cb)
    requires std::is_invocable_v<Callback>;
```

Accepts any invocable (lambda, function pointer, etc.) with signature `void()`.
- Stateless callables (convertible to `void (*)()`) are passed as a function pointer
  with no allocation.
- Stateful callables (lambdas capturing variables, etc.) are heap-allocated; the
  framework deletes the copy after `test_cleanup` runs.

**Must be called from the main thread** (typically `test_init`).

## FormatterFunction concept and test_formatter

```cpp
template <typename Callback> concept FormatterFunction =
    std::is_invocable_r_v<std::string, Callback>
    || std::is_invocable_r_v<std::string, Callback, ptrdiff_t>
    || std::is_null_pointer_v<Callback>;
```

The formatter passed to `memcmp_or_fail` must satisfy `FormatterFunction`:
either `std::string fn()` (no index) or `std::string fn(ptrdiff_t idx)` (with
the index of the first mismatch).

```cpp
bool test_formatter(std::function<std::string()> cb, size_t max);
bool test_formatter(std::function<std::string(ptrdiff_t)> cb, size_t max);
```

`test_formatter` is called internally in debug builds to validate that the
formatter does not crash when invoked for every element index up to `max`.
It is a no-op in release builds. Tests do not call it directly.
