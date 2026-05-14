---
applyTo: "**"
---
# sandstone.h — Failure Reporting

All failure-reporting functions are `noreturn`: they kill the calling thread and
cause the test to exit with a failure result. They must only be called from `test_run`.

## report_fail / report_fail_msg

```c
report_fail(test);                    // annotates with __FILE__ and __LINE__
report_fail_msg(fmt, ...);            // annotates with printf-style message + file/line
```

Use `report_fail_msg` when additional context helps diagnose the failure.

## memcmp_or_fail

Compares `actual` and `expected` arrays of `count` elements. If they differ, kills
the calling thread and logs the first mismatch with hex dump and element index.
`count` is the **number of elements**, not bytes.

```c
// C and C++ — no annotation
memcmp_or_fail(actual, expected, count);

// C and C++ — printf annotation (useful when a test does multiple comparisons)
memcmp_or_fail(actual, expected, count, fmt, ...);

// C++ only — formatter callback: std::string fn() or std::string fn(ptrdiff_t idx)
memcmp_or_fail(actual, expected, count, formatter);

// C only — low-level callback variant
memcmp_or_fail_cb(actual, expected, count, cb, token);
```

`actual` and `expected` must point to typed arrays (any `ValidDataType`); the type
is inferred. The formatter callback receives the index of the first mismatch and
returns a `std::string` with extra diagnostic info.

## install_failure_callback

```c
// C
void install_failure_callback(void (*cb)(void *), void *token, void (*cleanup)(void *));

// C++ — accepts any invocable (lambda, function pointer, etc.)
install_failure_callback(callable);
```

- **Must be called from the main thread** (typically `test_init`).
- `cb` is called **at most once per thread** on the first failure event in that thread.
  Failure events: `memcmp_or_fail`, `log_error`, `report_fail_msg`, thrown exception,
  or `test_run` returning failure.
- `cleanup` (may be null) is called from the main thread after `test_cleanup`.
- The C++ template overload manages lifetime automatically for non-stateless callables
  (heap-allocates a copy; `cleanup` deletes it).

## SANDSTONE_NO_LOGGING effects on failure functions

When `SANDSTONE_NO_LOGGING` is defined:
- `report_fail` / `report_fail_msg` still terminate the thread but suppress log output.
- `memcmp_or_fail` still detects mismatches and terminates; formatter/fmt args are ignored.
- `memcmp_or_fail_cb` uses null callback and token.
- `install_failure_callback` becomes a no-op (`(void)cb`).
