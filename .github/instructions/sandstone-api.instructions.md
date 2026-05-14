---
applyTo: "**"
---
# sandstone.h API Reference — Index

The files below document the full public API of `framework/sandstone.h`, organized by topic.
Use them when `framework/sandstone.h` cannot be read directly.

| File | Content |
| ---- | ------- |
| `sandstone-api-test-struct.instructions.md` | `DECLARE_TEST`/`END_DECLARE_TEST` pattern; all `struct test` fields; `EXIT_SKIP` |
| `sandstone-api-flags.instructions.md` | `TestQuality` enum; `test_flags` enum with all values and bitmasks |
| `sandstone-api-lifecycle.instructions.md` | Test lifecycle phases and concurrency rules; `TEST_LOOP`; timing; `test_is_retry` |
| `sandstone-api-failure.instructions.md` | `report_fail*`; all `memcmp_or_fail` overloads; `install_failure_callback`; `SANDSTONE_NO_LOGGING` effects |
| `sandstone-api-logging.instructions.md` | All `log_*` macros; `SkipCategory` enum; call-ordering constraints; `SANDSTONE_NO_LOGGING` silencing |
| `sandstone-api-threading.instructions.md` | `thread_num`; `thread_count`/`device_count`/`num_packages`; MSR access; `retrieve_physical_address`; `reschedule` |
| `sandstone-api-random.instructions.md` | `random*`; `memset_random`; `frandom*`; `set_random_bits`; `aligned_alloc_safe`; `IS_ALIGNED`; `MASK`; `IGNORE_RETVAL`; `UNUSED_ARGS` |
| `sandstone-api-cpp.instructions.md` | `TestRunner<T>`; `CpuNotSupported`/`OsNotSupported`; C++ `install_failure_callback`; `FormatterFunction`; `test_formatter` |
