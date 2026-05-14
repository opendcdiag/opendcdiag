---
applyTo: "**"
---
# sandstone.h — TestQuality and test_flags Enums

## TestQuality enum

| Value | Integer | Meaning |
| ----- | ------- | ------- |
| `TEST_QUALITY_SKIP` | `-1` | Never run. |
| `TEST_QUALITY_BETA` | `0` | Run only with `--beta` flag (default for new tests). |
| `TEST_QUALITY_PROD` | `2` | Run by default. |

Note: value `1` is intentionally absent from the enum.

## test_flags enum

| Flag | Value | Meaning |
| ---- | ----- | ------- |
| `test_schedule_default` | `0` | Framework picks best scheduling heuristic. |
| `test_schedule_sequential` | `1` | Threads run sequentially, not in parallel. |
| `test_schedule_fullsystem` | `2` | All logical processors in one child process. |
| `test_schedule_isolate_socket` | `3` | One child process per socket, all cores. |
| `test_schedule_isolate_numa_domain` | `4` | One child process per NUMA domain per socket. |
| `test_flag_ignore_memory_use` | `0x0010` | `--test-tests`: ignore memory consumption check. |
| `test_flag_ignore_test_overtime` | `0x0020` | `--test-tests`: ignore >25% over requested duration. |
| `test_flag_ignore_test_undertime` | `0x0040` | `--test-tests`: ignore >25% under requested duration. |
| `test_flag_ignore_loop_timing` | `0x0080` | `--test-tests`: ignore inner loop timing checks. |
| `test_flag_ignore_do_while` | `0x0100` | `--test-tests`: ignore early `test_time_condition()` detection. |
| `test_failure_package_only` | `0x1000` | Failure attributed to package, not thread/core. |
| `test_is_optional` | `0x2000` | Only run with `--include-optional`. |
| `test_requires_smt` | `0x4000` | Requires SMT/Hyperthreading enabled. |
| `test_init_in_parent` | `0x10000` | Run `test_init` in parent; do not use random generator or cause memory side-effects. |
| `test_in_parent` | `0x20000` | Entire test runs in parent regardless of mode. |

Multiple flags may be combined with `|`. In C++, `operator|` is provided for
`test_flag` values and returns `test_flags` without requiring a cast.
