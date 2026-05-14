---
applyTo: "**"
---
# sandstone.h — Test Structure and Declaration

## DECLARE_TEST pattern

```c
DECLARE_TEST(test_id, "one-line description")
    .quality_level  = TEST_QUALITY_PROD,
    .test_preinit   = my_preinit,   /* optional */
    .test_init      = my_init,      /* optional */
    .test_run       = my_run,       /* required */
    .test_cleanup   = my_cleanup,   /* optional */
    .test_postcleanup = my_postcleanup, /* optional */
    .flags          = test_schedule_sequential,
    .desired_duration = 0,
END_DECLARE_TEST
```

`DECLARE_TEST_GROUPS(...)` assigns the test to one or more `struct test_group*` groups;
assign the result to `.groups`.

## struct test fields

| Field | Type | Meaning |
| ----- | ---- | ------- |
| `id` | `const char *` | Unique string identifier; set by macro. |
| `description` | `const char *` | One-line human description; set by macro. |
| `groups` | `const struct test_group * const *` | Array of group pointers; set via `DECLARE_TEST_GROUPS`. |
| `test_preinit` | `initfunc` | Called once in parent process per application run. Optional. |
| `test_init` | `initfunc` | Called in child main thread before run. Optional. |
| `test_run` | `runfunc` | Called per thread in parallel. Required. Signature: `int fn(struct test *, int thread)`. |
| `test_cleanup` | `cleanupfunc` | Called in child main thread after run. Optional. |
| `test_postcleanup` | `cleanupfunc` | Called in child main thread, once per application run. Optional. |
| `quality_level` | `test_quality` | See `sandstone-api-flags.instructions.md`. |
| `flags` | `test_flags` | See `sandstone-api-flags.instructions.md`. |
| `desired_duration` | `int` (ms) | `0`=default, `<0`=run once, `INT_MAX`=run forever (must be killed). |
| `minimum_duration` | `int` (ms) | Lower bound on run time; `0`=no limit. Note: the header comment incorrectly says "upper bound" — the field name and semantic are authoritative. |
| `maximum_duration` | `int` (ms) | Upper bound on run time; `0`=no limit. |
| `fracture_loop_count` | `int` | `<0`=never fracture, `0`=auto, `>1`=fracture at that inner loop count. |
| `minimum_cpu` | `device_features_t` | Minimum device feature set; test is skipped if device is older. |
| `data` | `void *` | Test-lifetime opaque pointer. Set in `test_init`, read in `test_run`, freed in `test_cleanup`. If test was skipped in preinit, points to a skip message string. |
| `per_thread` | `struct test_data_per_thread *` | Array indexed by `thread_num`; each element has a `void *data` slot for per-thread state. |

`test_kvm_config` (KVM configuration callback) is intentionally omitted; it is
only relevant to KVM-based tests.

## EXIT_SKIP

`EXIT_SKIP` (`-255`) — return this from `test_init` (or `test_preinit`) to skip the test.
Always call `log_skip(category, ...)` before returning `EXIT_SKIP`.
