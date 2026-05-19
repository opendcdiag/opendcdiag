---
applyTo: "**"
---
# sandstone.h — Test Lifecycle and Loop Control

## Lifecycle phases

Phases execute sequentially. No two phases run concurrently. A phase only starts
if the previous phase completed without error.

| Order | Function | Where it runs | Notes |
| ----- | -------- | -------------- | ----- |
| 1 | `test_preinit(test)` | Parent process, once per application run | May set `test->data` to a skip-message string and return `EXIT_SKIP`. Do not use the random generator here. |
| 2 | `test_init(test)` | Child main thread | Allocate resources; store in `test->data`. Return `EXIT_SKIP` to skip. Runs in parent if `test_init_in_parent` flag is set (do not use random generator or cause memory side-effects in that case). |
| 3 | `test_run(test, thread)` | Child, all threads in parallel | Called one or more times. Must use `TEST_LOOP` for time-bounded execution. Return `EXIT_SUCCESS` or `EXIT_FAILURE`. |
| 4 | `test_cleanup(test)` | Child main thread | Free resources allocated in `test_init`. |
| 5 | `test_postcleanup(test)` | Child main thread, once per application run | Mirror of `test_preinit`. |

## TEST_LOOP

```c
TEST_LOOP(test, N) {
    /* body executed N times per outer iteration */
}
```

- `N` **must be a power of 2** (enforced by convention; `static_assert(N > 0)` is present).
- The framework checks elapsed time after every N body executions. If the time slot
  has expired, the loop exits; otherwise it runs another N iterations.
- `TEST_LOOP` internally calls `test_loop_start()` and `test_loop_end()` —
  these are **framework-internal**; tests must not call them directly.
- Every `test_run` function that loops over time **must** use `TEST_LOOP`. Do not
  hand-roll a loop around `test_time_condition()`.

## Timing functions

`bool test_time_condition()` — returns `true` if time remains. Prefer `TEST_LOOP`.
`test_time_condition(test)` (with an argument) is also valid; a macro wrapper
silently drops the argument and calls the no-argument form.
Calling `test_time_condition()` before doing any work in the loop is flagged by
`--test-tests` unless `test_flag_ignore_do_while` is set.

`bool test_loop_condition(int N)` — called by `TEST_LOOP`; not for direct use.
When idle-cycle injection is configured, this function may call `usleep()`.

## desired_duration and fracture_loop_count interaction

- `desired_duration < 0`: test is expected to run exactly once; set
  `test_flag_ignore_test_undertime` or `--test-tests` will warn.
- `fracture_loop_count > 1`: the framework splits the run into sub-runs at the
  specified inner-loop count boundary, allowing finer-grained failure attribution.

## Retry

`bool test_is_retry()` — returns `true` if the current invocation is a retry of a
previously failed run. Tests may use this to adjust behaviour (e.g., reduce work to
isolate the failing thread faster), but must not skip correctness checks.
