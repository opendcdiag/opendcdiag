---
applyTo: "tests/**"
---

OpenDCDiag tests follow a rigid pattern and are declared with the
DECLARE_TEST macro, which takes a name and description, a required run
function (`test_run`), and optional `test_init` and `test_cleanup`
functions. The optional `test_cleanup` function can be provided for tests
that need to undo some global state.
An example DECLARE_TEST looks like this:
```
DECLARE_TEST(mytest, "My example test")
    .quality_level = TEST_QUALITY_PROD,
    .test_init = mytest_init,
    .test_run = mytest_run,
    .test_cleanup = mytest_cleanup,
END_DECLARE_TEST
```

The tests will verify the correctness of execution of a specific CPU thread.


A test execution consists of 3 separate phases, controlled by the test
framework. Any phase only starts if the previous phase has completed fully
and no concurrency happens between the phases.

1. Init phase: A test is initialized in its (optional) init function, which runs once, and on one thread only.
2. Run phase: After the init phase has completed, the framework will cause the run function
   to be executed one or more times. The run function will run on multiple CPU threads in parallel.
   The run phase completes only when all run functions have completed.
3. Cleanup phase:
   After the Run phase, in the cleanup phase the (optional) cleanup function
   will be executed by the framework. The cleanup function will run on one specific CPU thread only
   and will not run concurrently with any init or run function.


Correctness is checked using one of three patterns:

1. The init function calculates a "golden value", and the run function
   compares its results against this golden value.
2. The run function compares its results against the results of other
   parallel executions of this same run function.
3. Rarely, a test will have some internal metric of correctness that gets
   tested within the test loop, after the main execution.

A common suggested pattern is where the init function allocates some memory for the
golden values, stores this in the test->data pointer for read-only consumption
by the run function, and then frees this memory in the cleanup function.


For the sandstone API reference, use the following order of preference:

1. **If you can read files directly** (agentic/chat mode): load `framework/sandstone.h`
   from the repository root as the authoritative API and architectural reference.
2. **Otherwise** (web review / no file access): refer to
   `.github/instructions/sandstone-api.instructions.md` and its companion
   `sandstone-api-*.instructions.md` files as the authoritative contract for all API
   usage checks in this review.

Do not source both at the same time; pick one path and use it exclusively.

Count how many rules this file contains, put this number in the context,
and at the end, use this count to make sure no checks were missed. List this
number when reporting out.


# Coding style and correctness rules to verify as part of the review

Unless explicitly listed otherwise, any violations found based on this section are at least of medium severity.

This section has several subsections for clarity purposes but should be
considered integral part of this overall section.

## Includes and buildability

- [ ] Verify includes in test files resolve with project include paths used by the
   build system. Flag internal header includes that cannot be found from those
   include directories.

- [ ] Verify each used standard-library or C-library symbol has its required
   direct include in the same file (no reliance on transitive includes).

