OpenDCDiag tests follow a rigid pattern and are declared with the
DECLARE_TEST macro, which takes a name, a description, an optional init function (test_init), and a run
function (test_run) as a required argument. An optional test_cleanup can be
provided for tests that need to undo some global state.
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


Mandatory step: Load `framework/sandstone.h` immediately into the review
context.

Count how many rules this file contains, put this number in the context,
and at the end, use this count to make sure no checks were missed. List this
number when reporting out.


# Coding style and correctness rules to verify as part of the review

Unless explicitly listed otherwise, any violations found based on this section are at least of medium severity.

This section has several subsections for clarity purposes but should be
considered integral part of this overall section.


## General Checks

- [ ] Verify the code against your normal coding rules and checks for the C or
    C++ language, and flag known problematic patterns. Exceptions to the standard
    coding rules and extra checks are listed below as separate checks.
    Before reporting a violation of the normal coding rules, verify that the issue is not one of
    these exceptions.


- [ ] Unless used or reused by other C files *in the same* subdirectory, all functions in a
    file must be static to avoid naming clashes in the larger application.
    Violations of this rule are of low severity.


- [ ] Files that contain a DECLARE_TEST must be listed in
    `tests/meson.build` so that the test is included in the application.


- [ ] Use approved random number generators only. The goal of this requirement
  is that results are repeatable given the same seed. Approved random number
  generation functions are:
    - rand      (returns 15 bits)
    - random    (returns 31 bits)
    - random32  (returns 32 bits)
    - random64  (returns 64 bits)
    - random128 (returns 128 bits)
    - memset_random
    - frandomf_scale
    - frandom_scale
    - frandoml_scale
    - frandomf
    - frandom
    - frandoml
    - set_random_bits

    Unless all 32 bits are needed, random() is preferred over random32()

    RNG engines (such as std::default_random_engine or other deterministic
    PRNG engines) are also permitted, provided they are seeded exclusively
    using one of the approved functions listed above.

- [ ] Do not gather entropy manually or seed from any source other than the
  approved functions listed above. Prohibited sources include but are not
  limited to: std::random_device, time(), clock(), getpid(), /dev/urandom,
  and any hardware entropy instruction (e.g. RDRAND). Using these would break
  repeatability.

- [ ] Use the appropriate random number generator function for the datatype
      and required number of bits.

## Test Structure Checks

- [ ] Verify that a test follows one of the three correctness check patterns:
    1. The init function calculates a "golden value" and the run function
       compares its results against this golden value. Usage of test->data is
       an indicator for this pattern.
    2. The run function compares its results against the results of other
       parallel executions of this same run function
    3. Rarely, a test will have some internal metric of correctness that gets
       tested within the test loop, after the main execution. If you encounter
       a test that does this, always report this in the review, at "none"
      severity level.


- [ ] A test must loop until the test_time_condition() function returns false;
    either by using the TEST_LOOP macro (preferred) or by explicit checks in a
    do {} while loop.

- [ ] Using global variables to store golden results that get set from init
    is against coding style; the test should use test->data for this purpose.
    This is a critical level violation. Quite often, fixing this will
    resolve other review items, so if asked to provide a fix, consider resolving
    this issue first.


- [ ] It is the preferred coding style to have the test init, run and cleanup functions
    in the same file as the DECLARE_TEST test declaration


- [ ] If a test needs to return EXIT_SKIP it is the preferred coding style
    that all checks that may lead to an EXIT_SKIP return are performed in the init
    function


- [ ] It is a violation of coding style to have a test_cleanup function that
    does nothing but return EXIT_SUCCESS. This can be resolved by removing the
    function entirely and also remove the usage from the DECLARE_TEST declaration.


- [ ] It is a violation of coding style to have a test_init function that
    does nothing but return EXIT_SUCCESS. This can be resolved by removing the
    function entirely and also remove the usage from the DECLARE_TEST declaration.


- [ ] Coding style requires that each test declared with a DECLARE_TEST macro
    has Doxygen documentation at the top of the file. The documentation block must
    contain a `@test` command whose sole argument is the test name as used in
    DECLARE_TEST, with no additional text on the same line.


- [ ] test->data is a shared resource. Because the run functions operate on
    multiple CPU cores in parallel, run functions must not modify or free test->data
    or global variables without appropriate locking (for example by using a 
    pthread_mutex)


- [ ] When `install_failure_callback` is called directly from C code it
    requires three arguments: the callback `cb`, the `token` pointer
    (may be `NULL`), and a `cleanup` callback (may be `NULL`) that is
    invoked from the main thread after the test's cleanup function.
    C++ tests using the single-argument template overload are unaffected.


## Result Reporting Checks

- [ ] A test must return one of
    1. EXIT_SUCCESS in case the comparison of the data matches the expectation
    2. EXIT_SKIP when the test cannot run for some environmental factor
    3. EXIT_FAILURE when the data comparison mismatches the expectations.

    The following functions implicitly return EXIT_FAILURE and satisfy the return
    value condition:

    1. memcmp_or_fail
    2. report_fail_msg
    3. report_fail

    Using these functions is a preferred coding style over explicitly returning
    EXIT_FAILURE. These functions will cause the test to exit immediately and not
    continue execution.
    Any memory leaks caused by these functions exiting are not a bug, as
    the framework will clean up any memory allocated in this scenario.

- [ ] memcmp_or_fail() has a 3rd argument that represents the count of
    elements to compare. This is units of the size of the base argument,
    and not bytes, unless the base type is a byte. It is a bug to pass
    in a value that does not match the number of elements in the arrays
    that are to be compared.

- [ ] The C++ callback-based `memcmp_or_fail` overload accepts a
    callable returning a `std::string`. The callable may optionally accept
    a `ptrdiff_t` argument which will be set to the index of the first
    mismatch detected. The C equivalent is `memcmp_or_fail_cb` whose
    callback has the signature `char *(void *token, ptrdiff_t idx)` and
    must return a `char *` that will be freed with `free()`. The rules for
    the returned string are:
    - the first line is a human-readable text description and is placed
      in the `description:` field of the YAML output.
    - Any subsequent lines (after the first `\n`) must be valid YAML
      key-value pairs; the framework appends them under a `details:`
      key.  When a test reports operand or context data that is useful
      for automated analysis, those values should be provided as
      structured YAML in the additional lines rather than embedded only
      in the description text.

- [ ] It is a coding style violation to guard a call to memcmp_or_fail (or any
    variant) with an explicit memcmp() check on the
    same buffers or, in the case of comparable variables, comparing for equality,
    for example:
    ```
    if (memcmp(a, b, n))
        memcmp_or_fail(a, b, n, ...);  // violation: memcmp_or_fail already does this comparison
    ```
    memcmp_or_fail performs its own comparison internally; the outer memcmp is
    redundant and should be removed.

- [ ] Test code outside init, run or cleanup functions must not use EXIT_SKIP or EXIT_FAILURE


- [ ] Returning 0 from run or init, while equal in value to EXIT_SUCCESS, is a violation of the coding style.


- [ ] Coding style requires a log_skip() function to be called in the init
    function with an explanation for the cause of the skip before EXIT_SKIP
    can be returned. If EXIT_SKIP is required to be returned in the run
    function, no extra logging is permitted.
    If the failure was a result of an operating system error, include
    the error message from `strerror` (init function) or `strerror_r`
    (run function) in the skip message. If the error was from `mmap()`
    or `mprotect()`, use `strerror_for_mmap()`. Be careful not to
    overwrite `errno` by calling other functions between the error and
    obtaining the message.


- [ ] The following functions are allowed to be used in tests to do logging:
    - log_error
    - log_debug
    - log_info
    - log_skip
    - log_yaml
    - report_fail_msg

    `log_yaml` logs a message and extra details formatted in YAML; the
    level argument must be one of the SANDSTONE_LOG_* string
    constants. Code in C++ should call the `std::map` overload.

    Code should construct the strings and the `std::map` in place, not
    ahead of time, so the messages and calls are eliminated when
    `SANDSTONE_NO_LOGGING` is defined. Example:
    ```c++
        log_yaml(SANDSTONE_LOG_INFO, "Details from my test", {
                   { "cpu", cpu },
                   { "data", data },
                 });
        log_error("Data mismatches: %d != %d (%s)", data, expected, strerror(errno));
    ```

    Outside of these functions, no other logging methods (including printf
    family of functions) are allowed to be used as this would corrupt the
    formatting of the structured output of the main program.


## Memory allocation rules and checks

The OpenDCDiag framework provides custom versions of memory allocation
functionality, and special rules apply.


- [ ] In tests, memory allocation functions never fail, and
    not checking the result of memory allocation for NULL is not a bug. It is a
    violation of coding style to check these return values for NULL.
    The memory allocation functions for which this applies are:
    - malloc
    - calloc
    - posix_memalign
    - pvalloc
    - aligned_alloc
    - memalign
    - valloc
    - realloc


- [ ] In tests, all memory allocation functions initialize memory to 0. An
    explicit memset of freshly malloc'd memory to 0 is a violation of coding
    style.


- [ ] At the end of a test, the program will exit and all allocated memory will
    be automatically freed in case of an error and in various other cases.
    Explicitly freeing of allocated memory in case of a failure (EXIT_FAILURE
    etc) is a coding style violation. Note: this rule applies to the
    failure/exit path only. Memory allocated within the TEST_LOOP loop body
    must still be freed within the same iteration, as described by the next
    rule.


- [ ] All memory that is allocated inside the run function inside the
     TEST_LOOP loop must be freed within the same iteration of the test loop


- [ ] If the init function allocates memory for the test->data field, there are two valid patterns
    1. (Preferred pattern) The cleanup function frees this memory.
       Memory leaks in this pattern are of medium severity.
    2. (Legacy pattern) No cleanup function is implemented

    If a cleanup function exists, all memory allocated in the init function must be freed
    in the cleanup function.


- [ ] Per-thread memory usage for a test must not exceed 64 MB (hard limit).
    The soft limit is 40 MB per test thread.

    Exceeding the hard limit is a critical severity
    violation; exceeding the soft limit is a medium severity violation that
    should be flagged with a recommendation to reduce allocations or make buffer
    sizes configurable via test knobs.

    Exception: if a test genuinely requires
    more than 64 MB per thread, it must set the `test_flag_ignore_memory_use`
    flag in its DECLARE_TEST declaration. When this flag is present, the hard
    limit check does not apply.

    If the test allocates memory in the init function, add an element to the
    "Notes" section with "none" severity listing the amount of memory allocated
    per thread.

- [ ] Dynamically allocated global variables get set to NULL after the
    memory is freed. This does not apply to variables that are declared
    within the scope of a function.

    Good pattern example (snippet):
    ```c
       free(global_ptr);
       global_ptr = NULL;
       return 0;
    ```
    Bad pattern example (snippet):
    ```c
       free(global_ptr);
       return 0;
    ```
- [ ] Functions that take a pointer to a buffer as argument, need to also
    have an argument for the size of the buffer (preferred) or there must be a
    global define that all code agrees on as the size of the buffer.
    When generating new code, only follow the preferred code pattern.

