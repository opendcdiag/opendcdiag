# A Guide to Writing OpenDCDiag tests

This guide explains how to write tests for the OpenDCDiag framework.

## A first test

OpenDCDiag tests are written in C, C++, and occasionally in assembly language.
Simple tests consist of a single source file that contains a declarative
section, providing the framework with information about the test, and a
number of function calls that implement the test.

A [very simple test](../tests/examples/simple_add.c) is presented below

```c
/**
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b simple_add
 * @parblock
 * simple_add repeatedly adds the same two random numbers on each thread
 * and checks all threads produce the same result.
 * @endparblock
 */

#include "sandstone.h"
static unsigned int value1;
static unsigned int value2;
static unsigned int golden_sum;

static int simple_add_init(struct test *test)
{
    value1 = random32();
    value2 = random32();
    golden_sum = value1 + value2;

    return EXIT_SUCCESS;
}

static int simple_add_run(struct test *test, int cpu)
{
    unsigned int sum;

    TEST_LOOP(test, 1 << 20) {
        sum = value1 + value2;
        if (sum != golden_sum)
            report_fail_msg("Add failed.  Expected %u got %u", golden_sum, sum);
    }

    return EXIT_SUCCESS;
}

DECLARE_TEST(simple_add, "Repeatedly add two integer numbers")
    .test_init = simple_add_init,
    .test_run = simple_add_run,
    .quality_level = TEST_QUALITY_BETA,
END_DECLARE_TEST
```

The test begins with a comment containing the test name and a description of the
test. Each OpenDCDiag test is expected to contain such a comment providing some
information about what the test does and how it operates. The comment is
followed by some global variables\*, two static functions, and a declarative
section that registers the test with the OpenDCDiag framework.

:warning: \* Normally, it is not good practice to store test-specific data in global
  variables. The reason for this and an alternative method for managing test
  data are presented later in the document.

### Declaring a new test

A new test is declared using the DECLARE_TEST macro. The first parameter is a test name.
Test names must be unique, are never changed once the test is merged, and should
also match the test name specified in the test description comment. The test name is
followed by a one-line description of the test. The DECLARE_TEST macro defines a new
instance of an OpenDCDiag *test* structure, which is documented in
[sandstone.h](../framework/sandstone.h). The *test* structure contains a number
of fields that tests can set to provide the OpenDCDiag framework with
information about the test. Our simple test sets three of these fields, each of
which will be explained below. For now, let's build and run our test.

### Building and running the test

The examples are not registered in the build. To build simple_add, add the
following block to [tests/cpu/meson.build](../tests/cpu/meson.build) before
`tests_set_base.apply(tests_config)`, then rebuild:

```meson
tests_set_base.add(
    files(
        '../examples/simple_add.c',
    )
)
```

For a new CPU test, add its source to the appropriate source set in that file
before the source set is applied. Paths passed to `files()` are relative to
`tests/cpu/`, so an example source uses `../examples/`, while a source under
`tests/cpu/<testname>/` uses `<testname>/<filename>`.

Now let's check to see if our test is available. A list of tests can be
obtained by passing the --list to the opendcdiag binary. Let's search for
our test by name.

```console
./opendcdiag --beta --list
```

You should see a list of test names and their descriptions. Somewhere in this
list there should be a line that looks something like this.

```
23 simple_add           "Repeatedly add two integer numbers"
```

To run the test, type

```
./opendcdiag --beta -v -e simple_add --output-format=tap
# opendcdiag --beta -v -e simple_add --output-format=tap
# Operating system: Linux 5.14.2-arch1-2
# Random generator state: LCG:560936296
ok   1 simple_add               # (beta test)
ok   2 simple_add               # (beta test)
ok   3 simple_add               # (beta test)
ok   4 simple_add               # (beta test)
ok   5 simple_add               # (beta test)
ok   6 simple_add               # (beta test)
ok   7 simple_add               # (beta test)
ok   8 mce_check
exit: pass
```

And you should see that the test has run and passed.

### Test quality

To execute our new test and see it in the list of tests, we needed to
pass the '--beta' command line option. The reason for this is that we added
the following to our test declaration

```c
        .quality_level = TEST_QUALITY_BETA,
```

By default, OpenDCDiag only runs production tests when executed, i.e., tests
with a *quality_level* of *TEST_QUALITY_PROD*. Why then did we label our new
test as a beta test?  This is an OpenDCDiag convention. New tests always
have their quality level set to *TEST_QUALITY_BETA*. After they have been merged
for a while and have executed without issue, their status is upgraded to
*TEST_QUALITY_PROD*.

### Fracturing

The test should have run and passed multiple times.
Each test is given a time slot in which it can run. By default, this time slot
is one second, but this default can be overridden in the test declaration using
the *desired_duration*, *minimum_duration*, and *maximum_duration* fields.  By
default, the OpenDCDiag framework continually runs a test until its
allocated time period has elapsed. Each test invocation is run in its own
process with a different random number seed. Assuming that the test uses random
numbers, as our simple test does, each invocation of the test performs
a different computation. This feature of OpenDCDiag is referred to as
fracturing and is the reason that you see the test being run multiple times.
Fracturing is enabled by default for all tests but it can be disabled on a test-
by-test basis by specifying a value of less than 0 for the *fracture_loop_count*
field when declaring a test. It may make sense to disable fracturing if you
only want your test to run once for some reason or if your init function (see
below) is very expensive.  It is also possible to disable fracturing from the
command line using the --max-test-loop-count option.  Specifying this option on
the opendcdiag command line and setting it to 0, e.g.,
--max-test-loop-count=0, disables fracturing for that run of opendcdiag.

### Test execution

By default, the OpenDCDiag framework runs a test as follows:

1. It creates a new process.
2. It calls test_init() if supplied, normally on the new process's main thread.
3. It creates a worker for each hardware thread selected for this execution and
pins each worker to its hardware thread.
4. It invokes test_run() on each worker, not on the coordinator.
5. It joins the workers and verifies outputs submitted through the optional
cross-check API.
6. It calls test_cleanup() if supplied, then reports the test's outcome,
including verification and cleanup results.
7. It may re-execute the test in a new process if time permits, as we have seen.

A failed or skipped test_init() returns before workers or test_cleanup() run.
A crash or hang can also prevent verification and cleanup from completing.
Tests that use [slicing](#slicing) follow this lifecycle separately in each slice.

To put this in the context of our simple_add test, the framework creates a new
process and calls our simple_add_init function on the main thread of this
process. Our init function generates two random integers, computes their sum,
and stores all three values in global variables. It returns EXIT_SUCCESS to
indicate that the test can proceed. The framework creates and pins the workers,
then invokes test_run() on each worker. Our run function sums the two random
numbers and compares the result to the precomputed *golden_sum*. A mismatch
signals an error through report_fail_msg, which logs the error and exits the
thread. Our computation and comparison run repeatedly in a loop generated by
the TEST_LOOP macro.
TEST_LOOP executes its body continuously until it is asked to terminate by the
OpenDCDiag framework. The second parameter to TEST_LOOP specifies the
granularity of our loop. In our simple_add test, we set the granularity to
`1 << 20`. TEST_LOOP will perform `1 << 20` iterations and then ask the framework
whether it's okay to continue executing. If there is some more time left in the
test's time slot TEST_LOOP performs another `1 << 20` iterations before checking
with the framework again. The process continues until the framework asks the
test to exit. By convention, the second parameter to TEST_LOOP is always a
power of two. The OpenDCDiag framework includes a facility to help test writers
select an appropriate value for the second parameter of TEST_LOOP. For
more information, see the [Test Tuning](#test-tuning) section below.

Our simple_add test is trivial and is unlikely to detect any real
problems. It does, however, illustrate the pattern used by most OpenDCDiag
tests. It computes a golden value in the *test_init* function, and then recomputes
that value in the test_run function that is executed on multiple hardware threads.
The values computed by test_run are compared to the initial golden value and,
if there is a mismatch, an error is reported.


### Random numbers

Random numbers in simple_add are generated using a framework function called
random32 that returns a random number using the random number generator selected
for this invocation of OpenDCDiag. OpenDCDiag uses a number of different
random number generators and information about the generator used for any given
invocation is output when OpenDCDiag is run. Returning to the example output of our
OpenDCDiag invocation above, we see

```
# opendcdiag --beta -v -e simple_add --output-format=tap
# Operating system: Linux 5.14.2-arch1-2
# Random generator state: LCG:560936296
```

By default a different random number generator and seed is chosen each time
OpenDCDiag is run. However, this behavior can be overridden by specifying the
-s command line options. For example,

```
./opendcdiag --beta -v -s LCG:560936296 -e simple_add  --output-format=tap
```

results in a new invocation of simple_add that performs the exact same set
of computations as our original invocation. This is an important feature of the
OpenDCDiag framework as it allows failed tests that use random numbers to be
replayed using the same data. For this reason, it is important that tests use
the random number functions provided by the framework. The framework provides a
rich set of random number generating functions for a variety of types. These
are documented in [sandstone.h](../framework/sandstone.h). Examples include
*random64* for generating an unsigned random 64 bit numbers, *frandomf* for
generating a random float between 0.0 and 1.0, and *memset_random* for filling a
buffer with random data. The framework also overrides C standard library and OS
specific random functions such as *rand* and *random*, so that random numbers
generated by any 3rd party libraries used by the tests will also be generated
using the framework and hence reproducible.

## A second test

Now that we've covered the basics of creating an OpenDCDiag test, let's try
something a little bit more complex. Our new test is still going to test the
system's ability to add numbers, but rather than adding two numbers per thread
on each iteration of the test, we're going to add 1024 numbers, and we're going
to do the addition using SIMD instructions.
Here's our [new test](../tests/examples/vector_add.c).

```c
/**
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b vector_add
 * @parblock
 * vector_add repeatedly adds two arrays of random numbers together using
 * AVX-512 instructions and checks that their output is correct.
 * @endparblock
 */

#include "sandstone.h"

#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define VECTOR_ADD_ELEMENTS (1u << 10)
#define VECTOR_ADD_BUF_SIZE (VECTOR_ADD_ELEMENTS * sizeof(uint32_t))

struct vector_add_t_ {
    uint32_t *a;
    uint32_t *b;
    uint32_t *golden;
};
typedef struct vector_add_t_ vector_add_t;

static void prv_do_add(const uint32_t *a, const uint32_t *b, uint32_t *res)
{
    for (size_t i = 0; i < VECTOR_ADD_ELEMENTS / 16; i++) {
        __m512i r1 = _mm512_load_epi32(&a[i*16]);
        __m512i r2 = _mm512_load_epi32(&b[i*16]);
        __m512i r3 = _mm512_add_epi32(r1, r2);
        _mm512_store_epi32(&res[i*16], r3);
    }
}

static int vector_add_init(struct test *test)
{
    vector_add_t *va = malloc(sizeof(*va));
    va->a = aligned_alloc(64, VECTOR_ADD_BUF_SIZE);
    va->b = aligned_alloc(64, VECTOR_ADD_BUF_SIZE);
    va->golden = aligned_alloc_safe(64, VECTOR_ADD_BUF_SIZE);
    memset_random(va->a, VECTOR_ADD_BUF_SIZE);
    memset_random(va->b, VECTOR_ADD_BUF_SIZE);
    prv_do_add(va->a, va->b, va->golden);
    test->data = va;

    return EXIT_SUCCESS;
}

static int vector_add_run(struct test *test, int cpu)
{
    vector_add_t *va = test->data;
    uint32_t *res = aligned_alloc(64, VECTOR_ADD_BUF_SIZE);

    TEST_LOOP(test, 1 << 13) {
        memset(res, 0, VECTOR_ADD_BUF_SIZE);
        prv_do_add(va->a, va->b, res);
        memcmp_or_fail(res, va->golden, VECTOR_ADD_ELEMENTS);
    }

    free(res);

    return EXIT_SUCCESS;
}

static int vector_add_cleanup(struct test *test)
{
    vector_add_t *va = test->data;
    if (va) {
        free(va->golden);
        free(va->b);
        free(va->a);
        free(va);
    }
    return EXIT_SUCCESS;
}

DECLARE_TEST(vector_add, "Repeatedly add arrays of unsigned integers using AVX-512 instructions")
    .test_init = vector_add_init,
    .test_run = vector_add_run,
    .test_cleanup = vector_add_cleanup,
    .minimum_cpu = cpu_skylake_avx512,
    .quality_level = TEST_QUALITY_BETA,
END_DECLARE_TEST
```

This new test makes more use of the OpenDCDiag framework than the first test and
we'll discuss each of the differences below. To build vector_add, add the
following block to [tests/cpu/meson.build](../tests/cpu/meson.build) before
`tests_set_skx.apply(tests_config)`, then rebuild:

```meson
tests_set_skx.add(
    files(
        '../examples/vector_add.c',
    )
)
```

### Base architecture, mixed builds, and C++ global statics

Note this registration uses tests_set_skx.add instead of tests_set_base.add.
This is required as our new test makes use of Intel® Advanced Vector Extensions
512 (Intel® AVX-512) intrinsics and will only build if our test source file is
compiled with the correct compiler options, in this case -march=skylake-avx512.
This command line option is not specified when compiling the files added to
tests_set_base. It follows then that not all the source files in an OpenDCDiag
build are compiled with the same compile options and this has some implications.

1. The framework and tests added to tests_set_base use the configured base
   architecture. On x86-64, this is selected through the march_base Meson
   option; tests_set_skx adds the Skylake AVX-512 target unless the base already
   supports AVX-512. This source set is built only for x86-64.
2. The OpenDCDiag binary is only guaranteed to run correctly on machines that
   support the base architecture or greater. If run on older machines, it will
   crash with SIGILL.
3. Test writers adding new tests that use features of the CPU not present in the
   base architecture need to inform the framework that their test requires a
   specific CPU feature. This is done using the DECLARE_TEST macro, which is
   shown later. The framework checks the capabilities of the CPU on which it is
   executed at runtime and skips any tests requiring features that the CPU does
   not support.
4. Tests that are compiled with an -march greater than the base -march cannot
   define global static variables that generate code. This is just an issue for
   C++ tests that might define a global static instance of a class that has a
   constructor. The compiler may generate code for the constructor that uses
   instructions that are not present in the base architecture, and as this code
   is run at program startup before the framework itself starts, the framework
   cannot prevent it from executing. The end result could be that OpenDCDiag
   would fail to start when run on a machine that just supported the base
   architecture. For this reason, global statics are not allowed in OpenDCDiag
   tests. Note that some of the C++ standard library header files define global
   statics, e.g., \<iostream\>, so the inclusion of such files in OpenDCDiag
   tests is not permitted.

### Running vector_add

We run our new test using the opendcdiag command as before specifying our new
test name

```
./opendcdiag --beta -v -e vector_add --output-format=tap
```

and the result should be something like this.

```
# opendcdiag --beta -v -e vector_add --output-format=tap
# Operating system: Linux 5.14.2-arch1-2
# Random generator state: LCG:112841597
ok   1 vector_add               # (beta test)
ok   2 vector_add               # (beta test)
ok   3 vector_add               # (beta test)
ok   4 mce_check
exit: pass
```

This output was generated on a machine that supports Intel AVX-512 and so our test
ran and passed. On a machine without Intel AVX-512 support, you should see
something like this instead.

```
# opendcdiag --beta -v -e vector_add --output-format=tap
# Operating system: Linux 5.14.2-arch1-2
# Random generator state: LCG:1332445696
ok   1 vector_add               # (beta test) SKIP
ok   2 mce_check
exit: pass
```

The OpenDCDiag framework knows that our test requires Intel AVX-512 and it also knows that the
machine it is being run on doesn't support this feature, so it skips the test.
If it ran the test, the test would crash.

### Minimum CPU

How does the OpenDCDiag framework know our test requires Intel AVX-512? It knows
because we advertised this fact the in the DECLARE_TEST macro.

```c
        .minimum_cpu = cpu_skylake_avx512,
```

minimum_cpu is a bit mask of features. The values are defined in cpu_features.h
file. This file is generated at build time and can be found in your meson build
folder.

### Memory allocation and cleanup

Our new test, vector_add, allocates memory dynamically in both its *test_init*
and *test_run* functions using the C standard library functions *malloc* and
*aligned_alloc*. The latter requires the allocation size to be a multiple of the
requested alignment; VECTOR_ADD_BUF_SIZE is 4096 bytes, a multiple of 64. The
framework also provides *aligned_alloc_safe*, which calls *aligned_alloc* but
before it does so, it ensures that the size of the memory being allocated is a
multiple of the requested alignment, a requirement of *aligned_alloc*. If it is
not, the size of the requested memory is increased so that the constraints of
*aligned_alloc* are met. Note that the test does not check the return value of
any of the memory allocation functions. The reason for this is that the
OpenDCDiag framework actually overrides the standard C library and Posix memory
allocation functions, so that any allocation failure results in the calling
thread exiting. The overridden functions also fill the allocated memory with
zeros before returning, so newly allocated buffers do not need an explicit
memset to initialize them to zero.

The *test_init* function allocates three buffers. These buffers are 64-byte
aligned as required by the *prv_do_add* function that actually performs the
addition. The first two buffers are filled with random data using the framework
function *memset_random* and the third buffer is initialized by calling
*prv_do_add*. Pointers to all three buffers are stored in a dynamically
allocated structure and a pointer to this structure is stored in the *data*
field of the test object. Data needed by a test for a single invocation can be
allocated dynamically, as in this example, and stored in the *test->data* field where
it can be retrieved in the *test_run* or *test_cleanup* functions.

**Use of the *test->data* field is the recommended way of managing test-specific
data whose lifetime matches that of the test, i.e., data that needs to be
available in both the *test_init* and *test_run* functions. It provides a
better alternative to using global statics as was done in the first example.
Global statics can cause problems with tests written in C++ as we have seen. In
addition, as all the OpenDCDiag tests are built into one executable, the costs of
global static data introduced by one test are borne by all tests and the main
OpenDCDiag process itself, even if the test that created the global static data
is never actually run.**

The optional test_cleanup() function runs on the coordinating main thread after
workers join and submitted outputs are verified, including when workers fail
cleanly. It does not run if test_init() fails or skips, and a crash or hang may
prevent it from running. In normal fork and exec modes, each execution slice
runs in its own child process. The OS reclaims that process's private heap when
it exits, including allocations the test did not free. Without process
isolation, allocations can persist unless freed: this applies to
-fno-fork/--fork-mode=no, described in [Debugging tests](#debugging-tests), and
tests run in the parent process.

### memcmp_or_fail

Our vector_add example compares each worker's result to the golden result
computed in test_init(). The framework's convenience function memcmp_or_fail
performs this comparison. It accepts at least three
parameters in the following order; the newly computed data, the expected data,
and the number of elements to compare. The interesting thing about
memcmp_or_fail is that it is type aware even when called from C code. So the
third parameter needs to be set to the number of elements and not the number of
bytes. For arrays of 32-bit unsigned integers, pass the number of integers in
those arrays as the third argument. memcmp_or_fail then compares the elements in
the actual and expected arrays and fails the test with detailed log information
if there is a data mismatch. If memcmp_or_fail detects a mismatch, it stops the
normal execution of the current thread. In vector_add this bypasses the free of
*res*, but as the
isolated child process exits, the OS reclaims its private heap. This relies on
process isolation: in no-fork mode or parent-process tests, unfreed allocations
can persist, as described in [Memory allocation and cleanup](#memory-allocation-and-cleanup).


If your test contains multiple calls to *memcmp_or_fail* that compare the same
types of data, it can be difficult to determine which call actually failed by
looking at the logs. In such cases, the test writer is expected to
provide one or more additional parameters to describe the data. The first is a
printf like format string and any subsequent parameters provide the data for
that format string. Here's an example from the zstd test.

```c
    memcmp_or_fail(back_buf, buf, bufsz, "decompressed data");
```

### Logging

By default, OpenDCDiag creates a log file and writes to that log file as it
executes the tests. Information about the results of the tests plus any
additional information the tests log is output to the log file. If the
entire test run succeeds without error, OpenDCDiag deletes the log file.  If
you'd like to preserve the logfile you can use the -o parameter to provide an
explicit log file name. OpenDCDiag will not remove log files specified with the
-o parameter, even when there is no error. It is also possible to get
OpenDCDiag to log to standard output with '-o -'.  This is useful when debugging.

At this stage, it's instructive to look at what an OpenDCDiag test looks like
when it fails. Let's modify our *test_run* function to induce a failure by
adding the following two lines:

```c
         TEST_LOOP(test, 1 << 13) {
                 memset(res, 0, VECTOR_ADD_BUF_SIZE);
                 prv_do_add(va->a, va->b, res);
+                if (cpu == 0)
+                        res[10] = 0xffffffff;
```

These two lines corrupt the computed result in the first test thread. This
causes the call to memcmp_or_fail to fail and log an error. If you rebuild
and rerun OpenDCDiag, for example by typing:

```
./opendcdiag --beta -e vector_add -o -
```

you should see something like this on your screen:

```
[    0.400017] not ok   1 vector_add           # (beta test)
 ---
  info: {version: d5fd06013e97-dirty, timestamp: 2021-09-22T14:08:32Z}
  fail: { cpu-mask: '1......__.....__......__......:.......__.....__......__......', time-to-fail: 9.706, seed: 'LCG:1503975110'}
  Thread 0 on CPU 0 (pkg 0, core 0, thr 0, family/model/stepping 06-55-06, microcode 0x4003102, PPIN N/A):
  - failed: { time: 9.706, loop-count: 0 }
  - data-miscompare:
       description: ''
       type:        uint32_t
       offset:      [ 40, 0 ]
       address:     '0x7fab78000928'
       actual:      '0xffffffff'
       expected:    '0x1058c590'
       mask:        '0xefa73a6f'
       data(Bytes 0..63 of actual):
        5a 86 86 20  72 cf 38 5a  26 af c7 4f  67 2b 9a 1a   e0 72 cb 8a  5e 02 90 cd  fc 60 a8 16  e9 47 20 78
        c9 00 a6 6c  c1 4e 81 9e  ff ff ff ff  0b ad 73 21   46 15 7d 73  54 7f ea 44  71 c9 00 f1  c2 5f 19 1c
       data(Bytes 0..63 of expected):
        5a 86 86 20  72 cf 38 5a  26 af c7 4f  67 2b 9a 1a   e0 72 cb 8a  5e 02 90 cd  fc 60 a8 16  e9 47 20 78
        c9 00 a6 6c  c1 4e 81 9e  90 c5 58 10  0b ad 73 21   46 15 7d 73  54 7f ea 44  71 c9 00 f1  c2 5f 19 1c
```

You should also see that the test has been rerun by the framework and that it
consistently fails. When a test fails, OpenDCDiag reruns it to investigate
whether the failure is specific to a core or hardware thread. Here, we
deliberately induced a failure on the first hardware thread discovered.

In addition to the mismatch diagnostics, OpenDCDiag has some additional logging
functions that can be used. Among these functions are *log_skip*, *log_debug*,
*log_info*, *log_warning* and *log_error*. They all behave like printf and are
declared in [sandstone.h](../framework/sandstone.h). OpenDCDiag also provides an
additional function that is useful for logging binary data, *log_data*, also
declared and documented in [sandstone.h](../framework/sandstone.h).

There is one golden rule of logging in OpenDCDiag tests. Tests are only allowed
to log information on their error paths.  A test that completes successfully
should not write any additional information to the logs. It is appropriate to
use the log functions to log information on the non-error paths during a test's
development but these statements must be removed before the test is merged. The
one exception here are *log_debug* statements. These statements can be included
in the non-error paths of production tests, but they only generate output on
debug builds (they are compiled out of release builds).

By default, OpenDCDiag limits the amount of log statements that each test
invocation can make. By default this value is set to five.  If a test has already
issued five log statements, its sixth and subsequent log statements will be ignored
and will not appear in the logs. The framework also limits the amount of data
that can be logged with the *log_data* function, by default, to 128 bytes.  If
then, your logs are truncated, specify the --max-messages and
--max-logdata parameters when executing opendcdiag. Both these options take an
integer parameter. Setting this parameter to zero removes all limits.

One final note about logging. Any data written to standard output is
discarded. Adding a printf statement to a test has no effect. If you
want to see debug output in your logs, use the logging functions provided.
Information written to standard error will appear in the logs.  However,
test writers are expected to use the framework's logging functions rather than
writing to standard error directly.

## Named inputs and cross-checked outputs

The API in [crosscheck.h](../framework/crosscheck.h) is an alternative to managing
immutable input and reference buffers yourself. Existing explicit comparisons,
including the examples above, remain supported. API use enables capture without
a `.crosscheck` field or mode declaration.

Declare named, typed arrays with `CROSSCHECK_INPUT(name, type)` and
`CROSSCHECK_OUTPUT(name, type)`. These declarations establish names and element
types; they do not store test data or capture anything until set_input() or
submit_output() is called.

Tests **set inputs**, **get inputs**, and **submit outputs**. The framework
**captures snapshots** and verifies submitted outputs; capture describes its
ownership mechanism, not a separate public test operation.

| Test operation | Public API | Framework behavior |
| --- | --- | --- |
| Set inputs | `set_input()` | Copy the supplied elements into an owned immutable input snapshot |
| Get inputs | `get_input()` | Return a typed, read-only view of the input snapshot |
| Submit outputs | `submit_output()` | Capture the participant's first submission and check later submissions against it |

### C declarations and type inference

In C, `CROSSCHECK_INPUT(addends, uint32_t)` generates an element typedef and a
named view struct:

```c
typedef uint32_t crosscheck_input_type_addends;
struct CrossCheckInputView_addends {
    const uint32_t *const data;
    const size_t count;
};
```

The macro also checks that the element type is supported and generates typed
set/get helper functions. The public set_input() and get_input() macros select
those helpers for the declared name. get_input(addends) returns
`struct CrossCheckInputView_addends`; `.data` points to immutable captured
elements and `.count` is their element count. Both members are const, even when
the local struct itself is not declared const.

`CROSSCHECK_OUTPUT(sum, uint32_t)` generates the element typedef
`crosscheck_output_type_sum` and a typed submit helper. It does not generate a
view struct: output capture belongs to the framework and submit_output() returns
void. The typed set/submit macros reject incompatible element pointers at
compile time.

Use the GCC and Clang `__auto_type` extension to infer the generated input view
type instead of spelling its struct name:

```c
__auto_type input = get_input(addends);
uint32_t first = input.data[0];
size_t count = input.count;
```

The project uses GNU C17; `__auto_type` provides type inference without requiring
C23. An explicit `struct CrossCheckInputView_addends` declaration also works.
Do not modify captured elements or free the view's pointer.

### C++ declarations and type inference

In C++, the macros declare static constexpr instances of these key structs in
the SandstoneCrossCheck namespace:

```cpp
template <InputElement T> struct InputKey { const char *name; };
template <InputElement T> struct OutputKey { const char *name; };
```

For example, the declarations expand to:

```cpp
static constexpr SandstoneCrossCheck::InputKey<uint32_t> addends{"addends"};
static constexpr SandstoneCrossCheck::OutputKey<uint32_t> sum{"sum"};
```

These structs contain only the capture name, not input or output buffers.
The InputElement constraint checks the supported element type. get_input(addends)
returns `std::span<const uint32_t>`; use standard C++ `auto` for inference:

```cpp
const auto input = get_input(addends);
uint32_t first = input[0];
size_t count = input.size();
```

set_input() and submit_output() use typed overloads rather than C dispatch
macros. They accept pointer/count pairs or supported contiguous, sized ranges.

### A cross-checked test

For example, [crosschecked_add.c](../tests/examples/crosschecked_add.c) uses
framework-owned snapshots and a golden computation in init. The named tags
identify captures; unlike the legacy simple_add example, no static variable
stores inputs or reference data:

```c
#include "crosscheck.h"

CROSSCHECK_INPUT(addends, uint32_t);
CROSSCHECK_OUTPUT(sum, uint32_t);

static int crosschecked_add_init(struct test *test)
{
    uint32_t scratch[] = {random32(), random32()};
    set_input(addends, scratch, 2, "Addends");
    __auto_type input = get_input(addends);
    uint32_t result = input.data[0] + input.data[1];
    submit_output(sum, &result, 1, "Golden sum computed in init");
    return EXIT_SUCCESS;
}

static int crosschecked_add_run(struct test *test, int cpu)
{
    __auto_type input = get_input(addends);
    TEST_LOOP(test, 1 << 20) {
        uint32_t result = input.data[0] + input.data[1];
        submit_output(sum, &result, 1, "Worker sum");
    }
    return EXIT_SUCCESS;
}

DECLARE_TEST(crosschecked_add, "Cross-check repeated integer additions")
    .test_init = crosschecked_add_init,
    .test_run = crosschecked_add_run,
    .quality_level = TEST_QUALITY_BETA,
END_DECLARE_TEST
```

Both **golden** and **consensus** patterns are supported. Golden submits an init
computation alongside worker computations; consensus omits init's output
submission and compares workers only. Init has one ordinary vote for each name
it submits, not an authoritative reference. It may submit only some names.

### Worker-only consensus

The same source file also includes consensus_add, which shares the input/output
declarations and crosschecked_add_run() above but uses an init function that only
sets inputs:

```c
static int consensus_add_init(struct test *test)
{
    uint32_t scratch[] = {random32(), random32()};
    set_input(addends, scratch, 2, "Addends");
    return EXIT_SUCCESS;
}

DECLARE_TEST(consensus_add, "Cross-check integer additions among workers")
    .test_init = consensus_add_init,
    .test_run = crosschecked_add_run,
    .quality_level = TEST_QUALITY_BETA,
END_DECLARE_TEST
```

Init still supplies framework-owned inputs, but does not submit a sum. Workers
compute from the same captured inputs and submit their sums as before. This
pattern needs at least two successful workers per output; a single worker has
no other participant to cross-check against and resource-skips after cleanup.

### Verification policy and its limits

Golden and consensus use the same verification algorithm. Here, **golden means
an additional computation submitted from init, not a trusted expected value**.
The framework can implicate an incorrect golden producer when workers agree,
but it can also implicate a correct golden producer when a strict majority of
workers agree on an incorrect result. Majority agreement establishes agreement,
not correctness. Tests needing authoritative expected-data checks can still use
explicit comparisons such as memcmp_or_fail, as in the earlier examples.

Each output name denotes one invariant array per execution slice and pass.
The framework captures each participant's first submission; later submissions
must match that snapshot immediately. Repeated submissions never add votes.
After joining, verification compares successful participants separately for each
name. A strict majority (more than half) implicates outlying producers. Without
a strict majority, every conflicting producer has a failed data comparison and
is implicated; none is labeled correct. Majority agreement cannot detect values
that are wrong in the same way on all participants. Votes count computations,
not distinct hardware threads: init and a worker can execute on the same CPU.

For these examples, **T (true)** means the correct output and **F (false)** means
the same incorrect output wherever F appears. These are illustrative correctness
labels, not Boolean values submitted through the API. The framework does not
know which output is correct; it compares the submitted arrays. All submissions
have the same element type and count, and all participants complete successfully:

| Init submission | Worker submissions | Post-join outcome |
| --- | --- | --- |
| T | T, T | Agreement; no comparison failure |
| F | T, T | Init's producing logical processor is implicated |
| T | F, F | Init's producing logical processor is still implicated; the majority is not proof of correctness |
| None | T, T, F | The F worker's producing logical processor is implicated |
| None | T, F | Processors producing T or F are implicated; neither array is established as correct |

Implicated processors are suspects based on failed data comparisons, not proof
that each processor is defective. Repeating a submission checks invariance but
does not strengthen its participant's vote.

Skipped and failed workers do not vote, even if they submitted before exiting.
Their original diagnostics and already-recorded failures remain intact. Init
failure or skip stops execution before workers and cleanup, as usual. If all
workers skip, init alone cannot make the test pass. Fewer than two successful
participants for any output causes an insufficient-resource skip after cleanup,
unless a failure already exists. A later-submission mismatch can still fail a
single-participant execution.

Every successful worker must submit all names discovered from successful workers
or init. Missing submissions and incompatible types/counts are contract errors,
not values to vote on or CPU-attributed data mismatches. These post-join contract
errors follow cleanup and report OperatingSystemError/EXIT_INVALID; `--ignore-os-errors`
may waive those errors, but cannot waive a data comparison failure. A failure on
another name takes precedence over contract errors and insufficient coverage.
Zero-length outputs are valid. Declarations alone do not register required names,
so a name omitted by everyone is undetectable. Input-only use is permitted.

Immediate API misuse is different from a post-join contract error. Calling an
API in the wrong phase, setting an input twice, looking up a missing input or
one with a different element type, passing a null data pointer with a nonzero
count or an overflowing extent, and changing the type/count of a participant's
later submission terminate execution as invalid. These paths do not guarantee
normal cleanup or callback unwinding. A later submission with matching type/count
but different data is a comparison failure instead, and implicates the logical
processor executing that failed comparison.

Set each input once in test_init(), and compute outputs from get_input() snapshots
rather than the original randomized scratch storage. Lookup is allowed in init
and run; submission is allowed in init and run; cleanup must not call these APIs.
Views and snapshots remain alive through cleanup, including post-join failure
and skip paths. State resets for each slice, retry, and fracture pass and is not
shared across processes. Source buffers remain test-owned and may be reused or
freed after set_input() or submit_output() returns. Counts are elements, not bytes. Captured storage
has element alignment, not arbitrary SIMD alignment; use unaligned loads when
needed. The API does not write capture files.

Element types must be unqualified, non-void, trivially copyable types recognized
by [sandstone_data.h](../framework/sandstone_data.h). C supports
SANDSTONE_SCALAR_TYPES, including uint32_t, float, and BFloat16. C++ also supports
TypeToDataType mappings such as Float32 and contiguous, sized containers.
Comparison preserves meaningful representation bytes, including NaN payloads
and signed zero, while ignoring trailing scalar padding such as x87 padding.
Supply meaningful output descriptions; each first submission owns its metadata.
Deferred worker callbacks run on the coordinator under the target worker identity,
not the worker's original TLS or physical execution context. Init does not run
worker failure callbacks. Deferred attribution records the logical processor at
the first submission, not the coordinator or the worker's later completion CPU.

## Additional information

### Test groups

OpenDCDiag allows test writers to assign their tests to one or
more groups. Tests in the same group share some characteristics. For
example, they may all focus on one part of a CPU's architecture or
they may all employ the same sort of testing techniques. The nice
thing about assigning a test to a group is that you can easily run or
exclude all the tests in a group using simple command line options.
OpenDCDiag currently defines a number of groups. These can be seen by
running the following command.

```
./opendcdiag --list-groups
@compression
@math
```

To view the tests that form part of each group, run the opendcdiag
command with the --list option. This lists all the tests and outputs
some information about the defined test groups.  Example
group information output by this option is presented below.

```
Groups:
@compression           "Tests that drive compression routines in various libraries"
  zstd_aaa
  zstd1
  zstd
  zstd19
  zfuzz
  zlib_aaa
  zlib1
  zlib
@math                  "Tests that perform math using, e.g., Eigen"
  eigen_gemm_double14
  eigen_gemm_cdouble_dynamic_square
  eigen_gemm_double_dynamic_square
  eigen_gemm_float_dynamic_square
  eigen_svd_cdouble_noavx512
  eigen_sparse
  eigen_svd
  eigen_svd_double
  eigen_svd_double2
  eigen_svd_fvectors
  eigen_svd_cdouble
```

It's possible to run all the tests in a specific group with a simple
command line invocation. This invocation uses the -e option which we
have already seen, but rather than specifying a test name, we specify a
group name. For example we can run all the compression tests as follows:

```
./opendcdiag -v -e @compression --output-format=tap
# opendcdiag -v -e @compression --output-format=tap
# Operating system: Linux 5.14.2-arch1-2
# Random generator state: LCG:345873330
ok   1 zstd_aaa
ok   2 zstd1
ok   3 zstd1
ok   4 zstd
ok   5 zstd19
ok   6 zstd19
ok   7 zfuzz
ok   8 zlib_aaa
ok   9 zlib1
ok  10 zlib1
ok  11 zlib
ok  12 zlib
ok  13 zlib
ok  14 mce_check
exit: pass
```

We can run all the tests except for the compression tests by using
--disable @compression.

Adding a test to an existing group is easy. We need to fill in
the *groups* field of the *test* structure using the
*DECLARE_TEST_GROUPS* macro. For example, let's suppose we wanted to
add our first test to the math group. We would add the
following line to our test declaration

```c
 DECLARE_TEST(simple_add, "Repeatedly add two integer numbers")
+        .groups = DECLARE_TEST_GROUPS(&group_math),
```

If we rebuild and run OpenDCDiag once more with the --beta and --list
option, we should see that simple_add has been added to the math
group.

Tests can be members of multiple groups. The DECLARE_TEST_GROUPS
macro accepts a comma-separated list of group pointers. The groups
themselves are defined in
[sandstone_test_groups.h](../framework/sandstone_test_groups.h).
To add a new group, modify this file.

### Skipping tests

We've seen that the OpenDCDiag framework can automatically skip tests that make
use of instructions that are not supported on the test machine. To take
advantage of this facility, test writers need to fill in the *minimum_cpu*
field.  There may, however, be other reasons that a test cannot be run on a
given machine. For example, the test may make use of an OS feature that is not
present on all platforms or it may require root or administrator access to run.
The framework doesn't provide any support for detecting
these conditions so it is up to individual tests to 'self skip' if they detect
conditions that will prevent them from running. This is done by performing a test
in *test_init* function and then using *log_skip* to specify a category and message
for the skip and finally returning *EXIT_SKIP* if the test fails. Pre-defined set
of categories are defined using enum *SkipCategory* in sandstone.h file.
For example, suppose we write a test that will work fine on Linux\* but will not run
on Windows\*.  In this case we might write an *test_init* function that looks like
this:

```c
static int linux_only_init(struct test *test)
{
#ifdef _WIN32
        log_skip(OsNotSupportedSkipCategory, "The linux_only test is not supported on Windows");
        return EXIT_SKIP;
#endif
        return EXIT_SUCCESS;
}
```

Note that returning any negative value from the *test_init* function causes
the test to skip.  If the reason for the skip was due to the failure of a C
standard library function or system call, it can be useful to make the test skip
by returning *-errno*, rather than *EXIT_SKIP*.

All tests are expected to build and run on Linux and Windows.  OS-specific
tests are expected to perform a test similar to what is shown above in
their *test_init* functions. Tests that cannot be run on the host machine
should skip and exit cleanly. They should not fail and they should not crash.
A log statement may be issued to explain the reason for skipping the test.

### Test tuning

It is not always obvious what value to pass for the second parameter
to TEST_LOOP. The value needs to be small enough so that the
framework can fracture the test a number of times and large enough to
ensure that the costs of setting up and tearing down the test, e.g.,
process creation, the execution of test_init, etc., are a very small
proportion of the runtime of the overall test. Ideally, we want our
test to spend as much of its allocated time slot as possible in its
test_run function, while accepting that we probably need to fracture it
to improve its effectiveness.

The framework includes a command line option, --test-tests, to help
select an appropriate value for the second parameter of TEST_LOOP.
This option is only available in debug builds and should only be used
in optimized debug builds. To create an optimized debug build pass
the -Dbuildtype=debugoptimized option to the meson command, e.g.:

```
meson builddir -Dbuildtype=debugoptimized
```

Run the functionally complete test with this option enabled. The following
historical excerpts illustrate the tuning workflow; measure timings and tune
loop counts for your test on the target hardware.

```
./opendcdiag --beta -v -e simple_add --output-format=tap --test-tests
# opendcdiag --beta -v -e simple_add --output-format=tap --test-tests
# Operating system: Linux 5.14.2-arch1-2
# Random generator state: AES:0a79e69180729ce1a9069ee561104850f586196e7f8d631e56f9611a9eefb7af
ok   1 simple_add               # (beta test)
ok   2 mce_check
exit: pass
```

Reducing the second parameter to TEST_LOOP from 1<<20 to 1<<10, rebuilding, and
re-running with --test-tests can expose excessive loop-check overhead. For
example, the historical version reported:

```
tests:
- test: simple_add
  result: fail
  fail: { cpu-mask: null, time-to-fail: null, seed: 'LCG:704221692'}
  time-at-end:   { elapsed:   1000.037, now: !!timestamp '2021-09-29T11:08:54Z' }
  test-runtime: 1001.553
  threads:
  - thread: main
    messages:
    - { level: error, text: 'E> Inner loop is too short (average 0.001 ms) -- suggest making the test 5431x longer' }
# Test failed 1 out of 1 times (100.0%)
```

The loop granularity was reduced by 1024, but the historical diagnostic suggested
an increase of 5431: the original value was manually chosen, and --test-tests
allows considerable tolerance. Measure the current workload on your target
machine rather than reusing those numbers. Use --test-tests to tune tests once
they are functionally complete; tests that disable fracturing do not need this
tuning.


### CPU info

Sometimes tests need access to information about the cores, threads and packages
on which they run. The OpenDCDiag makes this information available via its
API.

#### num_cpus

It provides a function called *num_cpus* which returns the number of
hardware threads the current invocation of the test will be run on. Normally,
this is equal to the number of hardware threads in the machine under test, but
this is not always the case; if for example, the test uses slicing (see below),
the user specified the --cpuset parameter when executing opendcdiag, or the OS
restricts the number of threads that are visible to OpenDCDiag in some way. The
*num_cpus* function can be called in the *test_init*, *test_run* and
*test_cleanup* functions.

#### device_info and cpu

The *test_run* function's second parameter, *cpu*, has not been been discussed
in much detail until now. This parameter is an OpenDCDiag specific identifier
that identifies the hardware thread on which the current instance of the
*test_run* function is executing. It will always be greater than or equal to zero
and less than the value returned by *num_cpus*. It can be used as an index into
a global array maintained by the framework called *device_info*. This is an array
of structures, also called *device_info* that contain information about the
hardware threads on which the test is being run. The *device_info* structure is
documented in [sandstone.h](../framework/sandstone.h). It can be used for
example to figure out which core the current thread is associated with, how much
cache that core has, in which socket the current core is located, and what
version microcode the thread is running.

### Slicing

Tests normally run test_run() on workers pinned to the selected hardware
threads. Some tests need to limit the number of workers sharing resources in one
process, for example when test_run() allocates a large buffer for each worker.
The framework supports this through slicing. The test's scheduling flags select
a slice plan; by default, the framework chooses a plan heuristically. For
example, setting *flags* to test_schedule_isolate_socket in DECLARE_TEST selects
one slice per socket. These flags are documented in
[sandstone.h](../framework/sandstone.h). Separate slices can run concurrently,
so slicing does not impose a global limit on worker count or memory use.

In normal fork and exec modes, the framework runs a sliced test as follows:

1. It divides the selected hardware threads into slices according to the
selected plan.
2. It creates a separate child process for each slice. Within that process,
num_cpus() and *device_info* describe only the current slice.
3. Each child calls test_init() if supplied, then starts its pinned workers and
calls test_run() on each worker.
4. Each child joins its workers and verifies submitted outputs within that slice
using successful worker submissions and any init submissions as ordinary participants.
5. Each child calls test_cleanup() if supplied and exits. As in
[Test execution](#test-execution), failed or skipped initialization returns early,
and a crash or hang may prevent verification or cleanup.
6. The parent collects the child results and reports the aggregate outcome.

Slicing does not repeatedly call test_init() in the same child process.
The no-fork debugging mode supports only a single slice. Captured inputs, golden
outputs, and saved first submissions belong to one execution slice of one
invocation, including retries and fracture passes. They are not shared between
processes or reused across passes. The examples free their test-owned scratch
and result buffers locally and therefore need no test_cleanup() callback.
Test-owned resources kept in *test->data* can be released in test_cleanup(), as
described above.

### Debugging tests

Each OpenDCDiag test is run in its own separate process as we have seen. This
can make debugging of tests with a debugger a little tricky. For this
reason, OpenDCDiag contains a development option, --fork-mode. Setting the
value of this option to "no" forces OpenDCDiag to run tests in its own process.

Another aspect of the way the OpenDCDiag frameworks works that can complicate
debugging is the way that it runs the *test_run* function multiple times in
parallel on different threads. If you need to debug and step through the
*test_run* function, it's probably easiest to limit OpenDCDiag to a single thread.
This can be achieved using the -n option. Thus a typical command line for
debugging a test might be.

```console
gdb --args ./opendcdiag --beta -e simple_add --fork-mode=no -n1
```

For vector_add, retain at least two workers in the slice (-n2 or more) and use an
AVX-512-capable machine; consensus skips a one-worker slice.

The framework also provides support for debugging hung tests. By default the
framework will kill tests that have not responded after 5 minutes. You'll
probably see something like this in your logs when a test hangs

```
# opendcdiag --beta -v -e simple_add --output-format=tap
# Operating system: Linux 5.8.0-63-generic
# Random generator state: LCG:1315282236
not ok   1 simple_add           # (beta test) timed out
 ---
  info: {version: f09c9ae329da-dirty, timestamp: 2021-09-24T12:52:16Z, virtualized: true}
  fail: { cpu-mask: 'X:X:X:X:X:X:X:X', time-to-fail: null, seed: 'LCG:1315282236'}
  Main thread:
   - 'E> Child 18834 did not exit, sending signal SIGQUIT'
  Thread 0 on CPU 0 (pkg 0, core 0, thr 0, family/model/stepping 06-55-04, microcode 0x1, PPIN N/A):
   - 'E> Thread is stuck'
```

The default behavior can be overridden via the --on-hang development option.
The option --on-hang=gdb can be used automatically launch gdb to debug the hung
test. This option may require administrator privileges to work.

### API reference

OpenDCDiag's test APIs are declared in [sandstone.h](../framework/sandstone.h)
and [crosscheck.h](../framework/crosscheck.h). Consult these headers for
documentation of functions, structures, and cross-check requirements not covered in
this guide.
