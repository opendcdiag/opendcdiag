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
 * simple_add repeatedly adds the same two random numbers on each worker
 * and checks each sum against the captured golden output.
 * @endparblock
 */

#include "sandstone.h"
#include "crosscheck.h"

#include <stdint.h>
#include <stdlib.h>

DECLARE_CROSS_CHECK_INPUT(simple_add_values, uint32_t);
DECLARE_CROSS_CHECK_OUTPUT(simple_add_sum, uint32_t);

static int simple_add_init(struct test *test)
{
    uint32_t values[] = { random32(), random32() };
    capture_input(simple_add_values, values, 2, "Addends");
    const struct CrossCheckInputView_simple_add_values input = get_input(simple_add_values);
    uint32_t sum = input.data[0] + input.data[1];
    capture_output(simple_add_sum, &sum, 1, "Sum of two unsigned integers");

    return EXIT_SUCCESS;
}

static int simple_add_run(struct test *test, int cpu)
{
    const struct CrossCheckInputView_simple_add_values input = get_input(simple_add_values);

    TEST_LOOP(test, 1 << 20) {
        uint32_t sum = input.data[0] + input.data[1];
        capture_output(simple_add_sum, &sum, 1, "Sum of two unsigned integers");
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
followed by named input and output declarations, two static functions, and a declarative
section that registers the test with the OpenDCDiag framework.

The named capture API in [crosscheck.h](../framework/crosscheck.h) lets tests
share immutable inputs and verify invariant outputs without managing shared
reference buffers.

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
5. It joins the workers, checks successful workers' first submissions against
golden outputs, then verifies any consensus outputs.
6. It calls test_cleanup() if supplied, then reports the test's outcome,
including verification and cleanup results.
7. It may re-execute the test in a new process if time permits, as we have seen.

A failed or skipped test_init() returns before workers or test_cleanup() run.
A crash or hang can also prevent verification and cleanup from completing.
Tests that use [slicing](#slicing) follow this lifecycle separately in each slice.

To put this in the context of our simple_add test, the framework creates a new
process and calls our simple_add_init function on the main thread of this
process. Our init function generates two random integers and captures a copy
under the simple_add_values input name. It retrieves that immutable snapshot
with get_input, computes the sum from the snapshot, and captures the golden
output under the simple_add_sum output name. Our init function returns
EXIT_SUCCESS to indicate that all is well and that the test can proceed. The
framework creates and pins the workers, then invokes test_run() on each worker.
Our simple_add_run function retrieves the same captured input before the loop,
sums its two numbers, and submits the result with capture_output on every
iteration. The framework checks later submissions against each worker's first
submission. After joining the workers, it checks their first submissions against
the golden output. Our computation and submission are executed repeatedly in a
loop, generated by the TEST_LOOP macro.
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
problems. It does, however, illustrate one common verification pattern.
It computes a golden output in test_init(), then recomputes that output in
test_run() on multiple workers. The submitted outputs are checked for invariance
and against the golden output. A data mismatch is a test failure; an unexpected
test or environment problem is a test error and requires investigation. A passing
run only means that no defect was detected under the exercised conditions.

### Named input and output capture

DECLARE_CROSS_CHECK_INPUT and DECLARE_CROSS_CHECK_OUTPUT bind each name to a
supported element type without const or volatile qualifiers. C supports the
scalar types listed in SANDSTONE_SCALAR_TYPES in
[sandstone_data.h](../framework/sandstone_data.h), such as uint32_t, float, and
BFloat16. C++ also supports its TypeToDataType mappings, such as Float32; element
types must be non-void and trivially copyable.

In C, get_input returns a named, typed view with a `const T *data` and an element
`count`. Do not modify the captured storage or free its pointer. The framework
owns the copied inputs, any captured golden outputs, and a snapshot of each
worker's first submission. Capture does not write inputs or outputs to files.
The source buffers remain test-owned and may be reused or freed after capture
returns; stack variables are also valid capture sources.

Capture each input name once, in test_init() only, and compute worker outputs and
any golden outputs from get_input snapshots, not from the original randomized
scratch storage. Lookup is allowed in test_init() and test_run() only. Views
remain valid through test_cleanup(), but that callback must not perform another
lookup or capture. Storage has the alignment needed for its element type, not an
arbitrary SIMD alignment.
Counts passed to capture_input and capture_output are counts of elements, not
bytes; the scalar sum has count 1 and its input has count 2.

Each output name denotes one invariant array per execution slice, not a stream
of changing values. In the golden output mode used by simple_add, capture its
golden output once in test_init(). Every worker that completes successfully must
submit every golden output name at least once, using the declared element type
and expected count. Later submissions for that name are checked immediately
against that worker's first submission. After all workers finish and their
completion states are finalized, the framework checks each successful worker's
first submission against the golden output before calling test_cleanup(). This
is not consensus among workers: the golden output is the reference even if all
workers produce the same incorrect result.

Golden outputs are optional. In the consensus mode used by vector_add below,
there is no golden output capture in test_init(). After all workers in an
execution slice finish, the framework compares their first submissions against
logical worker 0's first submission in that slice, with no majority voting or
fallback to another reference worker. Every worker in the slice must submit
each consensus output name and complete successfully for consensus to pass.
An incomplete participating slice prevents an overall pass: the invocation is
skipped unless a failure or more serious outcome takes precedence. Later
submissions must still match each worker's own first submission. With only one
worker in a slice, this checks only invariance, not agreement with an independent
result.

All C capture calls require a description argument; supply meaningful text,
especially for outputs. In golden output mode, the golden output's name, type,
count, and description are authoritative diagnostic metadata; a worker's
description does not replace them. In consensus mode, logical worker 0's first
submission in each slice supplies the reference type, count, and description
for each output name. Captures are local to each execution slice of each
invocation, including retries and fracture passes. They are not shared between
processes or reused across passes, so invariance is required within a slice and
pass, not across them.


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
to do the addition using SIMD instructions. Unlike simple_add, which captures a
golden output in test_init(), this test uses worker consensus without a golden
output.
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
 * AVX-512 instructions, checking output invariance and agreement among workers.
 * @endparblock
 */

#include "sandstone.h"
#include "crosscheck.h"

#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define VECTOR_ADD_ELEMENTS (1u << 10)
#define VECTOR_ADD_BUF_SIZE (VECTOR_ADD_ELEMENTS * sizeof(uint32_t))

DECLARE_CROSS_CHECK_INPUT(vector_add_a, uint32_t);
DECLARE_CROSS_CHECK_INPUT(vector_add_b, uint32_t);
DECLARE_CROSS_CHECK_OUTPUT(vector_add_sum, uint32_t);

static void vector_add_do_add(const uint32_t *a, const uint32_t *b, uint32_t *res)
{
    for (size_t i = 0; i < VECTOR_ADD_ELEMENTS / 16; i++) {
        __m512i r1 = _mm512_loadu_epi32(&a[i*16]);
        __m512i r2 = _mm512_loadu_epi32(&b[i*16]);
        __m512i r3 = _mm512_add_epi32(r1, r2);
        _mm512_store_epi32(&res[i*16], r3);
    }
}

static int vector_add_init(struct test *test)
{
    uint32_t *scratch = malloc(VECTOR_ADD_BUF_SIZE);

    memset_random(scratch, VECTOR_ADD_BUF_SIZE);
    capture_input(vector_add_a, scratch, VECTOR_ADD_ELEMENTS, "First array of addends");
    memset_random(scratch, VECTOR_ADD_BUF_SIZE);
    capture_input(vector_add_b, scratch, VECTOR_ADD_ELEMENTS, "Second array of addends");
    free(scratch);

    return EXIT_SUCCESS;
}

static int vector_add_run(struct test *test, int cpu)
{
    const struct CrossCheckInputView_vector_add_a a = get_input(vector_add_a);
    const struct CrossCheckInputView_vector_add_b b = get_input(vector_add_b);
    uint32_t *res = aligned_alloc(64, VECTOR_ADD_BUF_SIZE);

    TEST_LOOP(test, 1 << 13) {
        memset(res, 0, VECTOR_ADD_BUF_SIZE);
        vector_add_do_add(a.data, b.data, res);
        capture_output(vector_add_sum, res, VECTOR_ADD_ELEMENTS, "Element-wise unsigned sums");
    }

    free(res);

    return EXIT_SUCCESS;
}

DECLARE_TEST(vector_add, "Repeatedly add arrays of unsigned integers using AVX-512 instructions")
    .test_init = vector_add_init,
    .test_run = vector_add_run,
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

This output was generated on a machine that supports Intel AVX-512 and so our test ran
and passed.  When run on a machine that does not support Intel AVX-512 you should see
something like this.

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

The test_init() function allocates one scratch buffer. It fills it with random
data, captures the first input array, then reuses the scratch buffer for the
second input array. Since capture_input copies the elements, reusing and freeing
the scratch buffer does not change either captured input. test_init() frees the
scratch buffer locally and does not compute or capture a golden output. Each
worker retrieves both immutable input views and submits its sums under
vector_add_sum.
Repeated submissions must match that worker's first submission. After all workers
join, the framework checks their first submissions against worker 0's first
submission, as described in
[Named input and output capture](#named-input-and-output-capture).
Unlike simple_add's golden output check, consensus cannot detect a result that is
consistently wrong in the same way on every worker.

Captured uint32_t arrays guarantee uint32_t alignment, not 64-byte alignment.
The *vector_add_do_add* helper therefore uses unaligned AVX-512 input loads. Its
output stores remain aligned because each worker allocates its result buffer
with 64-byte alignment. Although the helper should write every result element,
each iteration clears the reused result buffer first:
an omitted store could otherwise leave a correct result from the prior iteration
and go undetected. Both input views are retrieved outside TEST_LOOP; the loop
clears the result buffer, computes the sums, and submits the result.
The framework manages captured storage, so neither example needs a
test_cleanup() callback. Each worker frees its own result buffer before
returning successfully.

For resources that cannot be represented as immutable scalar captures, or for
tests that manage their own reference data, *test->data* remains a useful
alternative to global statics. Allocate the resources in test_init(), store
their pointer in *test->data*, retrieve it in test_run(), and release the
resources in test_cleanup(). Global statics can cause problems with C++ tests as
described above. Also, their storage costs are borne by the main process and all
tests even when the test that defines them never runs.

The optional test_cleanup() function runs on the coordinating main thread after
workers join and captured outputs are verified, including when workers fail
cleanly. It does not run if test_init() fails or skips, and a crash or hang may
prevent it from running. In normal fork and exec modes, each execution slice
runs in its own child process. The OS reclaims that process's private heap when
it exits, including allocations the test did not free. Without process
isolation, allocations can persist unless freed: this applies to
-fno-fork/--fork-mode=no, described in [Debugging tests](#debugging-tests), and
tests run in the parent process.

### memcmp_or_fail

Our vector_add example submits invariant outputs through capture_output. Tests
that own their expected data or need explicit comparisons can instead use the
framework's convenience function memcmp_or_fail. It accepts at least three
parameters in the following order; the newly computed data, the expected data,
and the number of elements to compare. The interesting thing about
memcmp_or_fail is that it is type aware even when called from C code. So the
third parameter needs to be set to the number of elements and not the number of
bytes. For arrays of 32-bit unsigned integers, pass the number of integers in
those arrays as the third argument. memcmp_or_fail then compares the elements in
the actual and expected arrays and fails the test with detailed log information
if there is a data mismatch. If memcmp_or_fail detects a mismatch, it stops the
normal execution of the current thread. A capture_output invariance mismatch
also stops the worker. In vector_add this bypasses the free of *res*, but as the
test has failed, its process is terminated and the memory is reclaimed by the
OS. This sort of memory leak is acceptable in OpenDCDiag code.


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
when it fails. The following simple_add failure was deliberately induced with a
debugger by modifying one byte in the framework-owned snapshot of a worker's
first submission. It demonstrates the mismatch diagnostic, not a hardware
silent data error. Comments in the excerpt mark omitted fields:

```yaml
- test: simple_add
  details: { quality: beta, description: "Repeatedly add two integer numbers" }
  # ... state and start timing omitted ...
  result: fail
  # ... failure summary and timing omitted ...
  threads:
  - thread: 0
    # ... CPU identity omitted ...
    state: failed
    # ... timing, loop count, and frequency omitted ...
    messages:
    - level: error
      data-miscompare:
       description: 'Cross-check output ''simple_add_sum'' (Sum of two unsigned integers), later submission vs first submission'
       type:        uint32_t
       offset:      [ 0, 0 ]
       address:     '0x7ffff67fbc68'
       actual:      '0x9f28f4f8'
       expected:    '0x9f28f4f9'
       mask:        '0x00000001'
       details:
         Cross-check output 'simple_add_sum' (Sum of two unsigned integers), later submission vs first submission
       actual data:
        f8 f4 28 9f
       expected data:
        f9 f4 28 9f
```

The diagnostic identifies simple_add_sum and its description, the uint32_t
element type, the first mismatching byte at offset 0, and the XOR mask
0x00000001. The actual sum is 0x9f28f4f8; the expected value is the corrupted
saved first submission, 0x9f28f4f9. The comparison boundary is therefore labeled
"later submission vs first submission", not "first submission vs golden output".
Values and addresses will differ between runs.

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

Next, let's re-run our first test with this option enabled.

```
./opendcdiag --beta -v -e simple_add --output-format=tap --test-tests
# opendcdiag --beta -v -e simple_add --output-format=tap --test-tests
# Operating system: Linux 5.14.2-arch1-2
# Random generator state: AES:0a79e69180729ce1a9069ee561104850f586196e7f8d631e56f9611a9eefb7af
ok   1 simple_add               # (beta test)
ok   2 mce_check
exit: pass
```

With a bit of luck, our test should still pass. Now, for
the sake of demonstration, let's modify the second parameter to
TEST_LOOP from 1<<20 to 1<<10, rebuild our test, and re-run it with the
--test-tests option. The test should now fail with an error message.

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

We sped up our test loop by 1024 times and the OpenDCDiag framework is
informing us that it is now too fast. When run without the
--test-tests option, the test will still pass. Interestingly, the
framework is recommending that our sped-up test loop be slowed down by
5431x and not 1024x. The reason for this is that the initial value
for *simple_add* was manually chosen, i.e., not chosen by using
--test-tests, and that the chosen value was too small. Our original
test still passes when run with --test-tests, as --test-tests has a
high degree of tolerance. Nevertheless, the recommendation is for
test developers to use --test-tests to tune their tests once the tests
are functionally complete. Doing so improves the effectiveness of
their tests. Note the use of --test-tests for test tuning is not
needed for tests that disable fracturing.


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
4. Each child joins its workers, checks successful workers' first submissions
against golden outputs, then verifies consensus outputs within that slice.
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
gdb --args ./opendcdiag --beta -e vector_add --fork-mode=no -n1
```

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
documentation of functions, structures, and capture requirements not covered in
this guide.
