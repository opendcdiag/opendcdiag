# OpenDCDiag Coding Style Guidelines

## General Guidelines

* Software should be written in **C++ 20** or **C17** and compile using **GCC-10**.
* All software must be written for cross-platform execution on both **Linux** and **Microsoft Windows**.   Use the `_WIN32` and `__linux__` macros provided.
* All code must compile and link without warnings.
* All software must conform to the licensing requirements for OpenDCDiag as provided in the LICENSE file.
* If a patch changes existing files, try to minimize the lines changed as much as possible and please preserve the existing formatting and style.

## Coding Guidelines and Naming Convention

* C++ header and source files should have _*.hpp_ and _*.cpp_ extensions.
* C header and source files should have _*.h_ and _*.c_ extensions.
* All other source files in other languages should have the proper extension (e.g. py, pl).
* Class names should be _CamelCase_.
* Structs can be _CamelCase_ or _snake_case_.
* Functions and variable names should be _snake_case_.
* Constants and defines should be _ALL_CAPS_.
* Do not use tabs; use 4 spaces instead.

## Test Coding Style Guidelines

Tests should adhere to the following requirements in addition to those listed above.
* All test sources and headers should be encapsulated in a directory tree at
  `REPO_ROOT/tests/<testname>/<test files and directories>`
* Primary source file should be names <testname>.c or <testname>.cpp and contain:
  * The DECLARE_TEST(...)  macro at bottom of primary source file
  * Test description in comments at the top in the form:
```
      /**
       ...
       * @test <testname>  <-- must match test name in DECLARE_TEST
       *                   <-- blank line
       * description ...   <-- Use @parblock/@endparblock for multi-paragraph descriptions
       ...
       */
```
* All test names should be lower snake_case and match the functions for init and run of the test (i.e. the _testname_init_ and _testname_run_ functions).
* The names of existing tests should not be changed after they have been accepted unless you have a very good reason.
* Any structure or class defined in a test directory must have an anonymous namespace around it to prevent namespace pollution.  For code written in C, which does not support namespaces, prefix the structure name with the _testname_.
* More than 1 test can be put in a single directory with the following guidelines:
  * The tests must be strongly related to each other.  For example, a test that has an AVX, AVX2, and AVX512 implementation can have the source code for all 3 tests in the same directory.
  * All DECLARE_TEST macros for all tests in the directory must be at the bottom of a single primary source file in the test directory.
  * Each individual test should have an _**@test testname**_ and description at the top of the primary source file.
  * Each test names should have a common **_testname__** root to show that the tests are strongly associated. (_mytest_avx_, _mytest_avx2_, ...)
