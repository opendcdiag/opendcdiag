Count how many rules this file contains, put this number in the context,
and at the end, use this count to make sure no checks were missed. List this
number when reporting out.

### General Coding style rules

- [ ]  **C++23** (`-std=gnu++23`) and **C17** (`-std=gnu17`); GCC and clang
  are both required.
- [ ]  **4 spaces** indentation, **no tabs** anywhere in C/C++ (enforced by `.editorconfig`)
- [ ] **`CamelCase`** for classes and structs; **`snake_case`** for functions and variables; **`ALL_CAPS`** for constants/macros
- [ ] C++ headers: `*.hpp`; C headers: `*.h`
- [ ]  **Anonymous namespaces** required around all test-internal structs/classes in C++.
- [ ] Use a `testname_` prefix in C around all test-internal structs and functions
- [ ] All code must compile **without warnings** (`-Wall -Wextra` are enabled; `-Werror=format-security` is
    enforced, and `-Wno-unused-parameter` is used). 
    When doing code review, editing or creating new code, do a test build of the code
    to check for warnings.
- [ ] All code must be cross-platform (Linux + Windows); use `_WIN32` / `__linux__` macros.
    (Prefer using `#ifndef _WIN32` to detect non-Windows)
    Our framework provides a mmap() wrapper for Windows that internally uses VirtualAlloc
    and we use MinGW & winpthreads to provide more POSIX/Unix-like functionality on Windows.
- [ ] No trailing spaces at the end of a line
- [ ] All files must end with exactly one empty line
- [ ] Use American English spelling (e.g. `initialize`, `randomize`, `maximize` -- not `-ise` variants)
- [ ] Single spacing after periods -- no French spacing (double spaces after sentence-ending punctuation)
- [ ] The free() function takes NULL as a valid argument, checking for non-NULL just to call free() is a violation of coding style.
    Example of the bad case:   if (foo) free(foo);
- [ ] Avoid `long` and `unsigned long`, except where required by POSIX API.
    They are not allowed in cross-platform code, but are allowed in code clearly
    marked for use in Unix only (e.g., referring to a register-sized type).
- [ ] Use proper `<inttypes.h>` format specifiers for `<stdint.h>` types like `uint64_t`
    in `printf`-style functions (such as `log_error` and `memcmp_or_fail`). This is
    required for 64-bit types such as `uint64_t`, `int64_t`, but only recommended
    for smaller types. Alternatively, code may cast to `size_t`, `ptrdiff_t`,
    `long long`, or `unsigned long long` and use `"%zu"`, `"%td"`, `"%lld"`, and `"%llu"`
    respectively.
