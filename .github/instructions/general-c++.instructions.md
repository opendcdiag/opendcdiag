---
applyTo: "**/*.cpp,**/*.hpp,**/*.h,**/*.c"
---

# C++ coding guidelines

These coding rules apply to all C++ code in the project.

# General correctness rules to verify as part of the review

- [ ] Check for, and report Undefined Behavior (UB) as per the relevant C++ standard
      (assume C++23 if no standard version is specified)


## Standard library items

- [ ] Ensure that when std::vector.reserve() is used, no accesses beyond the
  end of the actual size happen. reserve(), unlike resize(), only changes
  the vector's allocated capacity, but not the size() of the vector.

- [ ] Except for boundaries where code interfaces from or to C code, std::string usage
    is strongly recommended for string handling.

- [ ] Standard library containers (std::vector etc) and iterators are preferred over custom-coded solutions.

- [ ] Prefer std::string over C style "char *", except when interfacing with
    C class libraries or the Linux kernel

- [ ] Use "std::<element>" instead of "<element>" even when code uses
    "using namespace std".


## Language standard

- [ ] Use only constructs in the C++23 standard that are neither deprecated nor
    obsoleted.

- [ ] Undefined behavior (UB) language constructs are a violation of coding
    style

- [ ] Any use of fixed sized buffers (example: char foo[128]) must be
    **provably** correct to not overflow the buffer in any condition

- [ ] "using namespace std;" is a deprecated construct and should not be
    used


## General C++ coding rules

- [ ] Use the RAII pattern for containers whenever possible

- [ ] Follow industry best practices for C++ for any new code.
    Flag any existing code as a "nit" if not covered already by other review
    rules

- [ ] Code should not contain "invisible" unicode characters.
    Invisible unicode characters include
    - U+061C
    - U+200B
    - U+200E
    - U+200F
    - U+202A
    - U+202B
    - U+202C
    - U+202D
    - U+202E
    - U+2066
    - U+2067
    - U+2068
    - U+2069


- [ ] It is a low severity issue if variables or arguments are not declared const, when
    they could or should have been

- [ ] Comments should match the code. If they don't, git history is likely
    to provide hints if there is a bug, or if the comment got stale as code
    changed for valid purposes.

- [ ] Range based for loops are preferred whenever possible
