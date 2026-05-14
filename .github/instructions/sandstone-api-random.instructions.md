---
applyTo: "**"
---
# sandstone.h — Random, Utilities and Helpers

## Integer random

```c
uint32_t    random32();    // uniform random 32-bit unsigned integer
uint64_t    random64();    // uniform random 64-bit unsigned integer
__uint128_t random128();   // uniform random 128-bit unsigned integer
```

## Buffer fill

```c
void *memset_random(void *dest, size_t n);  // fills n bytes at dest with random values; returns dest
```

## Floating-point random

```c
// Positive value between 0.0 and 1.0
float       frandomf();
double      frandom();
long double frandoml();

// Positive value between 0.0 and scale
float       frandomf_scale(float scale);
double      frandom_scale(double scale);
long double frandoml_scale(long double scale);
```

All floating-point random functions return positive values only.

## Bit-pattern random

```c
uint64_t set_random_bits(unsigned num_bits_to_set, uint32_t bitwidth);
```

Returns a `uint64_t` in which exactly `num_bits_to_set` bits are randomly set
within the lowest `bitwidth` bits; all higher bits are zero.
Example: `set_random_bits(2, 8)` returns a value with exactly 2 of the 8 LSBs set.

## Aligned allocation

```c
void *aligned_alloc_safe(size_t alignment, size_t size);
```

Wrapper around `aligned_alloc` that rounds `size` up to the nearest multiple of
`alignment` before calling, satisfying `aligned_alloc`'s precondition that size
must be a multiple of alignment. Enforces `alignment >= sizeof(void*)`.

## Alignment check

```c
IS_ALIGNED(ptr, alignment)   // expands to 1 if ptr is aligned; alignment must be a power of 2
```

Implemented as a bitmask check on the pointer cast to `uint64_t`.

## Bitmask

```c
MASK(bits)   // bitmask with the lowest `bits` bits set; handles bits == 64 correctly
```

## Suppress unused-variable warnings

```c
IGNORE_RETVAL(call)           // discards the return value of call; suppresses nodiscard warnings
UNUSED_ARGS(a, b, ...)        // casts up to 20 arguments to void; suppresses unused-parameter warnings
```

Use `IGNORE_RETVAL` instead of a bare cast to `void` when the intent needs to be
explicit. Use `UNUSED_ARGS` in function bodies instead of `(void)param` chains.
