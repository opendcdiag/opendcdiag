---
applyTo: "**"
---
# sandstone.h — Threading and Platform Access

## Thread identity and topology

```c
/* GCC / non-LLVM: */
extern __thread int thread_num __attribute__((tls_model("initial-exec")));
/* Clang / LLVM: */
extern thread_local int thread_num;
```

`thread_num` is always equal to the `thread` parameter passed to `test_run`.
It may be used to index `test->per_thread[]`.

```c
int thread_count();    // number of HW threads assigned to the test
int device_count();    // number of devices (CPUs or GPUs); normally == thread_count()
int num_packages();    // number of physical CPU sockets
```

`thread_count()` may be lower than the total system thread count if `--cpuset` is
used, if the test sets `.max_threads`, or if the OS restricts visible CPUs.

`device_count()` is tracked separately from `thread_count()`; prefer `device_count()`
when iterating over devices, and `thread_count()` when iterating over threads.

## Verbosity

```c
int8_t sandstone_verbosity_level();  // current verbosity; 0 = normal
```

## Device features

```c
extern device_features_t device_features;  // features of the current device
```

## Device scheduler / reschedule

```c
void reschedule();
```

Yields the device scheduler slot. Call inside `test_run` when the test does not
need the CPU for a period (e.g., waiting on a memory operation). Safe to call
unconditionally; is a no-op when no `DeviceScheduler` is active.

## MSR access (Linux x86-64 only, requires root)

```c
bool read_msr(int cpu, uint32_t msr, uint64_t *value);
bool write_msr(int cpu, uint32_t msr, uint64_t value);
```

Both return `false` on non-Linux or non-x86-64 platforms (inline stubs that do nothing).
On Linux x86-64, return `false` if the MSR cannot be accessed (e.g., insufficient
privileges or the MSR does not exist).

## Physical address retrieval (Linux only, requires root)

```c
uint64_t retrieve_physical_address(const volatile void *ptr);
```

Returns the physical address of a virtual pointer. Linux only; requires root.
Result is undefined on other platforms.

## mmap error reporting

```c
const char *strerror_for_mmap();
```

Returns the error message for the last failed `mmap()` call (or `VirtualAlloc` on
Windows). **Must be called before anything overwrites `errno` or `GetLastError()`.**
Use immediately after a failed `mmap()` in `test_init`.
