---
applyTo: "**"
---
# sandstone.h — Logging

All logging macros are printf-style. Use `<inttypes.h>` format specifiers
(e.g. `PRIu64`) for `<stdint.h>` types such as `uint64_t`. Alternatively, cast
to `size_t`/`ptrdiff_t`/`long long`/`unsigned long long` and use `%zu`/`%td`/`%lld`/`%llu`.

## Call-ordering constraints (enforced by convention)

1. `log_thread_context(fmt, ...)` — **must be the very first log call** in the thread.
   Its argument must be a single line of properly-formatted YAML. Omit if the thread
   has no device context to report.
2. `log_skip(category, fmt, ...)` — must come immediately after `log_thread_context`
   (if used), before any other log call, and before returning `EXIT_SKIP`.

Violating this order produces malformed YAML in the log output.

## Log macros

| Macro | Prefix | Notes |
| ----- | ------ | ----- |
| `log_error(fmt, ...)` | `E> ` | Always emitted. |
| `log_warning(fmt, ...)` | `W> ` | Always emitted. |
| `log_info(fmt, ...)` | `I> ` | Always emitted. |
| `log_debug(fmt, ...)` | `d> ` | **No-op in release builds** (`NDEBUG`). Generates no code. |
| `log_skip(cat, fmt, ...)` | — | Logs skip reason; see SkipCategory below. |
| `log_thread_context(fmt, ...)` | — | Single YAML line describing thread's device context. C++ also accepts `std::string_view`. |
| `log_platform_message(fmt, ...)` | `Platform issue:` | For OS/platform failures (memory alloc, file creation), not device failures. |
| `log_data(msg, data, size)` | — | Hex-dumps `size` bytes from `data` with label `msg`. |
| `log_yaml(level, yaml)` | — | Emits pre-formatted YAML at the given level character. |

`log_message(thread_num, fmt, ...)` is the raw underlying function; prefer the macros.

## SkipCategory enum

Use the most specific category available:

| Value | When to use |
| ----- | ----------- |
| `CpuNotSupportedSkipCategory` | CPU lacks required instruction set or features. |
| `CpuTopologyIssueSkipCategory` | CPU topology does not meet test requirements. |
| `TestResourceIssueSkipCategory` | Test-specific resource unavailable (e.g., a required file or device node). |
| `OSResourceIssueSkipCategory` | OS resource unavailable (memory, file descriptors, etc.). |
| `OsNotSupportedSkipCategory` | OS does not support what the test requires. |
| `DeviceNotFoundSkipCategory` | Required device (GPU, accelerator) not present. |
| `DeviceNotConfiguredSkipCategory` | Device present but not configured for testing. |
| `RuntimeSkipCategory` | Runtime condition prevents the test (e.g., insufficient privileges). |
| `TestObsoleteSkipCategory` | Test is obsolete and should not run. |
| `IgnoredMceCategory` | MCE detected but ignored per policy. |
| `SelftestSkipCategory` | Skip during framework self-test mode. |
| `UnknownSkipCategory` | Use only when no other category applies. |

## SANDSTONE_NO_LOGGING effects

When `SANDSTONE_NO_LOGGING` is defined:
- `log_warning`, `log_info`, `log_debug`, `log_data` become no-ops.
- `log_yaml` is redefined to call the underlying function with a null yaml string (not a true no-op).
- `log_error` emits a bare `E>` marker with no message.
- `log_platform_message` emits a bare `E>` marker only when the message starts with `E>`.
- `log_skip` passes a null message.
