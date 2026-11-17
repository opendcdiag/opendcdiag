/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CROSSCHECK_H
#define CROSSCHECK_H

#include <sandstone.h>

// Cross-check API: test requirements
// - A named key denotes an invariant typed array for one pass, not a varying stream.
// - Put tags shared across translation units in a shared header. Names match by
//   string contents, not tag or string-literal address. Input and output names
//   occupy separate namespaces within each attempt. Reusing a name/type/count
//   for unrelated values cannot be detected as misuse; type/count contracts are
//   checked on API use, not tag declaration.
// - Set inputs in test_init(); compute init and worker outputs from get_input() views.
// - Counts are element counts. The framework owns snapshots, so source buffers may be reused.
// - Element types must be unqualified (no const/volatile), non-void, trivially
//   copyable types recognized by sandstone_data.h, not arbitrary language scalars.
//   Supported types include uint32_t, float, BFloat16, and TypeToDataType mappings
//   such as Float32.
//
// Comparison and lifecycle details
// - Each test thread has one snapshot per name, indexed by thread_num, not device.
//   Init shares test thread zero's snapshot, without an extra vote; thread zero checks
//   it even after migration. Different test threads vote separately even on the same CPU.
//   Init must finish submissions before test_run(). Additional output-submitting
//   helper threads are unsupported. CPU test threads may migrate within the selected slice.
//   For threads with output snapshots, thread_runner cleanup records the current CPU/device
//   before callbacks and finish_reschedule(), including on skip and cancellation/failure.
//   Deferred hardware attribution uses that completion device; immediate mismatches use
//   detection/submission placement. Neither observation proves where data was computed.
//   First-submission host CPU is sampled only for a new snapshot and retained for reporting,
//   separately from completion CPU/device and first submission thread (including init's -1).
//   Accelerator attribution uses the assigned endpoint/tile or WQ, never the host CPU.
//   Compute init outputs on the first selected accelerator and worker outputs on their
//   assigned accelerator. Custom computation/mapping must agree with those assignments.
//   If any test thread succeeds, post-join verification includes every submitted snapshot,
//   even if the submitting test thread later skips.
//   A strict majority implicates outliers; without a majority, all conflicting
//   test threads' completion devices are implicated. Any preexisting failure stops deferred verification.
//   A name with fewer than two test thread snapshots needs no
//   deferred comparison; exactly one snapshot produces an informational diagnostic.
//   Conflicting value classes without a strict majority qualify the failure summary and
//   retry topology analysis as inconclusive attribution, without changing device masks.
//   Incompatible element types/counts are test bugs and abort after cleanup unless
//   a data comparison or cleanup failure takes precedence. Duplicate/missing inputs,
//   exact type/count, null data, and extent errors abort even in release builds.
// - Equality compares exact meaningful representation bytes, including NaN
//   payloads and signed zero, but ignores trailing scalar padding (such as x87).
// - State is local to the current execution slice/pass, not shared
//   across processes. Verification discovers submitted names; a tag never submitted
//   by init or test_run() does not register an output to check. APIs are forbidden in
//   the actual main process under process isolation, including parent execution flags;
//   valid no-fork use is permitted. Parent isolation, running-test, name, lifecycle,
//   and assigned accelerator index invariants are checked only in debug builds.
//   Init cannot rescue an all-workers-skipped run.
// - Views survive through test_cleanup(); set inputs in test_init(), submit
//   outputs in test_init()/test_run(), and look up inputs in init, run, or cleanup.
// - Deferred failure callbacks run on the main thread with the first submission's
//   thread_num, separately from hardware attribution, not the test thread's TLS or CPU context.
// - Init submits before test threads start. During test_run(), each test thread
//   exclusively accesses its own output map; the main thread compares maps after join.
//   No cross-check locking or atomics are needed. Helper-thread submissions and
//   live cross-thread output inspection are unsupported, not an external locking contract.
//   CPU test threads with snapshots completing or detecting a mismatch outside the selected
//   slice abort as API misuse, including in release builds. The API does
//   not harden framework affinity setup or infer the computation's CPU history.
//   Repeats borrow immutable snapshots without allocation or bookkeeping. First
//   submissions require readable data; observed snapshots reject incompatible
//   exact type/count before actual-data access.

#include "crosscheck_state.hpp"

#include <concepts>
#include <cstddef>
#include <limits>
#include <ranges>
#include <span>
#include <type_traits>

namespace SandstoneCrossCheck {

template <typename T>
concept InputElement = SandstoneDataDetails::ValidDataType<T>
        && !std::is_void_v<T> && !std::is_const_v<T> && !std::is_volatile_v<T>
        && std::is_trivially_copyable_v<T>;

template <InputElement T> struct InputKey
{
    const char *name;
};

template <InputElement T> struct OutputKey
{
    const char *name;
};

CrossCheckState &input_state_for_set(const char *name);
template<InputElement T>
inline void validate_data_extent(const T *data, size_t count)
{
    if (!data && count)
        invalid_operation("null data pointer with nonzero count");
    if (count > size_t(std::numeric_limits<ptrdiff_t>::max() - 1) / sizeof(T))
        invalid_operation("data extent overflows");
}
const CapturedSlot &lookup_input(const char *name, const void *type_token);
OutputSubmission output_state_for_submission(const char *name);
[[gnu::cold]] void check_output_submission(const OutputSubmission &submission, const void *actual);
enum class VerificationResult { Complete, Invalid, Failed };
VerificationResult verify_outputs();
void finish_thread();

} // namespace SandstoneCrossCheck

#define CROSSCHECK_INPUT(name, type) \
    static constexpr SandstoneCrossCheck::InputKey<type> name{#name}
#define CROSSCHECK_OUTPUT(name, type) \
    static constexpr SandstoneCrossCheck::OutputKey<type> name{#name}

template <SandstoneCrossCheck::InputElement T>
inline void set_input(SandstoneCrossCheck::InputKey<T> tag, const T *data, size_t count,
                      const char *description = nullptr)
{
    auto &state = SandstoneCrossCheck::input_state_for_set(tag.name);
    SandstoneCrossCheck::validate_data_extent(data, count);
    state.inputs.emplace(tag.name, SandstoneCrossCheck::make_captured_slot(data, count, description));
}

// Integer counts (including literal 0) must select the pointer/count overload,
// not convert to a null description when the source is a raw array.
template <SandstoneCrossCheck::InputElement T, SandstoneDataDetails::ContiguousComparable R,
          typename D = const char *>
    requires std::same_as<std::ranges::range_value_t<R>, T> && std::convertible_to<D, const char *>
inline void set_input(SandstoneCrossCheck::InputKey<T> tag, const R &values,
                      D description = nullptr)
{
    set_input(tag, std::ranges::data(values), std::ranges::size(values), description);
}

// Inputs are immutable and shared by all workers until the pass ends.
template <SandstoneCrossCheck::InputElement T>
[[nodiscard]] inline std::span<const T> get_input(SandstoneCrossCheck::InputKey<T> tag)
{
    const auto &slot = SandstoneCrossCheck::lookup_input(tag.name, &SandstoneCrossCheck::CAPTURE_TYPE_TOKEN<T>);
    return {static_cast<const T *>(slot.storage.get()), slot.count};
}

// Keep typed equality at the public boundary so fixed counts remain compiler-visible.
template <SandstoneCrossCheck::InputElement T>
inline __attribute__((always_inline)) void
submit_output(SandstoneCrossCheck::OutputKey<T> tag, const T *data, size_t count,
              const char *description)
{
    auto submission = SandstoneCrossCheck::output_state_for_submission(tag.name);
    SandstoneCrossCheck::validate_data_extent(data, count);
    const auto *expected = submission.submit(data, count, description);
    if (!expected || count == 0)
        return;
    if (!SandstoneDataDetails::memcmp_equal<SandstoneDataDetails::TypeToDataType<T>::Type>(
                data, expected->storage.get(), count * sizeof(T)))
        SandstoneCrossCheck::check_output_submission(submission, data);
}

template <SandstoneCrossCheck::InputElement T, SandstoneDataDetails::ContiguousComparable R>
    requires std::same_as<std::ranges::range_value_t<R>, T>
inline void submit_output(SandstoneCrossCheck::OutputKey<T> tag, const R &values,
                          const char *description)
{
    submit_output(tag, std::ranges::data(values), std::ranges::size(values), description);
}

#endif // CROSSCHECK_H
