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
// - Each selected CPU/device owns one snapshot per name; later submissions there must match.
//   CPU ownership observes submission placement; do not reschedule between computation
//   and submission. Accelerator workers submit their assigned endpoint/tile or WQ;
//   accelerator init may use inputs but may not submit outputs.
//   Post-join verification includes owners confirmed by successful workers or CPU init.
//   A strict majority implicates outliers; without a majority, all conflicting
//   owners are implicated. Skipped-worker-only slots do not vote; equal confirmation
//   by a successful worker qualifies the same snapshot. Any preexisting failure
//   stops deferred verification. A name with fewer than two eligible owners needs no
//   deferred comparison; exactly one owner produces an informational diagnostic.
//   Conflicting groups without a strict majority qualify the failure summary and
//   retry topology analysis as inconclusive attribution, without changing owner masks.
//   Incompatible element types/counts are test bugs and abort after cleanup unless
//   a data comparison or cleanup failure takes precedence. Immediate API misuse aborts.
// - Equality compares exact meaningful representation bytes, including NaN
//   payloads and signed zero, but ignores trailing scalar padding (such as x87).
// - State is local to the current execution slice/pass, not shared
//   across processes. Verification discovers submitted names; a tag never submitted
//   by any participant does not register an output to check. APIs are forbidden in
//   the actual main process under process isolation, including parent execution flags;
//   valid no-fork use is permitted. Init cannot rescue an all-workers-skipped run.
// - Views survive through test_cleanup(); set inputs in test_init(), submit
//   outputs in test_init()/test_run(), and look up inputs in init, run, or cleanup.
// - Deferred failure callbacks run on the coordinator with the first submitter's
//   worker identity, separately from hardware ownership, not its TLS or CPU context.

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
[[noreturn]] void invalid_operation(const char *reason);
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
void check_output_submission(const OutputSubmission &submission, const void *actual, OutputMatch match);
enum class VerificationResult { Complete, Invalid, Failed };
VerificationResult verify_outputs();

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

template <SandstoneCrossCheck::InputElement T>
inline void submit_output(SandstoneCrossCheck::OutputKey<T> tag, const T *data, size_t count,
                          const char *description)
{
    auto submission = SandstoneCrossCheck::output_state_for_submission(tag.name);
    SandstoneCrossCheck::validate_data_extent(data, count);
    auto match = submission.submit(data, count, description);
    if (match != SandstoneCrossCheck::OutputMatch::First
            && match != SandstoneCrossCheck::OutputMatch::Equal)
        SandstoneCrossCheck::check_output_submission(submission, data, match);
}

template <SandstoneCrossCheck::InputElement T, SandstoneDataDetails::ContiguousComparable R>
    requires std::same_as<std::ranges::range_value_t<R>, T>
inline void submit_output(SandstoneCrossCheck::OutputKey<T> tag, const R &values,
                          const char *description)
{
    submit_output(tag, std::ranges::data(values), std::ranges::size(values), description);
}

#endif // CROSSCHECK_H
