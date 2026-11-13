/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CROSSCHECK_H
#define CROSSCHECK_H

#include <sandstone.h>

// Cross-check API: test requirements
// - A named key denotes an invariant typed array for one pass, not a varying stream.
// - Set inputs in test_init(); compute init and worker outputs from get_input() views.
// - API use enables capture; no test declaration flag or verification mode is needed.
// - Counts are element counts. The framework owns snapshots, so source buffers may be reused.
// - Element types must be unqualified (no const/volatile), non-void, trivially
//   copyable types recognized by sandstone_data.h, not arbitrary language scalars.
//   C supports SANDSTONE_SCALAR_TYPES (e.g., uint32_t, float, BFloat16); C++ also
//   supports TypeToDataType mappings (e.g., Float32).
//
// Comparison and lifecycle details
// - Each participant's first submission is a snapshot; later submissions must match it.
//   Post-join verification includes successful workers and init, for names init submitted.
//   A strict majority implicates outliers; without a majority, all conflicting
//   producers are implicated. Skipped/failed workers do not vote. Fewer than two
//   participants for an output is insufficient coverage, not a comparison failure.
// - Equality compares exact meaningful representation bytes, including NaN
//   payloads and signed zero, but ignores trailing scalar padding (such as x87).
// - State is local to the current execution slice/pass, not shared
//   across processes. Verification discovers submitted names; a tag never submitted
//   by any participant does not register an output to check.
// - Views survive through test_cleanup(); set inputs in test_init(), submit
//   outputs in test_init()/test_run(), and look up inputs in test_init()/test_run().
// - Deferred failure callbacks run on the coordinator with the target logical
//   worker identity, not the original worker's TLS or physical CPU context.

#ifdef __cplusplus
#include "crosscheck_state.hpp"

#include <concepts>
#include <cstddef>
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
void record_output_cpu(const char *name);
void check_output_submission(const char *name, const void *actual, size_t count, OutputMatch match);
enum class VerificationResult { Complete, Insufficient, Invalid, Failed };
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
template <SandstoneCrossCheck::InputElement T, SandstoneCrossCheck::ContiguousComparable<T> R,
          typename D = const char *>
    requires std::convertible_to<D, const char *>
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
    if (match == SandstoneCrossCheck::OutputMatch::First)
        SandstoneCrossCheck::record_output_cpu(tag.name);
    if (match != SandstoneCrossCheck::OutputMatch::First
            && match != SandstoneCrossCheck::OutputMatch::Equal)
        SandstoneCrossCheck::check_output_submission(tag.name, data, count, match);
}

template <SandstoneCrossCheck::InputElement T, SandstoneCrossCheck::ContiguousComparable<T> R>
inline void submit_output(SandstoneCrossCheck::OutputKey<T> tag, const R &values,
                          const char *description)
{
    submit_output(tag, std::ranges::data(values), std::ranges::size(values), description);
}

extern "C" {
#endif

struct CrossCheckInputView
{
    const void *data;
    size_t count;
};

#define CROSSCHECK_INPUT_PROTOTYPES(ctype, tag, suffix) \
    void _crosscheck_set_input_##suffix(const char *name, const ctype *data, size_t count, \
                                      const char *description); \
    struct CrossCheckInputView _crosscheck_get_input_##suffix(const char *name);
SANDSTONE_SCALAR_TYPES(CROSSCHECK_INPUT_PROTOTYPES)
#undef CROSSCHECK_INPUT_PROTOTYPES

#define CROSSCHECK_OUTPUT_PROTOTYPES(ctype, tag, suffix) \
    void _crosscheck_submit_output_##suffix(const char *name, const ctype *data, size_t count, \
                                          const char *description);
SANDSTONE_SCALAR_TYPES(CROSSCHECK_OUTPUT_PROTOTYPES)
#undef CROSSCHECK_OUTPUT_PROTOTYPES

#ifdef __cplusplus
} // extern "C"
#else

#define CROSSCHECK_INPUT_SET_ASSOC(ctype, tag, suffix) \
    , ctype *: _crosscheck_set_input_##suffix \
    , const ctype *: _crosscheck_set_input_##suffix
#define CROSSCHECK_INPUT_GET_ASSOC(ctype, tag, suffix) \
    , const ctype *: _crosscheck_get_input_##suffix
#define CROSSCHECK_INPUT_TYPE_ASSOC(ctype, tag, suffix) , ctype *: 1

#define CROSSCHECK_INPUT_SET_FN(data) \
    _Generic((data) SANDSTONE_SCALAR_TYPES(CROSSCHECK_INPUT_SET_ASSOC))
#define CROSSCHECK_INPUT_GET_FN(data) \
    _Generic((data) SANDSTONE_SCALAR_TYPES(CROSSCHECK_INPUT_GET_ASSOC))

// Tags used only in unevaluated type checks do not need either generated helper.
#define CROSSCHECK_INPUT(name, type) \
    _Static_assert(_Generic((type *)0 SANDSTONE_SCALAR_TYPES(CROSSCHECK_INPUT_TYPE_ASSOC)), \
                   "input elements must be unqualified recognized scalars"); \
    typedef type crosscheck_input_type_##name; \
    struct CrossCheckInputView_##name { const type *const data; const size_t count; }; \
    static inline __attribute__((unused)) void crosscheck_set_input_##name( \
            const type *data, size_t count, const char *description) \
    { \
        CROSSCHECK_INPUT_SET_FN(data)(#name, data, count, description); \
    } \
    static inline __attribute__((unused)) struct CrossCheckInputView_##name \
    crosscheck_get_input_##name(void) \
    { \
        struct CrossCheckInputView view = CROSSCHECK_INPUT_GET_FN((const type *)0)(#name); \
        return (struct CrossCheckInputView_##name){view.data, view.count}; \
    } \
    _Static_assert(1, "input declaration")

// No default association: an incompatible pointer is a compile-time error,
// including void pointers and other scalar types with the same DataType.
#define set_input(name, data, count, description) \
    ((void)sizeof(_Generic((data), \
        crosscheck_input_type_##name *: 0, const crosscheck_input_type_##name *: 0)), \
     crosscheck_set_input_##name((data), (count), (description)))
#define get_input(name) \
    ((void)sizeof(crosscheck_input_type_##name), crosscheck_get_input_##name())

#define CROSSCHECK_OUTPUT_SUBMIT_ASSOC(ctype, tag, suffix) \
    , ctype *: _crosscheck_submit_output_##suffix \
    , const ctype *: _crosscheck_submit_output_##suffix
#define CROSSCHECK_OUTPUT_SUBMIT_FN(data) \
    _Generic((data) SANDSTONE_SCALAR_TYPES(CROSSCHECK_OUTPUT_SUBMIT_ASSOC))

#define CROSSCHECK_OUTPUT(name, type) \
    _Static_assert(_Generic((type *)0 SANDSTONE_SCALAR_TYPES(CROSSCHECK_INPUT_TYPE_ASSOC)), \
                   "output elements must be unqualified recognized scalars"); \
    typedef type crosscheck_output_type_##name; \
    static inline void crosscheck_submit_output_##name(const type *data, size_t count, \
                                                      const char *description) \
    { \
        CROSSCHECK_OUTPUT_SUBMIT_FN(data)(#name, data, count, description); \
    } \
    _Static_assert(1, "output declaration")

#define submit_output(name, data, count, description) \
    ((void)sizeof(_Generic((data), \
        crosscheck_output_type_##name *: 0, const crosscheck_output_type_##name *: 0)), \
     crosscheck_submit_output_##name((data), (count), (description)))

#endif // __cplusplus

#endif // CROSSCHECK_H
