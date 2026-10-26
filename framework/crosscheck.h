/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CROSSCHECK_H
#define CROSSCHECK_H

#include <sandstone.h>

// Cross-check API: test requirements
// - A named tag denotes an invariant typed array for one pass, not a varying stream.
// - Capture inputs in test_init(); compute golden and worker outputs from get_input() views.
// - Optionally capture golden outputs in test_init(). Without a golden output for
//   a name, all workers must agree. Submit required worker outputs in test_run().
// - Counts are element counts. Capture owns a copy, so source buffers may be reused.
// - Element types must be unqualified (no const/volatile), non-void, trivially
//   copyable types recognized by sandstone_data.h, not arbitrary language scalars.
//   C supports SANDSTONE_SCALAR_TYPES (e.g., uint32_t, float, BFloat16); C++ also
//   supports TypeToDataType mappings (e.g., Float32).
//
// Comparison and lifecycle details
// - Each worker's first submission is a snapshot; later submissions must match it.
//   Golden output and consensus verification run post-join before test_cleanup().
//   Golden output verification applies only to successful workers. Consensus uses
//   fixed logical worker 0, with no fallback or voting. Incomplete worker execution
//   cannot pass consensus; original errors/skips remain intact.
// - Equality compares exact meaningful representation bytes, including NaN
//   payloads and signed zero, but ignores trailing scalar padding (such as x87).
// - State and worker 0 are local to the current execution slice/pass, not shared
//   across processes. Consensus discovers submitted names; a tag never submitted
//   by any worker does not register an output to check.
// - Views survive through test_cleanup(); capture inputs in test_init(), capture
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

template <InputElement T> struct InputTag
{
    const char *name;
};

template <InputElement T> struct OutputTag
{
    const char *name;
};

CrossCheckState &input_state_for_capture(const char *name);
const CapturedSlot &lookup_input(const char *name, const void *type_token);
CrossCheckState &output_state_for_capture(const char *name);
void check_output_submission(const char *name, const void *actual, size_t count, OutputMatch match);
void verify_worker_outputs(size_t worker);
bool verify_consensus_outputs();

} // namespace SandstoneCrossCheck

#define DECLARE_CROSS_CHECK_INPUT(name, type) \
    static constexpr SandstoneCrossCheck::InputTag<type> name{#name}
#define DECLARE_CROSS_CHECK_OUTPUT(name, type) \
    static constexpr SandstoneCrossCheck::OutputTag<type> name{#name}

template <SandstoneCrossCheck::InputElement T>
inline void capture_input(SandstoneCrossCheck::InputTag<T> tag, const T *data, size_t count,
                          const char *description = nullptr)
{
    auto &state = SandstoneCrossCheck::input_state_for_capture(tag.name);
    state.inputs.emplace(tag.name, SandstoneCrossCheck::make_captured_slot(data, count, description));
}

// Integer counts (including literal 0) must select the pointer/count overload,
// not convert to a null description when the source is a raw array.
template <SandstoneCrossCheck::InputElement T, SandstoneCrossCheck::ContiguousComparable<T> R,
          typename D = const char *>
    requires std::convertible_to<D, const char *>
inline void capture_input(SandstoneCrossCheck::InputTag<T> tag, const R &values,
                          D description = nullptr)
{
    capture_input(tag, std::ranges::data(values), std::ranges::size(values), description);
}

// Inputs are immutable and shared by all workers until the pass ends.
template <SandstoneCrossCheck::InputElement T>
[[nodiscard]] inline std::span<const T> get_input(SandstoneCrossCheck::InputTag<T> tag)
{
    const auto &slot = SandstoneCrossCheck::lookup_input(tag.name, &SandstoneCrossCheck::CAPTURE_TYPE_TOKEN<T>);
    return {static_cast<const T *>(slot.storage.get()), slot.count};
}

template <SandstoneCrossCheck::InputElement T>
inline void capture_output(SandstoneCrossCheck::OutputTag<T> tag, const T *data, size_t count,
                           const char *description)
{
    auto &state = SandstoneCrossCheck::output_state_for_capture(tag.name);
    if (state.phase == SandstoneCrossCheck::CrossCheckState::Phase::Initializing) {
        state.capture_golden(tag.name, data, count, description);
    } else {
        auto match = state.submit_output(size_t(thread_num), tag.name, data, count, description);
        if (match != SandstoneCrossCheck::OutputMatch::First
                && match != SandstoneCrossCheck::OutputMatch::Equal)
            SandstoneCrossCheck::check_output_submission(tag.name, data, count, match);
    }
}

template <SandstoneCrossCheck::InputElement T, SandstoneCrossCheck::ContiguousComparable<T> R>
inline void capture_output(SandstoneCrossCheck::OutputTag<T> tag, const R &values,
                           const char *description)
{
    capture_output(tag, std::ranges::data(values), std::ranges::size(values), description);
}

extern "C" {
#endif

struct CrossCheckInputView
{
    const void *data;
    size_t count;
};

#define CROSSCHECK_INPUT_PROTOTYPES(ctype, tag, suffix) \
    void _crosscheck_capture_input_##suffix(const char *name, const ctype *data, size_t count, \
                                            const char *description); \
    struct CrossCheckInputView _crosscheck_get_input_##suffix(const char *name);
SANDSTONE_SCALAR_TYPES(CROSSCHECK_INPUT_PROTOTYPES)
#undef CROSSCHECK_INPUT_PROTOTYPES

#define CROSSCHECK_OUTPUT_PROTOTYPES(ctype, tag, suffix) \
    void _crosscheck_capture_output_##suffix(const char *name, const ctype *data, size_t count, \
                                            const char *description);
SANDSTONE_SCALAR_TYPES(CROSSCHECK_OUTPUT_PROTOTYPES)
#undef CROSSCHECK_OUTPUT_PROTOTYPES

#ifdef __cplusplus
} // extern "C"
#else

#define CROSSCHECK_INPUT_CAPTURE_ASSOC(ctype, tag, suffix) \
    , ctype *: _crosscheck_capture_input_##suffix \
    , const ctype *: _crosscheck_capture_input_##suffix
#define CROSSCHECK_INPUT_GET_ASSOC(ctype, tag, suffix) \
    , const ctype *: _crosscheck_get_input_##suffix
#define CROSSCHECK_INPUT_TYPE_ASSOC(ctype, tag, suffix) , ctype *: 1

#define CROSSCHECK_INPUT_CAPTURE_FN(data) \
    _Generic((data) SANDSTONE_SCALAR_TYPES(CROSSCHECK_INPUT_CAPTURE_ASSOC))
#define CROSSCHECK_INPUT_GET_FN(data) \
    _Generic((data) SANDSTONE_SCALAR_TYPES(CROSSCHECK_INPUT_GET_ASSOC))

// Tags used only in unevaluated type checks do not need either generated helper.
#define DECLARE_CROSS_CHECK_INPUT(name, type) \
    _Static_assert(_Generic((type *)0 SANDSTONE_SCALAR_TYPES(CROSSCHECK_INPUT_TYPE_ASSOC)), \
                   "input elements must be unqualified recognized scalars"); \
    typedef type crosscheck_input_type_##name; \
    struct CrossCheckInputView_##name { const type *data; size_t count; }; \
    static inline __attribute__((unused)) void crosscheck_capture_input_##name( \
            const type *data, size_t count, const char *description) \
    { \
        CROSSCHECK_INPUT_CAPTURE_FN(data)(#name, data, count, description); \
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
#define capture_input(name, data, count, description) \
    ((void)sizeof(_Generic((data), \
        crosscheck_input_type_##name *: 0, const crosscheck_input_type_##name *: 0)), \
     crosscheck_capture_input_##name((data), (count), (description)))
#define get_input(name) \
    ((void)sizeof(crosscheck_input_type_##name), crosscheck_get_input_##name())

#define CROSSCHECK_OUTPUT_CAPTURE_ASSOC(ctype, tag, suffix) \
    , ctype *: _crosscheck_capture_output_##suffix \
    , const ctype *: _crosscheck_capture_output_##suffix
#define CROSSCHECK_OUTPUT_CAPTURE_FN(data) \
    _Generic((data) SANDSTONE_SCALAR_TYPES(CROSSCHECK_OUTPUT_CAPTURE_ASSOC))

#define DECLARE_CROSS_CHECK_OUTPUT(name, type) \
    _Static_assert(_Generic((type *)0 SANDSTONE_SCALAR_TYPES(CROSSCHECK_INPUT_TYPE_ASSOC)), \
                   "output elements must be unqualified recognized scalars"); \
    typedef type crosscheck_output_type_##name; \
    static inline void crosscheck_capture_output_##name(const type *data, size_t count, \
                                                       const char *description) \
    { \
        CROSSCHECK_OUTPUT_CAPTURE_FN(data)(#name, data, count, description); \
    } \
    _Static_assert(1, "output declaration")

#define capture_output(name, data, count, description) \
    ((void)sizeof(_Generic((data), \
        crosscheck_output_type_##name *: 0, const crosscheck_output_type_##name *: 0)), \
     crosscheck_capture_output_##name((data), (count), (description)))

#endif // __cplusplus

#endif // CROSSCHECK_H
