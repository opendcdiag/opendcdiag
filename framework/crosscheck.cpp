/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck.h"
#include "sandstone_p.h"

#include <cstddef>
#include <string>

namespace SandstoneCrossCheck {

CrossCheckState &input_state_for_capture(const char *name)
{
    CrossCheckState &state = sApp->crosscheck_state;
    assert(state.phase == CrossCheckState::Phase::Initializing && thread_num == -1
           && "capture_input() must be called from test_init()");
    assert(name && *name && "an input must have a nonempty name");
    assert(!state.inputs.contains(name) && "input name already captured in this pass");
    return state;
}

const CapturedSlot &lookup_input(const char *name, const void *type_token)
{
    const CrossCheckState &state = sApp->crosscheck_state;
    assert((state.phase == CrossCheckState::Phase::Initializing
            || state.phase == CrossCheckState::Phase::Running)
           && "get_input() must be called from test_init() or test_run()");
    assert(name && *name && "an input must have a nonempty name");
    auto it = state.inputs.find(name);
    assert(it != state.inputs.end() && "input was not captured in this pass");
    assert(it->second.type_token == type_token && "input tag has a different element type");
    (void)type_token;
    return it->second;
}

CrossCheckState &output_state_for_capture(const char *name)
{
    auto &state = sApp->crosscheck_state;
    assert(name && *name);
    assert((state.phase == CrossCheckState::Phase::Initializing && thread_num == -1)
           || (state.phase == CrossCheckState::Phase::Running && thread_num >= 0));
    (void)name;
    return state;
}

static void compare_output_or_fail(const std::string &name, const CapturedSlot &metadata,
                                   const CapturedSlot &expected, const void *actual, size_t count,
                                   OutputMatch match, const char *boundary)
{
    if (match == OutputMatch::CountMismatch)
        report_fail_msg("Cross-check output '%s' (%s), %s: count mismatch: actual %zu vs expected %zu",
                        name.c_str(), metadata.description.c_str(), boundary, count, expected.count);
    if (match == OutputMatch::DataMismatch)
        _memcmp_fail_report(actual, expected.storage.get(), expected.bytes().size(), expected.type,
                            "Cross-check output '%s' (%s), %s", name.c_str(),
                            metadata.description.c_str(), boundary);
}

void check_output_submission(const char *name, const void *actual, size_t count, OutputMatch match)
{
    const auto &state = sApp->crosscheck_state;
    if (match == OutputMatch::TypeMismatch)
        report_fail_msg("Cross-check output '%s': element type mismatch", name);
    auto golden = state.golden_outputs.find(name);
    const auto &expected = state.worker_outputs[size_t(thread_num)]->find(name)->second;
    compare_output_or_fail(name, golden == state.golden_outputs.end() ? expected : golden->second,
                           expected, actual, count, match,
                           "later submission vs first submission");
}

void verify_worker_outputs(size_t worker)
{
    const auto &state = sApp->crosscheck_state;
    assert(state.phase == CrossCheckState::Phase::Running);
    assert(worker < state.worker_outputs.size());
    for (const auto &[name, golden] : state.golden_outputs) {
        const auto &outputs = state.worker_outputs[worker];
        const CapturedSlot *first = nullptr;
        if (outputs) {
            auto it = outputs->find(name);
            if (it != outputs->end())
                first = &it->second;
        }
        auto match = compare_output(golden, first);
        if (match == OutputMatch::Equal)
            continue;
        std::string description = stdprintf("Cross-check output '%s'", name.c_str());
        if (!outputs)
            description += ": worker never submitted required golden outputs";
        else if (!first)
            description += ": worker did not submit a required golden output";
        else if (match == OutputMatch::TypeMismatch)
            description += ": element type mismatch";
        else {
            description += stdprintf(" (%s), first submission vs golden output", golden.description.c_str());
            if (match == OutputMatch::CountMismatch)
                description += stdprintf(": count mismatch: actual %zu vs expected %zu",
                                         first->count, golden.count);
        }
        logging_report_crosscheck_failure(int(worker), sApp->test_thread_data(int(worker))->completion_cpu,
                description, match == OutputMatch::DataMismatch ? &golden : nullptr,
                match == OutputMatch::DataMismatch ? first : nullptr);
        return;
    }
}

bool verify_consensus_outputs()
{
    const auto &state = sApp->crosscheck_state;
    auto names = state.consensus_outputs();
    if (names.empty())
        return true;

    bool complete = true;
    bool reference_completed = sApp->test_thread_data(0)->thread_state.load(std::memory_order_relaxed)
            == thread_succeeded;
    for (size_t worker = 0; worker < state.worker_outputs.size(); ++worker) {
        auto *thread = sApp->test_thread_data(int(worker));
        if (thread->thread_state.load(std::memory_order_relaxed) != thread_succeeded) {
            complete = false;
            continue; // Preserve original errors/skips, including nonreturning workers.
        }
        if (!reference_completed)
            continue;
        for (const auto &[name, reference] : names) {
            if (worker == 0 && reference)
                continue;
            const CapturedSlot *actual = nullptr;
            if (const auto &outputs = state.worker_outputs[worker]) {
                auto it = outputs->find(name);
                if (it != outputs->end())
                    actual = &it->second;
            }
            OutputMatch match = reference ? compare_output(*reference, actual) : OutputMatch::Missing;
            if (match == OutputMatch::Equal)
                continue;
            std::string description = stdprintf("Cross-check output '%.*s'", int(name.size()), name.data());
            if (!reference) {
                if (worker != 0)
                    continue;
                description += ": worker 0 did not submit output";
            } else {
                description += stdprintf(" (%s), first submission vs worker 0's first submission",
                                         reference->description.c_str());
            }
            if (reference && match == OutputMatch::Missing) {
                description += ": worker did not submit output";
            } else if (match == OutputMatch::TypeMismatch) {
                description += ": element type mismatch";
            } else if (match == OutputMatch::CountMismatch) {
                description += stdprintf(": count mismatch: actual %zu vs expected %zu",
                                         actual->count, reference->count);
            }
            logging_report_crosscheck_failure(int(worker), thread->completion_cpu, description,
                    match == OutputMatch::DataMismatch ? reference : nullptr,
                    match == OutputMatch::DataMismatch ? actual : nullptr);
        }
    }
    return complete;
}

} // namespace SandstoneCrossCheck

#define CROSSCHECK_INPUT_GLUE(ctype, tag, suffix) \
    extern "C" void _crosscheck_capture_input_##suffix(const char *name, const ctype *data, \
                                                       size_t count, const char *description) \
    { \
        capture_input(SandstoneCrossCheck::InputTag<ctype>{name}, data, count, description); \
    } \
    extern "C" CrossCheckInputView _crosscheck_get_input_##suffix(const char *name) \
    { \
        auto view = get_input(SandstoneCrossCheck::InputTag<ctype>{name}); \
        return {view.data(), view.size()}; \
    }
SANDSTONE_SCALAR_TYPES(CROSSCHECK_INPUT_GLUE)
#undef CROSSCHECK_INPUT_GLUE

#define CROSSCHECK_OUTPUT_GLUE(ctype, tag, suffix) \
    extern "C" void _crosscheck_capture_output_##suffix(const char *name, const ctype *data, \
                                                        size_t count, const char *description) \
    { \
        capture_output(SandstoneCrossCheck::OutputTag<ctype>{name}, data, count, description); \
    }
SANDSTONE_SCALAR_TYPES(CROSSCHECK_OUTPUT_GLUE)
#undef CROSSCHECK_OUTPUT_GLUE
