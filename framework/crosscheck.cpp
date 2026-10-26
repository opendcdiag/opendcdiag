/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck.h"
#include "sandstone_p.h"

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <sysexits.h>
#include <vector>

namespace SandstoneCrossCheck {

void invalid_operation(const char *reason)
{
    if (sApp->is_child_process()) {
        log_message_preformatted(thread_num, LOG_LEVEL_QUIET,
                stdprintf(SANDSTONE_LOG_ERROR "Cross-check invalid execution: %s", reason));
        _exit(EX_SOFTWARE);
    }
    logging_printf(LOG_LEVEL_QUIET, "# Cross-check invalid execution: %s\n", reason);
    _exit(cleanup_global(EXIT_INVALID, {}));
}

static void require_enabled(const char *name)
{
    if (!current_test() || current_test()->crosscheck == CrossCheckNone)
        invalid_operation("cross-check APIs require an enabled .crosscheck policy");
    if (!name || !*name)
        invalid_operation("cross-check keys require a nonempty name");
}

CrossCheckState &input_state_for_set(const char *name)
{
    CrossCheckState &state = sApp->crosscheck_state;
    require_enabled(name);
    if (state.phase != CrossCheckState::Phase::Initializing || thread_num != -1)
        invalid_operation("set_input() must be called from test_init()");
    if (state.inputs.contains(name))
        invalid_operation("input name already set in this attempt");
    return state;
}

const CapturedSlot &lookup_input(const char *name, const void *type_token)
{
    const CrossCheckState &state = sApp->crosscheck_state;
    require_enabled(name);
    if (state.phase != CrossCheckState::Phase::Initializing
            && state.phase != CrossCheckState::Phase::Running)
        invalid_operation("get_input() must be called from test_init() or test_run()");
    auto it = state.inputs.find(name);
    if (it == state.inputs.end())
        invalid_operation("input was not set in this attempt");
    if (it->second.type_token != type_token)
        invalid_operation("input key has a different element type");
    return it->second;
}

OutputSubmission output_state_for_submission(const char *name)
{
    auto &state = sApp->crosscheck_state;
    require_enabled(name);
    if (state.phase == CrossCheckState::Phase::Initializing && thread_num == -1) {
        if (current_test()->crosscheck != CrossCheckGolden)
            invalid_operation("consensus test_init() cannot submit outputs");
        std::string_view key(name);
        auto position = state.golden_outputs.lower_bound(key);
        if (position != state.golden_outputs.end() && position->first == key)
            invalid_operation("golden output name already submitted in this attempt");
        return {key, &state.golden_outputs, position, nullptr, false};
    } else if (state.phase == CrossCheckState::Phase::Running && thread_num >= 0) {
        auto submission = state.output_submission(size_t(thread_num), std::string_view(name));
        if (current_test()->crosscheck == CrossCheckGolden && !submission.existing && !submission.golden)
            invalid_operation("actual output has no golden reference");
        return submission;
    } else {
        invalid_operation("submit_output() must be called from test_init() or test_run()");
    }
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
        invalid_operation("output element type mismatch");
    if (match == OutputMatch::CountMismatch)
        invalid_operation("later output submission count mismatch");
    auto golden = state.golden_outputs.find(name);
    const auto &expected = state.worker_outputs[size_t(thread_num)]->find(name)->second;
    compare_output_or_fail(name, golden == state.golden_outputs.end() ? expected : golden->second,
                           expected, actual, count, match,
                           "later submission vs first submission");
}

bool verify_worker_outputs(size_t worker)
{
    const auto &state = sApp->crosscheck_state;
    assert(state.phase == CrossCheckState::Phase::Running);
    assert(worker < state.worker_outputs.size());
    bool valid = true;
    const auto &outputs = state.worker_outputs[worker];
    auto actual = outputs ? outputs->begin() : OutputMap::const_iterator{};
    for (const auto &[name, golden] : state.golden_outputs) {
        const CapturedSlot *first = nullptr;
        if (outputs) {
            while (actual != outputs->end() && actual->first < name)
                ++actual;
            if (actual != outputs->end() && actual->first == name)
                first = &actual++->second;
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
        if (match == OutputMatch::DataMismatch) {
            logging_report_crosscheck_failure(int(worker), sApp->test_thread_data(int(worker))->completion_cpu,
                    description, &golden, first);
        } else {
            log_message_preformatted(int(worker), LOG_LEVEL_QUIET, "E> " + description);
            valid = false;
        }
    }
    return valid;
}

bool verify_consensus_outputs()
{
    const auto &state = sApp->crosscheck_state;
    bool any_outputs = false;
    for (const auto &outputs : state.worker_outputs)
        any_outputs |= outputs && !outputs->empty();
    if (!any_outputs) {
        log_message_preformatted(-1, LOG_LEVEL_QUIET,
                std::string("E> Cross-check consensus registered no outputs"));
    }

    bool complete = any_outputs;
    const OutputMap empty_outputs;
    const auto &reference_outputs = state.worker_outputs[0] ? *state.worker_outputs[0] : empty_outputs;
    std::vector<std::string_view> extra_names;
    bool reference_completed = sApp->test_thread_data(0)->thread_state.load(std::memory_order_relaxed)
            == thread_succeeded;
    for (size_t worker = 0; worker < state.worker_outputs.size(); ++worker) {
        auto *thread = sApp->test_thread_data(int(worker));
        bool worker_completed = thread->thread_state.load(std::memory_order_relaxed) == thread_succeeded;
        if (!worker_completed) {
            log_message_preformatted(int(worker), LOG_LEVEL_QUIET,
                    std::string("E> Cross-check consensus incomplete: worker did not complete successfully"));
            complete = false;
        }
        if (!reference_completed || worker == 0)
            continue;
        const auto &outputs = state.worker_outputs[worker] ? *state.worker_outputs[worker] : empty_outputs;
        auto reference_it = reference_outputs.begin();
        auto actual_it = outputs.begin();
        while (reference_it != reference_outputs.end() || actual_it != outputs.end()) {
            if (actual_it != outputs.end()
                    && (reference_it == reference_outputs.end() || actual_it->first < reference_it->first)) {
                extra_names.push_back(actual_it++->first);
                continue;
            }
            const auto &[name, reference] = *reference_it++;
            const CapturedSlot *actual = nullptr;
            if (actual_it != outputs.end() && actual_it->first == name)
                actual = &actual_it++->second;
            if (!worker_completed)
                continue;
            OutputMatch match = compare_output(reference, actual);
            if (match == OutputMatch::Equal)
                continue;
            std::string description = stdprintf("Cross-check output '%.*s'", int(name.size()), name.data());
            description += stdprintf(" (%s), first submission vs worker 0's first submission",
                                     reference.description.c_str());
            if (match == OutputMatch::Missing) {
                description += ": worker did not submit output";
            } else if (match == OutputMatch::TypeMismatch) {
                description += ": element type mismatch";
            } else if (match == OutputMatch::CountMismatch) {
                description += stdprintf(": count mismatch: actual %zu vs expected %zu",
                                         actual->count, reference.count);
            } else if (match == OutputMatch::DataMismatch) {
                description += ": disagreement without independent attribution";
            }
            log_message_preformatted(int(worker), LOG_LEVEL_QUIET, "E> " + description);
            complete = false;
        }
    }
    std::sort(extra_names.begin(), extra_names.end());
    auto end = std::unique(extra_names.begin(), extra_names.end());
    for (auto it = extra_names.begin(); it != end; ++it) {
        log_message_preformatted(0, LOG_LEVEL_QUIET,
                stdprintf("E> Cross-check output '%.*s': worker 0 did not submit output",
                          int(it->size()), it->data()));
        complete = false;
    }
    return complete;
}

} // namespace SandstoneCrossCheck

#define CROSSCHECK_INPUT_GLUE(ctype, tag, suffix) \
    extern "C" void _crosscheck_set_input_##suffix(const char *name, const ctype *data, \
                                                size_t count, const char *description) \
    { \
        set_input(SandstoneCrossCheck::InputKey<ctype>{name}, data, count, description); \
    } \
    extern "C" CrossCheckInputView _crosscheck_get_input_##suffix(const char *name) \
    { \
        auto view = get_input(SandstoneCrossCheck::InputKey<ctype>{name}); \
        return {view.data(), view.size()}; \
    }
SANDSTONE_SCALAR_TYPES(CROSSCHECK_INPUT_GLUE)
#undef CROSSCHECK_INPUT_GLUE

#define CROSSCHECK_OUTPUT_GLUE(ctype, tag, suffix) \
    extern "C" void _crosscheck_submit_output_##suffix(const char *name, const ctype *data, \
                                                    size_t count, const char *description) \
    { \
        submit_output(SandstoneCrossCheck::OutputKey<ctype>{name}, data, count, description); \
    }
SANDSTONE_SCALAR_TYPES(CROSSCHECK_OUTPUT_GLUE)
#undef CROSSCHECK_OUTPUT_GLUE
