/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck.h"
#include "sandstone_p.h"

#include <sched.h>
#include <set>
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

static void require_context(const char *name)
{
    if (!current_test())
        invalid_operation("cross-check APIs require a running test");
    if (!name || !*name)
        invalid_operation("cross-check keys require a nonempty name");
}

CrossCheckState &input_state_for_set(const char *name)
{
    CrossCheckState &state = sApp->crosscheck_state;
    require_context(name);
    if (state.phase != CrossCheckState::Phase::Initializing || thread_num != -1)
        invalid_operation("set_input() must be called from test_init()");
    if (state.inputs.contains(name))
        invalid_operation("input name already set in this attempt");
    return state;
}

const CapturedSlot &lookup_input(const char *name, const void *type_token)
{
    const CrossCheckState &state = sApp->crosscheck_state;
    require_context(name);
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
    require_context(name);
    if (state.phase == CrossCheckState::Phase::Initializing && thread_num == -1) {
        std::string_view key(name);
        auto position = state.init_outputs.lower_bound(key);
        bool existing = position != state.init_outputs.end() && position->first == key;
        return {key, &state.init_outputs, position, existing};
    }
    if (state.phase == CrossCheckState::Phase::Running && thread_num >= 0)
        return state.output_submission(size_t(thread_num), std::string_view(name));
    invalid_operation("submit_output() must be called from test_init() or test_run()");
}

void record_output_cpu(const char *name)
{
    auto &state = sApp->crosscheck_state;
    auto &outputs = thread_num < 0 ? state.init_outputs : *state.worker_outputs[size_t(thread_num)];
    outputs.find(name)->second.cpu = sched_getcpu();
}

void check_output_submission(const char *name, const void *actual, size_t count, OutputMatch match)
{
    const auto &state = sApp->crosscheck_state;
    if (match == OutputMatch::TypeMismatch)
        invalid_operation("output element type mismatch");
    if (match == OutputMatch::CountMismatch)
        invalid_operation("later output submission count mismatch");
    const auto &outputs = thread_num < 0 ? state.init_outputs : *state.worker_outputs[size_t(thread_num)];
    const auto &expected = outputs.find(name)->second;
    sApp->thread_data(thread_num)->thread_flags |= uint32_t(PerThreadData::Common::Flag::CrossCheckFailure);
    _memcmp_fail_report(actual, expected.storage.get(), expected.bytes().size(), expected.type,
                        "Cross-check output '%s' (%s), later submission vs first submission",
                        name, expected.description.c_str());
}

VerificationResult verify_outputs()
{
    const auto &state = sApp->crosscheck_state;
    assert(state.phase == CrossCheckState::Phase::Running);
    bool any_outputs = !state.init_outputs.empty();
    for (const auto &outputs : state.worker_outputs)
        any_outputs |= outputs && !outputs->empty();
    if (!any_outputs)
        return VerificationResult::Complete;
    struct Participant { int thread; const OutputMap *outputs; };
    std::vector<Participant> participants;
    bool failed = sApp->main_thread_data()->has_failed();
    for (size_t worker = 0; worker < state.worker_outputs.size(); ++worker) {
        auto *thread = sApp->test_thread_data(int(worker));
        failed |= thread->has_failed();
        if (thread->thread_state.load(std::memory_order_relaxed) == thread_succeeded)
            participants.push_back({int(worker), state.worker_outputs[worker].get()});
    }
    // Freeze eligibility before reporting: a mismatch for one name must not remove
    // a participant's vote for other names. Init cannot rescue an all-skipped run.
    if (participants.empty())
        return failed ? VerificationResult::Failed : VerificationResult::Complete;
    if (!state.init_outputs.empty())
        participants.push_back({-1, &state.init_outputs});

    std::set<std::string_view> names;
    for (const auto &participant : participants) {
        if (participant.outputs) {
            for (const auto &[name, slot] : *participant.outputs)
                names.insert(name);
        }
    }
    bool invalid = false;
    bool insufficient = false;
    for (auto name : names) {
        std::vector<const CapturedSlot *> slots;
        std::vector<int> owners;
        bool valid = true;
        for (const auto &participant : participants) {
            const CapturedSlot *slot = nullptr;
            if (participant.outputs) {
                auto it = participant.outputs->find(name);
                if (it != participant.outputs->end())
                    slot = &it->second;
            }
            if (!slot && participant.thread == -1)
                continue; // init opts in per name
            if (!slot) {
                log_message_preformatted(participant.thread, LOG_LEVEL_QUIET,
                        stdprintf("E> Cross-check output '%.*s': worker did not submit output",
                                  int(name.size()), name.data()));
                valid = false;
                continue;
            }
            if (!slots.empty() && (slot->type_token != slots.front()->type_token
                                  || slot->count != slots.front()->count)) {
                log_message_preformatted(participant.thread, LOG_LEVEL_QUIET,
                        stdprintf("E> Cross-check output '%.*s': element type or count mismatch",
                                  int(name.size()), name.data()));
                valid = false;
            }
            slots.push_back(slot);
            owners.push_back(participant.thread);
        }
        if (!valid) {
            invalid = true;
            continue;
        }
        if (slots.size() < 2) {
            insufficient = true;
            continue;
        }
        const CapturedSlot *majority = find_majority(slots);
        for (size_t i = 0; i < slots.size(); ++i) {
            const CapturedSlot *expected = majority;
            if (!expected) {
                // Every producer in an unresolved disagreement has a real failed
                // comparison, but no group is labeled correct.
                for (const auto *other : slots) {
                    if (compare_output(*slots[i], other) == OutputMatch::DataMismatch) {
                        expected = other;
                        break;
                    }
                }
            }
            if (!expected || compare_output(*expected, slots[i]) == OutputMatch::Equal)
                continue;
            std::string description = stdprintf("Cross-check output '%.*s' (%s), %s",
                    int(name.size()), name.data(), slots[i]->description.c_str(),
                    majority ? "first submission vs strict majority"
                             : "no strict majority; conflicting producers implicated");
            if (owners[i] < 0)
                description += stdprintf("; init on logical processor %d", slots[i]->cpu);
            logging_report_crosscheck_failure(owners[i], LogicalProcessor(slots[i]->cpu),
                                             description, expected, slots[i]);
            failed = true;
        }
    }
    if (failed)
        return VerificationResult::Failed;
    if (invalid)
        return VerificationResult::Invalid;
    return insufficient ? VerificationResult::Insufficient : VerificationResult::Complete;
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
