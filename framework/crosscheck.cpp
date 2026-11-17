/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck.h"
#include "logging.h"
#include "sandstone_p.h"

#include <cstdlib>
#include <sched.h>
#include <string>
#include <vector>

namespace SandstoneCrossCheck {

void invalid_operation(const char *reason)
{
    if (sApp->is_child_process()) {
        log_message_preformatted(thread_num, LOG_LEVEL_QUIET,
                stdprintf(SANDSTONE_LOG_ERROR "Cross-check invalid execution: %s", reason));
    } else {
        logging_printf(LOG_LEVEL_QUIET, "# Cross-check invalid execution: %s\n", reason);
    }
    abort();
}

static void require_context([[maybe_unused]] const char *name)
{
#ifndef NDEBUG
    if (sApp->is_main_process()
            && sApp->current_fork_mode() != SandstoneApplication::ForkMode::no_fork)
        invalid_operation("cross-check APIs require process-local test execution");
    assert(current_test());
    assert(name && *name);
#endif
}

CrossCheckState &input_state_for_set(const char *name)
{
    CrossCheckState &state = sApp->crosscheck_state;
    require_context(name);
    assert(sApp->test_phase == SandstoneApplication::TestPhase::Init);
    if (state.inputs.contains(name))
        invalid_operation("input name already set in this attempt");
    return state;
}

const CapturedSlot &lookup_input(const char *name, const void *type_token)
{
    const CrossCheckState &state = sApp->crosscheck_state;
    require_context(name);
    assert(sApp->test_phase == SandstoneApplication::TestPhase::Init
            || sApp->test_phase == SandstoneApplication::TestPhase::Run
            || sApp->test_phase == SandstoneApplication::TestPhase::Cleanup);
    auto it = state.inputs.find(name);
    if (it == state.inputs.end())
        invalid_operation("input was not set in this attempt");
    if (it->second.type_token != type_token)
        invalid_operation("input key has a different element type");
    return it->second;
}

OutputSubmission output_state_for_submission(const char *name)
{
    require_context(name);
    [[maybe_unused]] bool is_init = sApp->test_phase == SandstoneApplication::TestPhase::Init;
    assert(is_init || (sApp->test_phase == SandstoneApplication::TestPhase::Run && thread_num >= 0));
    size_t thread = is_init ? 0 : size_t(thread_num);
    auto submission = sApp->crosscheck_state.output_submission(thread, name, thread_num,
                                                               LogicalProcessor::None);
    if (!submission.reference)
        submission.cpu = LogicalProcessor(sched_getcpu());
    return submission;
}

static int current_device([[maybe_unused]] LogicalProcessor cpu)
{
#ifdef SANDSTONE_DEVICE_CPU
    for (int device = 0; device < device_count(); ++device) {
        if (LogicalProcessor(device_info[device].cpu_number) == cpu)
            return device;
    }
    invalid_operation("completion or mismatch CPU is outside the selected slice");
#else
    // Accelerator workers retain their assigned endpoint/tile or WQ identity.
    assert(thread_num < device_count());
    return thread_num < 0 ? 0 : thread_num;
#endif
}

void finish_thread()
{
    auto &outputs = sApp->crosscheck_state.thread_outputs[thread_num];
    if (outputs.snapshots.empty())
        return;
    outputs.completion_cpu = LogicalProcessor(sched_getcpu());
    outputs.completion_device = current_device(outputs.completion_cpu);
}

static std::string device_description([[maybe_unused]] int device)
{
#if SANDSTONE_NO_LOGGING
    return {};
#else
    return AbstractLogger::thread_id_header_for_device(device, LOG_LEVEL_VERBOSE(2));
#endif
}

static int thread_device(size_t thread)
{
    const auto &outputs = sApp->crosscheck_state.thread_outputs[thread];
    assert(outputs.completion_device >= 0);
    return outputs.completion_device;
}

static LogicalProcessor thread_cpu(size_t thread)
{
    const auto &outputs = sApp->crosscheck_state.thread_outputs[thread];
    assert(outputs.completion_device >= 0);
    return outputs.completion_cpu;
}

static std::string thread_description(size_t thread)
{
    return stdprintf("thread %zu: ", thread) + device_description(thread_device(thread));
}

static std::string format_crosscheck_mismatch(const std::map<std::string, YamlFormatter::SimpleValue> &values)
{
    // The mismatch formatter treats everything after the headline as YAML details.
    return "Cross-check output mismatch\n" + format_yaml(values);
}

void check_output_submission(const OutputSubmission &submission, const void *actual)
{
    const auto &expected = submission.snapshot();
    auto cpu = LogicalProcessor(sched_getcpu());
    bool is_init = sApp->test_phase == SandstoneApplication::TestPhase::Init;
    int device = current_device(cpu);
    if (is_init)
        sApp->crosscheck_failures[device] = true;
    else
        submission.outputs->mismatch_device = device;
    auto *thread = sApp->thread_data(thread_num);
    thread->thread_flags |= uint32_t(PerThreadData::Common::Flag::CrossCheckFailure)
            | uint32_t(PerThreadData::Common::Flag::CrossCheckReporting);
    std::string description = format_crosscheck_mismatch({
        { "output", submission.name },
        { "thread", uint64_t(submission.thread_index) },
        { "first_submission_thread", expected.first_worker },
        { "device_description", device_description(device) },
        { "host_cpu", int(cpu) },
        { "placement_description", std::string_view("mismatch detection/submission placement") },
        { "comparison_description", std::string_view("later submission vs first submission") },
        { "reference_device_description", device_description(device) },
        { "reference_host_cpu", int(expected.cpu) },
        { "reference_placement_description", std::string_view("first submission host CPU is reporting metadata only") },
        { "first_submission_host_cpu", int(expected.cpu) },
        { "first_description", expected.description },
    });
    _memcmp_fail_report(actual, expected.storage.get(), expected.bytes().size(), expected.type,
                        "%s", description.c_str());
}

VerificationResult verify_outputs()
{
    const auto &state = sApp->crosscheck_state;
    assert(sApp->test_phase == SandstoneApplication::TestPhase::Framework);
    bool preexisting_failure = sApp->main_thread_data()->has_failed();
    bool any_successful_worker = false;
    for (int worker = 0; worker < sApp->thread_count; ++worker) {
        auto *thread = sApp->test_thread_data(worker);
        const auto &outputs = state.thread_outputs[worker];
        if (outputs.mismatch_device >= 0)
            sApp->crosscheck_failures[outputs.mismatch_device] = true;
        preexisting_failure |= thread->has_failed();
        if (thread->thread_state.load(std::memory_order_relaxed) == thread_succeeded)
            any_successful_worker = true;
    }
    if (preexisting_failure)
        return VerificationResult::Failed;
    if (!any_successful_worker)
        return VerificationResult::Complete;
    // Classification of every name precedes reporting, which changes worker outcomes.
    const auto conclusions = state.classify_outputs();
    // Persist attribution before a callback can interrupt reporting a later name.
    for (const auto &result : conclusions) {
        if (result.has_type_or_count_mismatch || result.groups.size() < 2)
            continue;
        if (result.majority_group < 0)
            sApp->main_thread_data()->thread_flags |= uint32_t(PerThreadData::Common::Flag::CrossCheckNoMajority);
        for (size_t group = 0; group < result.groups.size(); ++group) {
            if (int(group) != result.majority_group) {
                for (const auto &vote : result.groups[group])
                    sApp->crosscheck_failures[thread_device(vote.thread)] = true;
            }
        }
    }
    bool has_data_mismatch = false;
    bool has_incompatible_outputs = false;
    for (const auto &result : conclusions) {
        if (result.has_type_or_count_mismatch) {
            has_incompatible_outputs = true;
            log_message_preformatted(result.groups.front().front().slot->first_worker, LOG_LEVEL_QUIET,
                    "E> Cross-check output '" + std::string(result.name) + "': element type or count mismatch");
            continue;
        }
        size_t submitted_threads = 0;
        for (const auto &group : result.groups)
            submitted_threads += group.size();
        if (submitted_threads == 1)
            log_info("Cross-check output '%s': one test thread submitted; no deferred comparison",
                     result.name.data());
        if (result.groups.size() < 2)
            continue;
        std::string membership;
        for (size_t group = 0; group < result.groups.size(); ++group) {
            membership += stdprintf("; value class %zu:", group);
            for (const auto &vote : result.groups[group])
                membership += " [" + thread_description(vote.thread) + "]";
        }
        for (size_t group = 0; group < result.groups.size(); ++group) {
            if (int(group) == result.majority_group)
                continue;
            size_t reference_group = result.majority_group >= 0
                    ? size_t(result.majority_group) : (group == 0 ? 1 : 0);
            const auto &reference = result.groups[reference_group].front();
            for (const auto &vote : result.groups[group]) {
                std::string description = format_crosscheck_mismatch({
                    { "output", result.name },
                    { "thread", uint64_t(vote.thread) },
                    { "first_submission_thread", vote.slot->first_worker },
                    { "device_description", device_description(thread_device(vote.thread)) },
                    { "host_cpu", int(thread_cpu(vote.thread)) },
                    { "placement_description", std::string_view("test thread completion CPU/device") },
                    { "first_submission_host_cpu", int(vote.slot->cpu) },
                    { "value_class", uint64_t(group) },
                    { "comparison_description", std::string_view(result.majority_group >= 0
                            ? "strict majority baseline (not proven correct)"
                            : "no strict majority; conflicting peer") },
                    { "reference_device_description", device_description(thread_device(reference.thread)) },
                    { "reference_thread", uint64_t(reference.thread) },
                    { "reference_host_cpu", int(thread_cpu(reference.thread)) },
                    { "reference_first_submission_host_cpu", int(reference.slot->cpu) },
                    { "reference_value_class", uint64_t(reference_group) },
                    { "value_classes_description", membership },
                    { "first_description", vote.slot->description },
                });
                logging_report_crosscheck_failure(vote.slot->first_worker, description, reference.slot,
                                                   vote.slot, thread_cpu(vote.thread));
                has_data_mismatch = true;
            }
        }
    }
    if (has_data_mismatch)
        return VerificationResult::Failed;
    return has_incompatible_outputs ? VerificationResult::Invalid : VerificationResult::Complete;
}

} // namespace SandstoneCrossCheck
