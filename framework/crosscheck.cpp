/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck.h"
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

static void require_context(const char *name)
{
    if (sApp->is_main_process()
            && sApp->current_fork_mode() != SandstoneApplication::ForkMode::no_fork)
        invalid_operation("cross-check APIs require process-local test execution");
    if (!current_test())
        invalid_operation("cross-check APIs require a running test");
    if (!name || !*name)
        invalid_operation("cross-check keys require a nonempty name");
}

CrossCheckState &input_state_for_set(const char *name)
{
    CrossCheckState &state = sApp->crosscheck_state;
    require_context(name);
    if (sApp->test_phase != SandstoneApplication::TestPhase::Init)
        invalid_operation("set_input() must be called from test_init()");
    if (state.inputs.contains(name))
        invalid_operation("input name already set in this attempt");
    return state;
}

const CapturedSlot &lookup_input(const char *name, const void *type_token)
{
    const CrossCheckState &state = sApp->crosscheck_state;
    require_context(name);
    if (sApp->test_phase != SandstoneApplication::TestPhase::Init
            && sApp->test_phase != SandstoneApplication::TestPhase::Run
            && sApp->test_phase != SandstoneApplication::TestPhase::Cleanup)
        invalid_operation("get_input() must be called from test_init(), test_run(), or test_cleanup()");
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
    bool is_init = sApp->test_phase == SandstoneApplication::TestPhase::Init;
    if (!is_init && !(sApp->test_phase == SandstoneApplication::TestPhase::Run && thread_num >= 0))
        invalid_operation("submit_output() must be called from test_init() or test_run()");
    auto cpu = LogicalProcessor(sched_getcpu());
    if (cpu == LogicalProcessor::None)
        invalid_operation("cannot observe submission CPU");
    size_t owner;
#ifdef SANDSTONE_DEVICE_CPU
    for (owner = 0; owner < size_t(device_count()); ++owner) {
        if (LogicalProcessor(device_info[owner].cpu_number) == cpu)
            break;
    }
    if (owner == size_t(device_count()))
        invalid_operation("submission CPU is outside the selected slice");
#else
    if (is_init)
        invalid_operation("accelerator init may not submit outputs");
    owner = size_t(thread_num);
    if (owner >= size_t(device_count()))
        invalid_operation("worker has no assigned output device");
#endif
    return sApp->crosscheck_state.output_submission(owner, name, is_init ? -1 : thread_num, cpu);
}

static std::string owner_description(size_t owner)
{
    const auto &info = device_info[owner];
#if defined(SANDSTONE_DEVICE_CPU)
    return stdprintf("logical processor %d", info.cpu_number);
#elif defined(SANDSTONE_DEVICE_GPU)
    return stdprintf("GPU %d endpoint %d tile %d (PCI %04x:%02x:%02x.%x)", info.gpu_number,
                     info.device_index, info.subdevice_index, unsigned(info.bdf.domain),
                     unsigned(info.bdf.bus), unsigned(info.bdf.device), unsigned(info.bdf.function));
#elif defined(SANDSTONE_DEVICE_IDXD)
    return stdprintf("IDXD device %d WQ %d (PCI %04x:%02x:%02x.%x)", info.device_id, info.wq_id,
                     unsigned(info.bdf.domain), unsigned(info.bdf.bus),
                     unsigned(info.bdf.device), unsigned(info.bdf.function));
#endif
}

static void record_owner_failure(size_t owner)
{
    sApp->crosscheck_failures[owner].store(true, std::memory_order_relaxed);
}

static std::string format_crosscheck_mismatch(const std::map<std::string, YamlFormatter::SimpleValue> &values)
{
    // The mismatch formatter treats everything after the headline as YAML details.
    return "Cross-check output mismatch\n" + format_yaml(values);
}

void check_output_submission(const OutputSubmission &submission, const void *actual, OutputMatch match)
{
    if (match == OutputMatch::TypeMismatch)
        invalid_operation("output element type mismatch");
    if (match == OutputMatch::CountMismatch)
        invalid_operation("later output submission count mismatch");
    const auto &expected = submission.snapshot();
    record_owner_failure(submission.owner);
    auto *thread = sApp->thread_data(thread_num);
    thread->thread_flags |= uint32_t(PerThreadData::Common::Flag::CrossCheckFailure)
            | uint32_t(PerThreadData::Common::Flag::CrossCheckReporting);
    std::string description = format_crosscheck_mismatch({
        { "output", submission.name },
        { "owner", owner_description(submission.owner) },
        { "host_cpu", int(submission.cpu) },
        { "comparison", std::string_view("later submission vs first submission") },
        { "reference_owner", owner_description(submission.owner) },
        { "reference_host_cpu", int(expected.cpu) },
        { "first_description", expected.description },
    });
    _memcmp_fail_report(actual, expected.storage.get(), expected.bytes().size(), expected.type,
                        "%s", description.c_str());
}

VerificationResult verify_outputs()
{
    const auto &state = sApp->crosscheck_state;
    assert(sApp->test_phase == SandstoneApplication::TestPhase::Framework);
    if (sApp->main_thread_data()->has_failed())
        return VerificationResult::Failed;
    bool any_successful_worker = false;
    for (int worker = 0; worker < sApp->thread_count; ++worker) {
        auto *thread = sApp->test_thread_data(worker);
        if (thread->has_failed())
            return VerificationResult::Failed;
        if (thread->thread_state.load(std::memory_order_relaxed) == thread_succeeded)
            any_successful_worker = true;
    }
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
                    record_owner_failure(vote.owner);
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
        size_t published_owners = 0;
        for (const auto &group : result.groups)
            published_owners += group.size();
        if (published_owners == 1)
            log_info("Cross-check output '%s': one published owner; no cross-owner comparison",
                     result.name.data());
        if (result.groups.size() < 2)
            continue;
        std::string membership;
        for (size_t group = 0; group < result.groups.size(); ++group) {
            membership += stdprintf("; group %zu:", group);
            for (const auto &vote : result.groups[group])
                membership += " [" + owner_description(vote.owner) + "]";
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
                    { "owner", owner_description(vote.owner) },
                    { "host_cpu", int(vote.slot->cpu) },
                    { "group", uint64_t(group) },
                    { "comparison", std::string_view(result.majority_group >= 0
                            ? "strict majority baseline (not proven correct)"
                            : "no strict majority; conflicting peer") },
                    { "reference_owner", owner_description(reference.owner) },
                    { "reference_host_cpu", int(reference.slot->cpu) },
                    { "reference_group", uint64_t(reference_group) },
                    { "groups", membership },
                    { "first_description", vote.slot->description },
                });
                logging_report_crosscheck_failure(vote.slot->first_worker, description, reference.slot, vote.slot);
                has_data_mismatch = true;
            }
        }
    }
    if (has_data_mismatch)
        return VerificationResult::Failed;
    return has_incompatible_outputs ? VerificationResult::Invalid : VerificationResult::Complete;
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
