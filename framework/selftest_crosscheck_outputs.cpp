/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck.h"
#include "selftest_crosscheck_outputs.h"
#include "sandstone_p.h"

#include <array>
#include <bit>
#include <cerrno>
#include <cinttypes>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <limits>
#include <sched.h>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "fp_vectors/Floats.h"

namespace {
CROSSCHECK_INPUT(output_numbers, uint32_t);
CROSSCHECK_OUTPUT(output_words, uint32_t);
CROSSCHECK_OUTPUT(output_flags, bool);
CROSSCHECK_OUTPUT(output_empty, uint32_t);
CROSSCHECK_OUTPUT(output_wrapper, Float32);
CROSSCHECK_OUTPUT(output_wrapper64, Float64);
CROSSCHECK_INPUT(output_label, char);
CROSSCHECK_OUTPUT(output_text, char);
CROSSCHECK_OUTPUT(output_float, float);
CROSSCHECK_OUTPUT(output_long_double, long double);
CROSSCHECK_OUTPUT(consensus_a, uint32_t);
CROSSCHECK_OUTPUT(consensus_z, uint32_t);
uint32_t output_generation = 0;
int64_t incomplete_slice = 0;
int64_t fail_slice = -1;
int64_t skip_worker = 1;
int64_t skip_mask = -1;
int64_t outlier_worker = -1;
bool skip_after_submission = false;
bool skip_return = true;
bool resource_skip = false;
bool unknown_invalid_pointer = false;
bool unknown_invalid_count = false;
bool ordered_merge = false;
std::weak_ptr<const void> previous_golden;
std::weak_ptr<const void> previous_consensus;
std::weak_ptr<const void> previous_vote;

bool output_case(const test *test, std::string_view suffix)
{
    return std::string_view(test->id).ends_with(suffix);
}

bool consensus_worker_skips(int thread)
{
    if (skip_mask < 0)
        return thread == skip_worker;
    return thread < 63 && (uint64_t(skip_mask) & (uint64_t(1) << thread));
}

std::array<uint32_t, 2> compute_words()
{
    auto input = get_input(output_numbers);
    return {input[0] + input[1], input[0] * input[1]};
}

void output_failure_callback(void *)
{
    log_info("output failure callback fired");
}

[[maybe_unused]] void output_callback_cleanup(void *)
{
    const auto &state = sApp->crosscheck_state;
    if (!previous_golden.expired() || !previous_consensus.expired() || !previous_vote.expired()
            || !state.inputs.empty() || !state.init_outputs.empty()
            || !state.worker_outputs.empty()
            || state.phase != SandstoneCrossCheck::CrossCheckState::Phase::Inactive)
        report_fail_msg("Cross-check storage survived callback cleanup");
    log_info("output callback cleanup released storage");
}

constexpr size_t LONG_DOUBLE_MEANINGFUL =
        SandstoneDataDetails::type_real_size(SANDSTONE_LONG_DOUBLE_TYPE);

std::array<long double, 3> long_double_values()
{
    return {0.L, -0.L, 1.25L};
}
} // namespace

namespace {
CROSSCHECK_OUTPUT(vote_a, uint32_t);
CROSSCHECK_OUTPUT(vote_z, uint32_t);
int64_t vote_init, vote_values, vote_skips, vote_failures, vote_later, vote_shape;
bool vote_after, vote_cleanup_skip, vote_two_names, vote_reschedule, vote_retry;
}

int selftest_crosscheck_votes_init(struct test *test)
{
    if (!previous_vote.expired())
        report_fail_msg("Vote snapshots survived the previous execution");
    vote_init = get_testspecific_knob_value_int(test, "init", -1);
    vote_values = get_testspecific_knob_value_int(test, "values", 0);
    vote_skips = get_testspecific_knob_value_int(test, "skips", 0);
    vote_failures = get_testspecific_knob_value_int(test, "failures", 0);
    vote_later = get_testspecific_knob_value_int(test, "later", -1);
    vote_shape = get_testspecific_knob_value_int(test, "shape", 0);
    vote_after = get_testspecific_knob_value_int(test, "after", 0);
    vote_cleanup_skip = get_testspecific_knob_value_int(test, "cleanup_skip", 0);
    vote_two_names = get_testspecific_knob_value_int(test, "two_names", 0);
    vote_reschedule = get_testspecific_knob_value_int(test, "reschedule", 0);
    vote_retry = get_testspecific_knob_value_int(test, "retry", 0);
    install_failure_callback(output_failure_callback, nullptr, output_callback_cleanup);
    if (vote_init >= 0) {
        uint32_t value = uint32_t(vote_init);
        submit_output(vote_a, &value, 1, "golden computation in init");
        submit_output(vote_a, &value, 1, "repetition is not another vote");
        log_info("vote init submission CPU %d", sched_getcpu());
        if (vote_two_names)
            submit_output(vote_z, &value, 1, "second golden computation");
        if (vote_later == -2) {
            ++value;
            submit_output(vote_a, &value, 1, nullptr);
        }
    }
    if (get_testspecific_knob_value_int(test, "init_skip", 0)) {
        log_skip(SelftestSkipCategory, "original vote init skip");
        return EXIT_SKIP;
    }
    return EXIT_SUCCESS;
}

int selftest_crosscheck_votes_run(struct test *test, int worker)
{
    bool skipped = worker < 63 && (uint64_t(vote_skips) >> worker & 1);
    bool failed = worker < 63 && (uint64_t(vote_failures) >> worker & 1);
    auto finish = [&] {
        if (failed)
            return EXIT_FAILURE;
        if (skipped) {
            log_skip(SelftestSkipCategory, "original vote worker skip");
            return EXIT_SKIP;
        }
        return EXIT_SUCCESS;
    };
    if ((skipped || failed) && !vote_after)
        return finish();
    uint32_t value = worker < 32 ? uint32_t(uint64_t(vote_values) >> (2 * worker) & 3) : 0;
    if (vote_retry && test_is_retry())
        value = 0;
    uint32_t values[] = {value, value};
    if (!(vote_shape == 1 && worker == 0)) {
        if (vote_shape == 3 && worker == 0) {
            uint8_t byte = uint8_t(value);
            submit_output(SandstoneCrossCheck::OutputKey<uint8_t>{vote_a.name}, &byte, 1, "wrong type");
        } else {
            submit_output(vote_a, values, vote_shape == 2 && worker == 0 ? 2 : 1, "worker computation");
        }
        log_info("vote worker %d submission CPU %d", worker, sched_getcpu());
    }
    if (vote_two_names) {
        uint32_t other = worker == 1 ? 1 : 0;
        submit_output(vote_z, &other, 1, "second worker computation");
    }
    if (worker == vote_later) {
        ++values[0];
        submit_output(vote_a, values, 1, nullptr);
    }
    if (vote_reschedule)
        reschedule();
    return finish();
}

int selftest_crosscheck_votes_cleanup(struct test *)
{
    const auto &state = sApp->crosscheck_state;
    for (const auto &outputs : state.worker_outputs) {
        if (outputs && !outputs->empty())
            previous_vote = outputs->begin()->second.storage;
    }
    for (size_t worker = 0; worker < state.worker_outputs.size(); ++worker) {
        log_info("vote worker %zu final state %d", worker,
                 int(sApp->test_thread_data(int(worker))->thread_state.load(std::memory_order_relaxed)));
    }
    log_info("vote cleanup retained snapshots");
    if (vote_cleanup_skip) {
        log_skip(SelftestSkipCategory, "vote cleanup requested skip");
        return EXIT_SKIP;
    }
    return EXIT_SUCCESS;
}

int selftest_crosscheck_outputs_init(struct test *test)
{
    if (output_case(test, "_missing_golden")) {
        unknown_invalid_pointer = get_testspecific_knob_value_int(test, "invalid_pointer", 0);
        unknown_invalid_count = get_testspecific_knob_value_int(test, "invalid_count", 0);
    }
    if (output_case(test, "_mixed_structural"))
        ordered_merge = get_testspecific_knob_value_int(test, "ordered_merge", 0);
    if (output_case(test, "_consensus_only_skip_diagnostic")) {
        skip_worker = get_testspecific_knob_value_int(test, "skip_worker", 1);
        skip_mask = -1;
        skip_after_submission = get_testspecific_knob_value_int(test, "after_submission", 0);
        skip_return = get_testspecific_knob_value_int(test, "return_skip", 1);
        outlier_worker = get_testspecific_knob_value_int(test, "mismatch", 0) ? 2 : -1;
        resource_skip = false;
    }
    if (output_case(test, "_consensus_only_states")) {
        // Bits select skipped workers; zero selects complete consensus.
        skip_mask = get_testspecific_knob_value_int(test, "skip_mask", 1);
        skip_after_submission = get_testspecific_knob_value_int(test, "after_submission", 0);
        skip_return = get_testspecific_knob_value_int(test, "return_skip", 1);
        outlier_worker = get_testspecific_knob_value_int(test, "outlier_worker", -1);
        resource_skip = true;
        ordered_merge = get_testspecific_knob_value_int(test, "ordered_merge", 0);
    }
    if (output_case(test, "_consensus_mixed_slice")) {
        incomplete_slice = get_testspecific_knob_value_int(test, "incomplete_slice", 0);
        fail_slice = get_testspecific_knob_value_int(test, "fail_slice", -1);
    }
    if (!previous_golden.expired() || !previous_consensus.expired())
        report_fail_msg("Cross-check output storage survived the previous pass");
    if (std::string_view(test->id).find("_consensus_") != std::string_view::npos) {
        install_failure_callback(output_failure_callback, nullptr, output_callback_cleanup);
        if (output_case(test, "_consensus_only_skip_init")) {
            log_skip(SelftestSkipCategory, "Consensus init opted out before verification activation");
            return EXIT_SKIP;
        }
        if (output_case(test, "_consensus_input_only")) {
            const uint32_t value = 42;
            set_input(output_numbers, &value, 1);
        }
        return EXIT_SUCCESS;
    }
    if (output_case(test, "_padding_pass") || output_case(test, "_padding_fail")) {
        if constexpr (LONG_DOUBLE_MEANINGFUL == sizeof(long double)) {
            log_skip(SelftestSkipCategory, "Requires trailing long double padding");
            return EXIT_SKIP;
        }
    }
    std::vector<uint32_t> source = {++output_generation, 5};
    if (output_case(test, "_c_golden_pass"))
        selftest_crosscheck_outputs_c_input(output_generation);
    else
        set_input(output_numbers, source, "owned output computation inputs");
    source.assign(2, 0);
    auto words = compute_words();
    std::string description = "authoritative golden words";
    const bool flags[] = {true, false};
    if (output_case(test, "_c_pass") || output_case(test, "_c_golden_pass")
            || output_case(test, "_c_bad_first") || output_case(test, "_c_bad_later")
            || output_case(test, "_c_golden_count") || output_case(test, "_c_later_count")) {
        selftest_crosscheck_outputs_c_golden();
    } else {
        submit_output(output_words, words, description.c_str());
        submit_output(output_flags, flags, nullptr);
        submit_output(output_empty, static_cast<const uint32_t *>(nullptr), 0, nullptr);
    }
    words.fill(0);
    description.assign("destroyed golden description");
    previous_golden = sApp->crosscheck_state.init_outputs.at(output_words.name).storage;
    if (output_case(test, "_mixed_structural") && ordered_merge) {
        submit_output(SandstoneCrossCheck::OutputKey<uint32_t>{"output_z"}, compute_words(), "last mismatch");
        submit_output(SandstoneCrossCheck::OutputKey<uint32_t>{"output_zz"}, compute_words(), "last missing");
    }
    if (!output_case(test, "_parent_skip_init"))
        install_failure_callback(output_failure_callback, nullptr, output_callback_cleanup);
    if (output_case(test, "_duplicate")) {
        words = compute_words();
        submit_output(output_words, words, nullptr);
    }
    if (output_case(test, "_invalid_pointer") && !output_case(test, "_worker_invalid_pointer")) {
        CROSSCHECK_OUTPUT(invalid_output, uint32_t);
        submit_output(invalid_output, static_cast<const uint32_t *>(nullptr), 1, nullptr);
    }
    if (output_case(test, "_invalid_count") && !output_case(test, "_worker_invalid_count")) {
        CROSSCHECK_OUTPUT(invalid_output, uint32_t);
        submit_output(invalid_output, words.data(), std::numeric_limits<size_t>::max(), nullptr);
    }
    if (output_case(test, "_wrapper_pass") || output_case(test, "_wrapper_conflict")) {
        const Float32 values[] = {Float32(1.0f), Float32(-0.0f)};
        submit_output(output_wrapper, values, nullptr);
        const Float64 wide[] = {Float64(1.0), Float64(-0.0)};
        submit_output(output_wrapper64, wide, nullptr);
    }
    if (output_case(test, "_containers_pass")) {
        set_input(output_label, std::string("cross check string"));
        auto label = get_input(output_label);
        submit_output(output_text, std::string(label.begin(), label.end()), "golden text");
    }
    if (output_case(test, "_nan_pass") || output_case(test, "_nan_fail")
            || output_case(test, "_zero_fail")) {
        const std::array<uint32_t, 3> bits = {0, 0x7fc12345, 0x80000000};
        const auto values = std::bit_cast<std::array<float, 3>>(bits);
        submit_output(output_float, values, "golden floating bits");
    }
    if (output_case(test, "_padding_pass") || output_case(test, "_padding_fail")) {
        auto values = long_double_values();
        log_info("output padded mismatch byte offset %zu", 2 * sizeof(long double));
        for (auto &value : values)
            std::memset(reinterpret_cast<unsigned char *>(&value) + LONG_DOUBLE_MEANINGFUL,
                        0xa5, sizeof(value) - LONG_DOUBLE_MEANINGFUL);
        submit_output(output_long_double, values, "golden padded array");
    }
    log_info("output init generation %" PRIu32, output_generation);
    if (output_case(test, "_skip_init") || output_case(test, "_parent_skip_init")) {
        log_skip(SelftestSkipCategory, "Skip after golden output submission");
        return EXIT_SKIP;
    }
    if (output_case(test, "_error_init"))
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

int selftest_crosscheck_outputs_run(struct test *test, int thread)
{
    if (std::string_view(test->id).find("_consensus_") != std::string_view::npos) {
        if (output_case(test, "_consensus_empty") || output_case(test, "_consensus_input_only"))
            return EXIT_SUCCESS;
        if (output_case(test, "_consensus_zero_length")) {
            submit_output(consensus_a, static_cast<const uint32_t *>(nullptr), 0, nullptr);
            return EXIT_SUCCESS;
        }
        const bool states = output_case(test, "_consensus_only_states");
        const bool skip_diagnostic = states || output_case(test, "_consensus_only_skip_diagnostic");
        auto explicit_skip = [] {
            if (resource_skip)
                log_skip(TestResourceIssueSkipCategory, "synthetic consensus worker resource unavailable");
            else
                log_skip(SelftestSkipCategory, "original consensus worker explicit skip");
            return skip_return ? EXIT_SKIP : EXIT_SUCCESS;
        };
        if (skip_diagnostic && consensus_worker_skips(thread) && !skip_after_submission)
            return explicit_skip();
        if (states && ordered_merge) {
            const uint32_t value = uint32_t(thread != 0);
            const char *reference_names[] = {"j_ref", "h_shared", "f_ref", "d_shared", "b_ref"};
            const char *peer_names[] = {"h_shared", "e_extra", "d_shared", "c_extra", "a_extra"};
            auto names = thread == 0 ? std::span<const char *>(reference_names) : std::span<const char *>(peer_names);
            if (thread == 1)
                submit_output(SandstoneCrossCheck::OutputKey<uint32_t>{"k_extra"}, &value, 1, nullptr);
            for (const char *name : names)
                submit_output(SandstoneCrossCheck::OutputKey<uint32_t>{name}, &value, 1, "merge metadata");
            if (thread != 0 && consensus_worker_skips(thread)) {
                submit_output(SandstoneCrossCheck::OutputKey<uint32_t>{"g_skipped_extra"}, &value, 1, nullptr);
                return explicit_skip();
            }
            if (consensus_worker_skips(thread))
                return explicit_skip();
            return EXIT_SUCCESS;
        }
        if (thread == 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        int exiting_worker = std::string_view(test->id).find("_reference_") != std::string_view::npos ? 0 : 1;
        if (thread == exiting_worker) {
            if (output_case(test, "_consensus_mixed_slice")
                    && sApp->main_thread_data()->thread_range.starting_thread / 2 ==
                    incomplete_slice) {
                log_skip(SelftestSkipCategory, "original consensus slice worker skip");
                return EXIT_SKIP;
            }
            if (output_case(test, "_skip"))
                return EXIT_SKIP;
            if (output_case(test, "_error")) {
                log_error("original consensus worker error");
                return EXIT_SUCCESS;
            }
            if (output_case(test, "_noreturn") || output_case(test, "_sequential_exit"))
                report_fail_msg("original consensus worker noreturn");
        }
        uint32_t values[] = {17, 23};
        if (skip_diagnostic && thread == outlier_worker)
            ++values[0];
        if (std::string_view(test->id).find("_consensus_only_reference_") != std::string_view::npos)
            values[0] += thread;
        if (output_case(test, "_slice")) {
            values[0] = uint32_t(device_info[0].cpu_number);
            log_info("consensus slice reference %u", values[0]);
        }
        if ((output_case(test, "_zero_outlier") && thread == 0)
                || (output_case(test, "_single") && thread == 1))
            ++values[0];
        if (output_case(test, "_distinct"))
            values[0] += thread;
        if (!(output_case(test, "_consensus_missing") && thread == 1)
                && !(output_case(test, "_reference_missing") && thread == 0)) {
            submit_output(consensus_z, values, "worker z metadata");
            if (output_case(test, "_type") && thread == 1) {
                SandstoneCrossCheck::OutputKey<uint8_t> tag{consensus_a.name};
                const uint8_t bytes[] = {17, 23};
                submit_output(tag, bytes, 2, "different type");
            } else {
                submit_output(consensus_a, values, output_case(test, "_count") && thread == 1 ? 1 : 2,
                              "worker a metadata");
            }
            if (thread == 0)
                previous_consensus = sApp->crosscheck_state.worker_outputs[0]->at(consensus_a.name).storage;
            if (!output_case(test, "_count") && !output_case(test, "_type")) {
                submit_output(consensus_a, values, "ignored later metadata");
                if (output_case(test, "_consensus_mixed_slice") && thread == 0
                        && sApp->main_thread_data()->thread_range.starting_thread / 2 == fail_slice) {
                    ++values[0];
                    submit_output(consensus_a, values, nullptr);
                }
                if (output_case(test, "_later")) {
                    ++values[0];
                    submit_output(consensus_a, values, nullptr);
                }
            }
        }
        if (output_case(test, "_distinct"))
            reschedule();
        if (skip_diagnostic) {
            if (states)
                log_info("consensus fixture worker %d submitted %u,%u", thread, values[0], values[1]);
            if (consensus_worker_skips(thread))
                return explicit_skip();
        }
        log_info("consensus completion CPU %d", sched_getcpu());
        return EXIT_SUCCESS;
    }
    if (output_case(test, "_fail_return"))
        return EXIT_FAILURE;
    if (output_case(test, "_skip_return"))
        return EXIT_SKIP;
    if (output_case(test, "_negative_return")) {
        log_info("original output negative return");
        return -EIO;
    }
    if (output_case(test, "_fail_flag") && !output_case(test, "_bad_first_fail_flag")) {
        log_error("original output failure flag");
        return EXIT_SUCCESS;
    }
    if (output_case(test, "_skip_flag") && !output_case(test, "_bad_first_skip_flag")) {
        log_skip(SelftestSkipCategory, "original output skip flag");
        return EXIT_SUCCESS;
    }
    if (output_case(test, "_noreturn"))
        report_fail_msg("original output noreturn failure");
    if (output_case(test, "_missing_all"))
        return EXIT_SUCCESS;
    if (output_case(test, "_missing_golden")) {
        CROSSCHECK_OUTPUT(unreferenced_output, uint32_t);
        const uint32_t value = 1;
        const auto *data = unknown_invalid_pointer ? nullptr : &value;
        size_t count = unknown_invalid_count ? std::numeric_limits<size_t>::max() : 1;
        submit_output(unreferenced_output, data, count, nullptr);
    }
    if (output_case(test, "_c_conflict"))
        selftest_crosscheck_outputs_c_conflict();
    if (output_case(test, "_worker_invalid_pointer"))
        submit_output(output_words, static_cast<const uint32_t *>(nullptr), 1, nullptr);
    if (output_case(test, "_worker_invalid_count")) {
        const auto words = compute_words();
        submit_output(output_words, words.data(), std::numeric_limits<size_t>::max(), nullptr);
    }
    if (output_case(test, "_c_pass") || output_case(test, "_c_bad_first")
            || output_case(test, "_c_bad_later") || output_case(test, "_c_golden_count")
            || output_case(test, "_c_later_count"))
        return selftest_crosscheck_outputs_c_run(test, thread);
    auto words = compute_words();
    if (output_case(test, "_mixed_structural") && ordered_merge) {
        submit_output(output_empty, static_cast<const uint32_t *>(nullptr), 0, nullptr);
        ++words[0];
        submit_output(output_words, words, nullptr);
        submit_output(SandstoneCrossCheck::OutputKey<uint32_t>{"output_z"}, words, nullptr);
        // State-level APIs allow extra names; exercise the merge without weakening public policy.
        for (const char *name : {"a_extra", "output_middle_extra", "zz_extra"})
            sApp->crosscheck_state.submit_output(size_t(thread), name, words.data(), words.size(), nullptr);
        return EXIT_SUCCESS;
    }
    if (output_case(test, "_bad_first") || output_case(test, "_bad_first_fail_flag")
            || output_case(test, "_bad_first_skip_flag")
            || output_case(test, "_mixed_structural")
            || ((output_case(test, "_retry") || output_case(test, "_retry_invalid")) && !test_is_retry()))
        ++words[0];
    const bool flags[] = {true, false};
    // Workers deliberately submit names in a different order from test_init().
    if (!output_case(test, "_missing_partial") && !output_case(test, "_mixed_structural")
            && !(output_case(test, "_retry_invalid") && test_is_retry())) {
        if (thread % 2) {
            submit_output(output_flags, flags, "ignored flags");
            submit_output(output_empty, static_cast<const uint32_t *>(nullptr), 0, "ignored empty");
        } else {
            submit_output(output_empty, static_cast<const uint32_t *>(nullptr), 0, "ignored empty");
            submit_output(output_flags, flags, "ignored flags");
        }
    }
    if (output_case(test, "_golden_count")) {
        submit_output(output_words, words.data(), 1, nullptr);
    } else {
        submit_output(output_words, words, nullptr);
        auto repeated = words;
        words.fill(99);
        for (int i = 0; i < 3; ++i)
            submit_output(output_words, std::span<const uint32_t>(repeated), "ignored worker words");
        if (output_case(test, "_later_count"))
            submit_output(output_words, repeated.data(), 1, nullptr);
        if (output_case(test, "_bad_later")) {
            ++repeated[1];
            submit_output(output_words, repeated, nullptr);
        }
    }
    if (output_case(test, "_wrapper_pass") || output_case(test, "_wrapper_conflict"))
        selftest_crosscheck_outputs_cpp_peer(output_case(test, "_wrapper_conflict"));
    if (output_case(test, "_containers_pass")) {
        auto label = get_input(output_label);
        const std::string text(label.begin(), label.end());
        submit_output(output_text, text, nullptr);
        submit_output(output_text, text, "ignored text");
    }
    if (output_case(test, "_nan_pass") || output_case(test, "_nan_fail")
            || output_case(test, "_zero_fail")) {
        std::array<uint32_t, 3> bits = {0, 0x7fc12345, 0x80000000};
        auto values = std::bit_cast<std::array<float, 3>>(bits);
        submit_output(output_float, values, nullptr);
        if (output_case(test, "_nan_fail"))
            bits[1] ^= 1;
        if (output_case(test, "_zero_fail"))
            bits[0] = bits[2];
        values = std::bit_cast<std::array<float, 3>>(bits);
        submit_output(output_float, values, nullptr);
    }
    if (output_case(test, "_padding_pass") || output_case(test, "_padding_fail")) {
        auto values = long_double_values();
        submit_output(output_long_double, values, nullptr);
        for (auto &value : values)
            std::memset(reinterpret_cast<unsigned char *>(&value) + LONG_DOUBLE_MEANINGFUL,
                        0x5a, sizeof(value) - LONG_DOUBLE_MEANINGFUL);
        if (output_case(test, "_padding_fail"))
            reinterpret_cast<unsigned char *>(&values[2])[0] ^= 1;
        submit_output(output_long_double, values, "ignored padding");
    }
    if (output_case(test, "_fracture_pass")) {
        TEST_LOOP(test, 1) {
            const auto actual = compute_words();
            submit_output(output_words, actual, nullptr);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    if (output_case(test, "_sequential_bad_first")) {
        reschedule();
        log_info("output completion CPU %d", sched_getcpu());
    }
    log_info("output post-submit sentinel");
    if (output_case(test, "_bad_first_fail_flag"))
        log_error("original output failure flag after wrong first submission");
    if (output_case(test, "_bad_first_skip_flag")
            && (!output_case(test, "_mixed_bad_first_skip_flag") || thread == 0))
        log_skip(SelftestSkipCategory, "original output skip flag after wrong first submission");
    return EXIT_SUCCESS;
}

int selftest_crosscheck_outputs_cleanup(struct test *test)
{
    if (std::string_view(test->id).find("_consensus_") != std::string_view::npos
            && sApp->main_thread_data()->has_skipped())
        report_fail_msg("Consensus marked the main thread as skipped before cleanup");
    if (output_case(test, "_consensus_skip") && sApp->thread_count > 1
            && sApp->test_thread_data(1)->thread_state.load(std::memory_order_relaxed) != thread_skipped)
        report_fail_msg("Consensus overwrote the worker's original skip state");
    const auto &state = sApp->crosscheck_state;
    if (output_case(test, "_consensus_only_states")) {
        for (size_t worker = 0; worker < state.worker_outputs.size(); ++worker) {
            bool skipped = consensus_worker_skips(int(worker));
            bool submitted = !skipped || skip_after_submission;
            auto *data = sApp->test_thread_data(int(worker));
            bool actually_skipped = data->thread_state.load(std::memory_order_relaxed) == thread_skipped;
            if (actually_skipped != skipped || data->has_skipped() != skipped
                    || bool(state.worker_outputs[worker]) != submitted)
                report_fail_msg("Consensus fixture worker %zu has unexpected completion or submission state", worker);
            log_info("consensus fixture worker %zu: submitted=%d skipped=%d", worker, submitted, actually_skipped);
        }
    }
    if (std::string_view(test->id).find("_consensus_") != std::string_view::npos) {
        if ((!state.inputs.empty() && !output_case(test, "_consensus_input_only"))
                || !state.init_outputs.empty())
            report_fail_msg("Consensus-only test unexpectedly captured init data");
    } else if (previous_golden.expired() || state.init_outputs.empty()) {
        report_fail_msg("Cross-check golden output storage was released before test cleanup");
    }
    for (const auto &outputs : state.worker_outputs) {
        if (outputs) {
            for (const auto &[name, slot] : *outputs) {
                if (slot.count && !slot.storage)
                    report_fail_msg("Cross-check first submission storage was released before test cleanup");
                (void)name;
            }
        }
    }
    if (output_case(test, "_submit_cleanup")) {
        const auto words = std::array<uint32_t, 2>{1, 2};
        submit_output(output_words, words, nullptr);
    }
    log_info("output test cleanup retained storage");
    return EXIT_SUCCESS;
}
