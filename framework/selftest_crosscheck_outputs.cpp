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
DECLARE_CROSS_CHECK_INPUT(output_numbers, uint32_t);
DECLARE_CROSS_CHECK_OUTPUT(output_words, uint32_t);
DECLARE_CROSS_CHECK_OUTPUT(output_flags, bool);
DECLARE_CROSS_CHECK_OUTPUT(output_empty, uint32_t);
DECLARE_CROSS_CHECK_OUTPUT(output_wrapper, Float32);
DECLARE_CROSS_CHECK_OUTPUT(output_wrapper64, Float64);
DECLARE_CROSS_CHECK_INPUT(output_label, char);
DECLARE_CROSS_CHECK_OUTPUT(output_text, char);
DECLARE_CROSS_CHECK_OUTPUT(output_float, float);
DECLARE_CROSS_CHECK_OUTPUT(output_long_double, long double);
DECLARE_CROSS_CHECK_OUTPUT(consensus_a, uint32_t);
DECLARE_CROSS_CHECK_OUTPUT(consensus_z, uint32_t);
uint32_t output_generation = 0;
int64_t incomplete_slice = 0;
int64_t fail_slice = -1;
std::weak_ptr<const void> previous_golden;
std::weak_ptr<const void> previous_consensus;

bool output_case(const test *test, std::string_view suffix)
{
    return std::string_view(test->id).ends_with(suffix);
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

void output_callback_cleanup(void *)
{
    const auto &state = sApp->crosscheck_state;
    if (!previous_golden.expired() || !previous_consensus.expired()
            || !state.inputs.empty() || !state.golden_outputs.empty()
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

int selftest_crosscheck_outputs_init(struct test *test)
{
    if (output_case(test, "_consensus_mixed_slice")) {
        incomplete_slice = get_testspecific_knob_value_int(test, "incomplete_slice", 0);
        fail_slice = get_testspecific_knob_value_int(test, "fail_slice", -1);
    }
    if (!previous_golden.expired() || !previous_consensus.expired())
        report_fail_msg("Cross-check output storage survived the previous pass");
    if (std::string_view(test->id).find("_consensus_only_") != std::string_view::npos) {
        install_failure_callback(output_failure_callback, nullptr, output_callback_cleanup);
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
        capture_input(output_numbers, source, "owned output computation inputs");
    source.assign(2, 0);
    auto words = compute_words();
    std::string description = "authoritative golden words";
    const bool flags[] = {true, false};
    if (output_case(test, "_c_pass") || output_case(test, "_c_golden_pass")
            || output_case(test, "_c_bad_first") || output_case(test, "_c_bad_later")
            || output_case(test, "_c_golden_count") || output_case(test, "_c_later_count")) {
        selftest_crosscheck_outputs_c_golden();
    } else {
        capture_output(output_words, words, description.c_str());
        capture_output(output_flags, flags, nullptr);
        capture_output(output_empty, static_cast<const uint32_t *>(nullptr), 0, nullptr);
    }
    words.fill(0);
    description.assign("destroyed golden description");
    previous_golden = sApp->crosscheck_state.golden_outputs.at(output_words.name).storage;
    if (!output_case(test, "_parent_skip_init"))
        install_failure_callback(output_failure_callback, nullptr, output_callback_cleanup);
    if (output_case(test, "_duplicate")) {
        words = compute_words();
        capture_output(output_words, words, nullptr);
    }
    if (output_case(test, "_invalid_pointer") && !output_case(test, "_worker_invalid_pointer")) {
        DECLARE_CROSS_CHECK_OUTPUT(invalid_output, uint32_t);
        capture_output(invalid_output, static_cast<const uint32_t *>(nullptr), 1, nullptr);
    }
    if (output_case(test, "_invalid_count") && !output_case(test, "_worker_invalid_count")) {
        DECLARE_CROSS_CHECK_OUTPUT(invalid_output, uint32_t);
        capture_output(invalid_output, words.data(), std::numeric_limits<size_t>::max(), nullptr);
    }
    if (output_case(test, "_wrapper_pass") || output_case(test, "_wrapper_conflict")) {
        const Float32 values[] = {Float32(1.0f), Float32(-0.0f)};
        capture_output(output_wrapper, values, nullptr);
        const Float64 wide[] = {Float64(1.0), Float64(-0.0)};
        capture_output(output_wrapper64, wide, nullptr);
    }
    if (output_case(test, "_containers_pass")) {
        capture_input(output_label, std::string("cross check string"));
        auto label = get_input(output_label);
        capture_output(output_text, std::string(label.begin(), label.end()), "golden text");
    }
    if (output_case(test, "_nan_pass") || output_case(test, "_nan_fail")
            || output_case(test, "_zero_fail")) {
        const std::array<uint32_t, 3> bits = {0, 0x7fc12345, 0x80000000};
        const auto values = std::bit_cast<std::array<float, 3>>(bits);
        capture_output(output_float, values, "golden floating bits");
    }
    if (output_case(test, "_padding_pass") || output_case(test, "_padding_fail")) {
        auto values = long_double_values();
        log_info("output padded mismatch byte offset %zu", 2 * sizeof(long double));
        for (auto &value : values)
            std::memset(reinterpret_cast<unsigned char *>(&value) + LONG_DOUBLE_MEANINGFUL,
                        0xa5, sizeof(value) - LONG_DOUBLE_MEANINGFUL);
        capture_output(output_long_double, values, "golden padded array");
    }
    log_info("output init generation %" PRIu32, output_generation);
    if (output_case(test, "_skip_init") || output_case(test, "_parent_skip_init")) {
        log_skip(SelftestSkipCategory, "Skip after golden output capture");
        return EXIT_SKIP;
    }
    if (output_case(test, "_error_init"))
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

int selftest_crosscheck_outputs_run(struct test *test, int thread)
{
    if (std::string_view(test->id).find("_consensus_") != std::string_view::npos) {
        if (std::string_view(test->id).find("_consensus_only_") == std::string_view::npos) {
            auto words = compute_words();
            if (output_case(test, "_consensus_mixed_slice") && thread == 0
                    && sApp->main_thread_data()->thread_range.starting_thread / 2 ==
                    fail_slice)
                ++words[0];
            const bool flags[] = {true, false};
            capture_output(output_words, words, nullptr);
            capture_output(output_flags, flags, nullptr);
            capture_output(output_empty, static_cast<const uint32_t *>(nullptr), 0, nullptr);
        }
        if (thread == 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        int exiting_worker = std::string_view(test->id).find("_reference_") != std::string_view::npos ? 0 : 1;
        if (thread == exiting_worker) {
            if (output_case(test, "_consensus_mixed_slice")
                    && sApp->main_thread_data()->thread_range.starting_thread / 2 ==
                    incomplete_slice)
                return EXIT_SKIP;
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
        if (std::string_view(test->id).find("_consensus_only_reference_") != std::string_view::npos)
            values[0] += thread;
        if (output_case(test, "_slice")) {
            values[0] = uint32_t(device_info[0].cpu_number);
            log_info("consensus slice reference %u", values[0]);
        }
        if ((output_case(test, "_zero_outlier") && thread == 0)
                || (output_case(test, "_single") && thread == 1)
                || (output_case(test, "_multiple") && thread > 0))
            ++values[0];
        if (output_case(test, "_distinct"))
            values[0] += thread;
        if (!(output_case(test, "_consensus_missing") && thread == 1)
                && !(output_case(test, "_reference_missing") && thread == 0)) {
            capture_output(consensus_z, values, "worker z metadata");
            if (output_case(test, "_type") && thread == 1) {
                SandstoneCrossCheck::OutputTag<uint8_t> tag{consensus_a.name};
                const uint8_t bytes[] = {17, 23};
                capture_output(tag, bytes, 2, "different type");
            } else {
                capture_output(consensus_a, values, output_case(test, "_count") && thread == 1 ? 1 : 2,
                               "worker a metadata");
            }
            if (thread == 0)
                previous_consensus = sApp->crosscheck_state.worker_outputs[0]->at(consensus_a.name).storage;
            if (!output_case(test, "_count") && !output_case(test, "_type")) {
                capture_output(consensus_a, values, "ignored later metadata");
                if (output_case(test, "_later")) {
                    ++values[0];
                    capture_output(consensus_a, values, nullptr);
                }
            }
        }
        if (output_case(test, "_distinct"))
            reschedule();
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
        DECLARE_CROSS_CHECK_OUTPUT(uncaptured_output, uint32_t);
        const uint32_t value = 1;
        capture_output(uncaptured_output, &value, 1, nullptr);
    }
    if (output_case(test, "_c_conflict"))
        selftest_crosscheck_outputs_c_conflict();
    if (output_case(test, "_worker_invalid_pointer"))
        capture_output(output_words, static_cast<const uint32_t *>(nullptr), 1, nullptr);
    if (output_case(test, "_worker_invalid_count")) {
        const auto words = compute_words();
        capture_output(output_words, words.data(), std::numeric_limits<size_t>::max(), nullptr);
    }
    if (output_case(test, "_c_pass") || output_case(test, "_c_bad_first")
            || output_case(test, "_c_bad_later") || output_case(test, "_c_golden_count")
            || output_case(test, "_c_later_count"))
        return selftest_crosscheck_outputs_c_run(test, thread);
    auto words = compute_words();
    if (output_case(test, "_bad_first") || output_case(test, "_bad_first_fail_flag")
            || output_case(test, "_bad_first_skip_flag")
            || (output_case(test, "_retry") && !test_is_retry()))
        ++words[0];
    const bool flags[] = {true, false};
    // Workers deliberately submit names in a different order from test_init().
    if (!output_case(test, "_missing_partial")) {
        if (thread % 2) {
            capture_output(output_flags, flags, "ignored flags");
            capture_output(output_empty, static_cast<const uint32_t *>(nullptr), 0, "ignored empty");
        } else {
            capture_output(output_empty, static_cast<const uint32_t *>(nullptr), 0, "ignored empty");
            capture_output(output_flags, flags, "ignored flags");
        }
    }
    if (output_case(test, "_golden_count")) {
        capture_output(output_words, words.data(), 1, nullptr);
    } else {
        capture_output(output_words, words, nullptr);
        auto repeated = words;
        words.fill(99);
        for (int i = 0; i < 3; ++i)
            capture_output(output_words, std::span<const uint32_t>(repeated), "ignored worker words");
        if (output_case(test, "_later_count"))
            capture_output(output_words, repeated.data(), 1, nullptr);
        if (output_case(test, "_bad_later")) {
            ++repeated[1];
            capture_output(output_words, repeated, nullptr);
        }
    }
    if (output_case(test, "_wrapper_pass") || output_case(test, "_wrapper_conflict"))
        selftest_crosscheck_outputs_cpp_peer(output_case(test, "_wrapper_conflict"));
    if (output_case(test, "_containers_pass")) {
        auto label = get_input(output_label);
        const std::string text(label.begin(), label.end());
        capture_output(output_text, text, nullptr);
        capture_output(output_text, text, "ignored text");
    }
    if (output_case(test, "_nan_pass") || output_case(test, "_nan_fail")
            || output_case(test, "_zero_fail")) {
        std::array<uint32_t, 3> bits = {0, 0x7fc12345, 0x80000000};
        auto values = std::bit_cast<std::array<float, 3>>(bits);
        capture_output(output_float, values, nullptr);
        if (output_case(test, "_nan_fail"))
            bits[1] ^= 1;
        if (output_case(test, "_zero_fail"))
            bits[0] = bits[2];
        values = std::bit_cast<std::array<float, 3>>(bits);
        capture_output(output_float, values, nullptr);
    }
    if (output_case(test, "_padding_pass") || output_case(test, "_padding_fail")) {
        auto values = long_double_values();
        capture_output(output_long_double, values, nullptr);
        for (auto &value : values)
            std::memset(reinterpret_cast<unsigned char *>(&value) + LONG_DOUBLE_MEANINGFUL,
                        0x5a, sizeof(value) - LONG_DOUBLE_MEANINGFUL);
        if (output_case(test, "_padding_fail"))
            reinterpret_cast<unsigned char *>(&values[2])[0] ^= 1;
        capture_output(output_long_double, values, "ignored padding");
    }
    if (output_case(test, "_fracture_pass")) {
        TEST_LOOP(test, 1) {
            const auto actual = compute_words();
            capture_output(output_words, actual, nullptr);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    if (output_case(test, "_sequential_bad_first")) {
        reschedule();
        log_info("output completion CPU %d", sched_getcpu());
    }
    log_info("output post-capture sentinel");
    if (output_case(test, "_bad_first_fail_flag"))
        log_error("original output failure flag after wrong first submission");
    if (output_case(test, "_bad_first_skip_flag"))
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
    if (std::string_view(test->id).find("_consensus_only_") != std::string_view::npos) {
        if (!state.inputs.empty() || !state.golden_outputs.empty())
            report_fail_msg("Consensus-only test unexpectedly captured init data");
    } else if (previous_golden.expired() || state.golden_outputs.empty()) {
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
    if (output_case(test, "_capture_cleanup")) {
        const auto words = std::array<uint32_t, 2>{1, 2};
        capture_output(output_words, words, nullptr);
    }
    log_info("output test cleanup retained storage");
    return EXIT_SUCCESS;
}
