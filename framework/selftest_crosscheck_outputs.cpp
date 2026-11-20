/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck.h"
#include "selftest_crosscheck_outputs.h"
#include "sandstone_p.h"
#include "topology.h"

#include <array>
#include <atomic>
#include <barrier>
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
CROSSCHECK_OUTPUT(skipped_words, uint32_t);
uint32_t output_generation = 0;
std::weak_ptr<const void> previous_init_snapshot;
std::weak_ptr<const void> previous_consensus;
std::weak_ptr<const void> previous_vote;
std::atomic<bool> check_callback_owner_union = false;

std::shared_ptr<const void> output_storage(std::string_view name)
{
    auto &state = sApp->crosscheck_state;
    std::lock_guard lock(state.mutex);
    for (const auto &outputs : state.owner_outputs) {
        auto it = outputs.find(name);
        if (it != outputs.end())
            return it->second.storage;
    }
    return {};
}

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
    if (check_callback_owner_union.exchange(false, std::memory_order_relaxed)) {
        bool complete = device_count() >= 2;
        for (int owner = 0; owner < device_count(); ++owner) {
            if (sApp->crosscheck_failures[owner].load(std::memory_order_relaxed) != (owner < 2))
                complete = false;
        }
        if (complete)
            log_info("first callback observed complete all-name owner union");
        else
            log_error("first callback observed incomplete all-name owner union");
    }
    log_info("output failure callback fired for worker %d", thread_num);
}

[[maybe_unused]] void output_callback_cleanup(void *)
{
    const auto &state = sApp->crosscheck_state;
    if (!previous_init_snapshot.expired() || !previous_consensus.expired() || !previous_vote.expired()
            || !state.inputs.empty() || !state.owner_outputs.empty()
            || sApp->test_phase != SandstoneApplication::TestPhase::Framework)
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
int64_t vote_init, vote_values, vote_skips, vote_failures, vote_later, vote_shape, vote_c_worker;
bool vote_after, vote_cleanup_skip, vote_two_names, vote_retry;
bool vote_repeat, vote_log_failure, vote_cleanup_failure;
bool vote_nonfirst_slice;
int64_t vote_owner_case, vote_outside_cpu;
std::unique_ptr<std::barrier<>> vote_barrier;

bool pin_output_cpu(int cpu)
{
    if (pin_to_logical_processor(LogicalProcessor(cpu)) && sched_getcpu() == cpu)
        return true;
    log_skip(SelftestSkipCategory, "Cannot pin cross-check fixture to CPU %d", cpu);
    return false;
}

int owner_outputs_run(int worker)
{
#ifdef SANDSTONE_DEVICE_CPU
    auto submit = [&](int owner, uint32_t value, const char *description) {
        if (!pin_output_cpu(device_info[owner].cpu_number))
            return false;
        submit_output(vote_a, &value, 1, description);
        log_info("owner worker %d submitted slot %d CPU %d", worker, owner, sched_getcpu());
        return true;
    };
    if (vote_owner_case == 5) {
        if (!pin_output_cpu(device_info[0].cpu_number)) {
            vote_barrier->arrive_and_drop();
            return EXIT_SKIP;
        }
        vote_barrier->arrive_and_wait();
        uint32_t value = 0;
        for (int repeat = 0; repeat < 20; ++repeat)
            submit_output(vote_a, &value, 1, "concurrent shared CPU first snapshot");
        vote_barrier->arrive_and_wait();
        if (worker == 0 && !submit(1, 1, "second CPU, not another worker on the first CPU"))
            return EXIT_SKIP;
        return EXIT_SUCCESS;
    }
    if (vote_owner_case == 6 || vote_owner_case == 7) {
        if (worker == 0) {
            if (!submit(0, 0, "first writer skipped; retain this description"))
                return EXIT_SKIP;
            log_skip(SelftestSkipCategory, "owner first writer skipped");
            return EXIT_SKIP;
        }
        if (worker == 1 && vote_owner_case == 7
                && !submit(0, 0, "successful confirmation must not replace metadata"))
            return EXIT_SKIP;
        if (worker == 2 && !submit(1, 1, "conflicting second CPU"))
            return EXIT_SKIP;
        return EXIT_SUCCESS;
    }
    if (vote_owner_case == 9) {
        if (!pin_output_cpu(device_info[worker].cpu_number))
            return EXIT_SKIP;
        uint32_t values[] = {worker == 1 ? 1U : 0U, worker == 0 ? 1U : 0U};
        submit_output(vote_a, values, "whole array, not element-wise majority");
        return EXIT_SUCCESS;
    }
    if (worker != 0)
        return EXIT_SUCCESS;
    if (vote_owner_case == 10 || vote_owner_case == 11) {
        SandstoneCrossCheck::OutputKey<uint32_t> key{"owner's output: words\nsecond line"};
        std::string description = "first writer's description: value\nretained detail";
        uint32_t value = 1;
        if (!pin_output_cpu(device_info[1].cpu_number))
            return EXIT_SKIP;
        submit_output(key, &value, 1, description.c_str());
        description.assign("replacement description must not survive");
        if (vote_owner_case == 11) {
            value = 0;
            for (int owner : {0, 2}) {
                if (!pin_output_cpu(device_info[owner].cpu_number))
                    return EXIT_SKIP;
                submit_output(key, &value, 1, "majority snapshot");
            }
        }
        [[maybe_unused]] const uint8_t byte = 0;
        log_data("consume data budget before mismatch", &byte, 1);
        log_info("consume message budget before mismatch");
        if (vote_owner_case == 10) {
            ++value;
            submit_output(key, &value, 1, description.c_str());
        }
        return EXIT_SUCCESS;
    }
    if (vote_owner_case == 12) {
        const auto input = get_input(output_numbers);
        for (int owner = 0; owner < device_count(); ++owner) {
            if (!pin_output_cpu(device_info[owner].cpu_number))
                return EXIT_SKIP;
            uint32_t value = input[0] + input[1];
            submit_output(vote_a, &value, 1, "agreement across selected CPUs");
        }
        return EXIT_SUCCESS;
    }
    if (vote_owner_case == 8) {
        if (!pin_output_cpu(int(vote_outside_cpu)))
            return EXIT_SKIP;
        uint32_t value = 0;
        submit_output(vote_a, &value, 1, "intentional outside-slice misuse");
        report_fail_msg("Outside-slice submission unexpectedly returned");
    }
    if (vote_owner_case == 3 || vote_owner_case == 4) {
        if (!submit(0, 0, "original A snapshot"))
            return EXIT_SKIP;
        reschedule();
        if (!submit(1, 1, "independent B snapshot"))
            return EXIT_SKIP;
        reschedule();
        if (!submit(0, vote_owner_case == 4 ? 2 : 0, "return to A"))
            return EXIT_SKIP;
        log_info("owner A-B-A returned to original snapshot");
        return EXIT_SUCCESS;
    }
    if (!submit(1, 1, "worker zero first captured CPU B"))
        return EXIT_SKIP;
    if (vote_owner_case == 2 && !submit(2, 1, "same worker also captured CPU C"))
        return EXIT_SKIP;
    if (!submit(0, 0, "worker zero initial CPU is not an outlier"))
        return EXIT_SKIP;
    for (int owner = vote_owner_case == 2 ? 3 : 2; owner < device_count(); ++owner) {
        if (!submit(owner, 0, "majority CPU captured by worker zero"))
            return EXIT_SKIP;
    }
#else
    (void)worker;
#endif
    return EXIT_SUCCESS;
}
}

static int selftest_crosscheck_votes_init(struct test *test)
{
#ifndef SANDSTONE_DEVICE_CPU
    log_skip(SelftestSkipCategory, "CPU ownership fixture requires a CPU build");
    return EXIT_SKIP;
#endif
    if (!previous_vote.expired())
        report_fail_msg("Vote snapshots survived the previous execution");
    vote_init = get_testspecific_knob_value_int(test, "init", -1);
    vote_values = get_testspecific_knob_value_int(test, "values", 0);
    vote_skips = get_testspecific_knob_value_int(test, "skips", 0);
    vote_failures = get_testspecific_knob_value_int(test, "failures", 0);
    vote_later = get_testspecific_knob_value_int(test, "later", -1);
    vote_shape = get_testspecific_knob_value_int(test, "shape", 0);
    vote_c_worker = get_testspecific_knob_value_int(test, "c_worker", -1);
    vote_after = get_testspecific_knob_value_int(test, "after", 0);
    vote_cleanup_skip = get_testspecific_knob_value_int(test, "cleanup_skip", 0);
    vote_two_names = get_testspecific_knob_value_int(test, "two_names", 0);
    vote_retry = get_testspecific_knob_value_int(test, "retry", 0);
    vote_repeat = get_testspecific_knob_value_int(test, "repeat", 0);
    vote_log_failure = get_testspecific_knob_value_int(test, "log_failure", 0);
    vote_cleanup_failure = get_testspecific_knob_value_int(test, "cleanup_failure", 0);
    vote_nonfirst_slice = get_testspecific_knob_value_int(test, "nonfirst_slice", 0);
    vote_owner_case = get_testspecific_knob_value_int(test, "owner_case", 0);
    vote_outside_cpu = get_testspecific_knob_value_int(test, "outside_cpu", -1);
    check_callback_owner_union.store(get_testspecific_knob_value_int(test, "callback_union", 0),
                                     std::memory_order_relaxed);
    vote_barrier.reset();
    if (vote_owner_case) {
        int required = vote_owner_case == 2 ? 5 : vote_owner_case == 8 ? 1
                : vote_owner_case == 1 || vote_owner_case == 6 || vote_owner_case == 7
                        || vote_owner_case == 9 || vote_owner_case == 11 ? 3 : 2;
        if (device_count() < required) {
            log_skip(SelftestSkipCategory, "Ownership fixture requires %d selected CPUs", required);
            return EXIT_SKIP;
        }
#ifdef SANDSTONE_DEVICE_CPU
        for (int owner = 0; owner < required; ++owner) {
            if (!pin_output_cpu(device_info[owner].cpu_number))
                return EXIT_SKIP;
        }
#endif
        if (vote_owner_case == 5)
            vote_barrier = std::make_unique<std::barrier<>>(sApp->thread_count);
        if (vote_owner_case == 12) {
            const uint32_t input[] = {++output_generation, 5};
            set_input(output_numbers, input, "fresh ownership attempt input");
            log_info("owner agreement input generation %u", output_generation);
        }
    }
    install_failure_callback(output_failure_callback, nullptr, output_callback_cleanup);
    if (vote_init >= 0) {
        int64_t init_owner = get_testspecific_knob_value_int(test, "init_owner", 0);
        if (init_owner < 0 || init_owner >= device_count())
            report_fail_msg("Init fixture CPU index out of range");
        if (!pin_output_cpu(device_info[init_owner].cpu_number))
            return EXIT_SKIP;
        uint32_t value = uint32_t(vote_init);
        submit_output(vote_a, &value, 1, "CPU computation in init");
        submit_output(vote_a, &value, 1, "repetition is not another vote");
        log_info("vote init submission CPU %d", sched_getcpu());
        if (vote_two_names)
            submit_output(vote_z, &value, 1, "second init computation");
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

static int selftest_crosscheck_votes_run(struct test *test, int worker)
{
    if (vote_owner_case)
        return owner_outputs_run(worker);
    bool skipped = worker < 63 && (uint64_t(vote_skips) >> worker & 1);
    bool failed = worker < 63 && (uint64_t(vote_failures) >> worker & 1);
    auto finish = [&] {
        if (failed && vote_log_failure) {
            log_error("original vote worker error");
            return EXIT_SUCCESS;
        }
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
    if (vote_nonfirst_slice && sApp->main_thread_data()->device_range.starting_device == 0)
        value = 0;
    if (vote_retry && test_is_retry())
        value = 0;
    uint32_t values[] = {value, value};
    if (vote_shape == 4) {
        std::string name = stdprintf("worker_%d", worker);
        submit_output(SandstoneCrossCheck::OutputKey<uint32_t>{name.c_str()}, values, 1,
                      "disjoint worker name");
        return finish();
    }
    if (vote_shape == 5)
        return finish();
    if (!(vote_shape == 1 && worker == 0)) {
        if (vote_shape == 3 && worker == 0) {
            uint8_t byte = uint8_t(value);
            submit_output(SandstoneCrossCheck::OutputKey<uint8_t>{vote_a.name}, &byte, 1, "wrong type");
        } else {
            size_t count = vote_shape == 2 && worker == 0 ? 2 : 1;
            if (worker == vote_c_worker)
                selftest_crosscheck_outputs_c_vote(values, count);
            else
                submit_output(vote_a, values, count, "worker computation");
            if (vote_repeat)
                submit_output(vote_a, values, 1, "repeated worker submission");
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
    return finish();
}

static int selftest_crosscheck_votes_cleanup(struct test *)
{
    const auto &state = sApp->crosscheck_state;
    for (const auto &outputs : state.owner_outputs) {
        if (!outputs.empty())
            previous_vote = outputs.begin()->second.storage;
    }
    for (int worker = 0; worker < sApp->thread_count; ++worker) {
        log_info("vote worker %d final state %d", worker,
                 int(sApp->test_thread_data(worker)->thread_state.load(std::memory_order_relaxed)));
    }
    if (vote_owner_case == 3 || vote_owner_case == 4 || vote_owner_case == 5) {
        size_t captures = 0;
        for (const auto &outputs : state.owner_outputs)
            captures += outputs.count(vote_a.name);
        if (captures != 2)
            report_fail_msg("Expected two CPU-owned snapshots, got %zu", captures);
        log_info("owner cleanup retained exactly two CPU snapshots");
    }
    if (vote_owner_case == 12) {
        const auto input = get_input(output_numbers);
        if (input.size() != 2 || input[0] != output_generation || input[1] != 5)
            report_fail_msg("Ownership attempt input did not survive through cleanup");
        for (const auto &outputs : state.owner_outputs) {
            auto it = outputs.find(vote_a.name);
            if (it == outputs.end() || it->second.count != 1 || !it->second.storage
                    || *static_cast<const uint32_t *>(it->second.storage.get()) != input[0] + input[1])
                report_fail_msg("Ownership attempt lost or reused a CPU snapshot");
        }
        log_info("owner agreement captured %d CPUs with %d workers", device_count(), sApp->thread_count);
    }
    log_info("vote cleanup retained snapshots");
    if (vote_cleanup_failure) {
        log_error("original vote cleanup error");
        return EXIT_SUCCESS;
    }
    if (vote_cleanup_skip) {
        log_skip(SelftestSkipCategory, "vote cleanup requested skip");
        return EXIT_SKIP;
    }
    return EXIT_SUCCESS;
}

static int selftest_crosscheck_outputs_init(struct test *test)
{
    check_callback_owner_union.store(false, std::memory_order_relaxed);
#ifndef SANDSTONE_DEVICE_CPU
    log_skip(SelftestSkipCategory, "CPU output fixture requires a CPU build");
    return EXIT_SKIP;
#endif
    if (!previous_init_snapshot.expired() || !previous_consensus.expired())
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
    if (output_case(test, "_c_init_pass"))
        selftest_crosscheck_outputs_c_input(output_generation);
    else
        set_input(output_numbers, source, "owned output computation inputs");
    source.assign(2, 0);
    auto words = compute_words();
    std::string description = "CPU words computed in init";
    const bool flags[] = {true, false};
    if (output_case(test, "_c_init_pass")
            || output_case(test, "_c_bad_first") || output_case(test, "_c_bad_later")
            || output_case(test, "_c_init_snapshot_count") || output_case(test, "_c_later_count")) {
        selftest_crosscheck_outputs_c_init_outputs();
    } else {
        submit_output(output_words, words, description.c_str());
        submit_output(output_flags, flags, nullptr);
        submit_output(output_empty, static_cast<const uint32_t *>(nullptr), 0, nullptr);
    }
    words.fill(0);
    description.assign("destroyed init description");
    previous_init_snapshot = output_storage(output_words.name);
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
        submit_output(output_text, std::string(label.begin(), label.end()), "init text");
    }
    if (output_case(test, "_nan_pass") || output_case(test, "_nan_fail")
            || output_case(test, "_zero_fail")) {
        const std::array<uint32_t, 3> bits = {0, 0x7fc12345, 0x80000000};
        const auto values = std::bit_cast<std::array<float, 3>>(bits);
        submit_output(output_float, values, "init floating bits");
    }
    if (output_case(test, "_padding_pass") || output_case(test, "_padding_fail")) {
        auto values = long_double_values();
        log_info("output padded mismatch byte offset %zu", 2 * sizeof(long double));
        for (auto &value : values)
            std::memset(reinterpret_cast<unsigned char *>(&value) + LONG_DOUBLE_MEANINGFUL,
                        0xa5, sizeof(value) - LONG_DOUBLE_MEANINGFUL);
        submit_output(output_long_double, values, "init padded array");
    }
    log_info("output init generation %" PRIu32, output_generation);
    if (output_case(test, "_skip_init") || output_case(test, "_parent_skip_init")) {
        log_skip(SelftestSkipCategory, "Skip after init output submission");
        return EXIT_SKIP;
    }
    if (output_case(test, "_error_init"))
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

static int selftest_crosscheck_outputs_run(struct test *test, int thread)
{
    if (std::string_view(test->id).find("_consensus_") != std::string_view::npos) {
        if (output_case(test, "_consensus_empty") || output_case(test, "_consensus_input_only"))
            return EXIT_SUCCESS;
        if (output_case(test, "_consensus_zero_length")) {
            submit_output(consensus_a, static_cast<const uint32_t *>(nullptr), 0, nullptr);
            return EXIT_SUCCESS;
        }
        if (thread == 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        if (thread == 1) {
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
        if (output_case(test, "_slice")) {
            values[0] = uint32_t(device_info[0].cpu_number);
            log_info("consensus slice reference %u", values[0]);
        }
        if ((output_case(test, "_zero_outlier") && thread == 0)
                || (output_case(test, "_single") && thread == 1))
            ++values[0];
        if (output_case(test, "_distinct"))
            values[0] += thread;
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
            previous_consensus = output_storage(consensus_a.name);
        if (!output_case(test, "_count") && !output_case(test, "_type")) {
            submit_output(consensus_a, values, "ignored later metadata");
            if (output_case(test, "_later")) {
                ++values[0];
                submit_output(consensus_a, values, nullptr);
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
    if (output_case(test, "_additional_worker_output")) {
        CROSSCHECK_OUTPUT(worker_only_output, uint32_t);
        const uint32_t value = 1;
        submit_output(worker_only_output, &value, 1, nullptr);
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
            || output_case(test, "_c_bad_later") || output_case(test, "_c_init_snapshot_count")
            || output_case(test, "_c_later_count"))
        return selftest_crosscheck_outputs_c_run(test, thread);
    auto words = compute_words();
    if (output_case(test, "_bad_first_skip_flag")
            && !output_case(test, "_mixed_bad_first_skip_flag")) {
        ++words[0];
        submit_output(skipped_words, words, "skipped-worker-only independent name");
        log_skip(SelftestSkipCategory, "original output skip flag after independent submission");
        return EXIT_SUCCESS;
    }
    if (output_case(test, "_bad_first") || output_case(test, "_bad_first_fail_flag")
            || output_case(test, "_bad_first_skip_flag")
            || (output_case(test, "_retry") && !test_is_retry()))
        ++words[0];
    const bool flags[] = {true, false};
    // Workers deliberately submit names in a different order from test_init().
    if (thread % 2) {
        submit_output(output_flags, flags, "ignored flags");
        submit_output(output_empty, static_cast<const uint32_t *>(nullptr), 0, "ignored empty");
    } else {
        submit_output(output_empty, static_cast<const uint32_t *>(nullptr), 0, "ignored empty");
        submit_output(output_flags, flags, "ignored flags");
    }
    if (output_case(test, "_init_snapshot_count")) {
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
    log_info("output post-submit sentinel");
    if (output_case(test, "_bad_first_fail_flag"))
        log_error("original output failure flag after wrong first submission");
    if (output_case(test, "_bad_first_skip_flag")
            && (!output_case(test, "_mixed_bad_first_skip_flag") || thread == 0))
        log_skip(SelftestSkipCategory, "original output skip flag after wrong first submission");
    return EXIT_SUCCESS;
}

static int selftest_crosscheck_outputs_cleanup(struct test *test)
{
    if (std::string_view(test->id).find("_consensus_") != std::string_view::npos
            && sApp->main_thread_data()->has_skipped())
        report_fail_msg("Consensus marked the main thread as skipped before cleanup");
    if (output_case(test, "_consensus_skip") && sApp->thread_count > 1
            && sApp->test_thread_data(1)->thread_state.load(std::memory_order_relaxed) != thread_skipped)
        report_fail_msg("Consensus overwrote the worker's original skip state");
    const auto &state = sApp->crosscheck_state;
    if (std::string_view(test->id).find("_consensus_") != std::string_view::npos) {
        if (!state.inputs.empty() && !output_case(test, "_consensus_input_only"))
            report_fail_msg("Consensus-only test unexpectedly captured init data");
    } else if (previous_init_snapshot.expired()) {
        report_fail_msg("Cross-check init output storage was released before test cleanup");
    }
    for (const auto &outputs : state.owner_outputs) {
        for (const auto &[name, slot] : outputs) {
            if (slot.count && !slot.storage)
                report_fail_msg("Cross-check first submission storage was released before test cleanup");
            (void)name;
        }
    }
    if (output_case(test, "_submit_cleanup")) {
        const auto words = std::array<uint32_t, 2>{1, 2};
        submit_output(output_words, words, nullptr);
    }
    log_info("output test cleanup retained storage");
    return EXIT_SUCCESS;
}

#define CROSSCHECK_OUTPUT_SELFTEST(suffix, description_text, group, duration, flags_value) \
DECLARE_SELFTEST(SANDSTONE_CONCAT(selftest_crosscheck_output_, suffix), description_text) \
    .groups = DECLARE_TEST_GROUPS(&group), \
    .test_init = selftest_crosscheck_outputs_init, \
    .test_run = selftest_crosscheck_outputs_run, \
    .test_cleanup = selftest_crosscheck_outputs_cleanup, \
    .desired_duration = duration, \
    .fracture_loop_count = duration == 0 ? 10 : 0, \
    .quality_level = TEST_QUALITY_PROD, \
    .flags = flags_value, \
END_DECLARE_TEST

DECLARE_SELFTEST(selftest_crosscheck_votes, "Exercises CPU-owned outputs, majorities, and execution states")
    .test_init = selftest_crosscheck_votes_init,
    .test_run = selftest_crosscheck_votes_run,
    .test_cleanup = selftest_crosscheck_votes_cleanup,
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_PROD,
END_DECLARE_TEST
DECLARE_SELFTEST(selftest_crosscheck_votes_sequential, "Preserves submission CPU attribution after sequential rescheduling")
    .test_init = selftest_crosscheck_votes_init,
    .test_run = selftest_crosscheck_votes_run,
    .test_cleanup = selftest_crosscheck_votes_cleanup,
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_PROD,
    .flags = test_schedule_sequential,
END_DECLARE_TEST

CROSSCHECK_OUTPUT_SELFTEST(consensus_only_skip_init, "Skips before activating consensus verification",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(consensus_zero_length, "Accepts a present named zero-length consensus output",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(consensus_only_slice, "Verifies outputs separately in each execution slice",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(consensus_pass, "Verifies unanimous worker observations",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(consensus_sequential, "Verifies consensus with sequential workers",
                          group_positive, -1, test_schedule_sequential)
CROSSCHECK_OUTPUT_SELFTEST(consensus_skip, "Preserves a worker's skip during consensus verification",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(containers_pass, "Submits and verifies outputs from C++ containers",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(c_pass, "Verifies C worker outputs alongside C++ CPU init outputs",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(c_init_pass, "Verifies C++ worker outputs alongside C CPU init outputs",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(wrapper_pass, "Verifies floating-point wrapper outputs across translation units",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(nan_pass, "Accepts identical NaN payloads and signed zeros",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(padding_pass, "Ignores trailing long double padding when verifying outputs",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(fracture_pass, "Releases captured storage between fracture passes",
                          group_positive, 0, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(skip_init, "Releases captured storage after test_init() skips",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(parent_skip_init, "Rejects cross-check capture in isolated parent test_init()",
                          group_negative, -1, test_init_in_parent)
CROSSCHECK_OUTPUT_SELFTEST(skip_return, "Preserves a worker's skip return",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(negative_return, "Preserves a worker's negative return",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(skip_flag, "Preserves a worker's skip flag",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(bad_first_skip_flag, "Excludes an independent skipped-worker-only output from verification",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(additional_worker_output, "Accepts additional worker outputs without init submissions",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(consensus_empty, "Accepts execution without cross-check outputs",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(consensus_input_only, "Accepts input-only capture",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(consensus_zero_outlier, "Implicates worker 0 when it is a majority outlier",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(consensus_single, "Implicates producers of conflicting output data",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(consensus_distinct, "Implicates all producers when consensus has no majority",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(consensus_count, "Reports element count mismatches during consensus verification",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(consensus_type, "Reports element type mismatches during consensus verification",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(consensus_later, "Rejects changed later submissions before consensus verification",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(consensus_error, "Preserves a worker's error during consensus verification",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(consensus_noreturn, "Preserves a worker's nonreturning failure during consensus verification",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(consensus_sequential_exit, "Preserves a sequential worker's nonreturning failure",
                          group_negative, -1, test_schedule_sequential)
CROSSCHECK_OUTPUT_SELFTEST(bad_first, "Immediately rejects a worker changing its CPU's init snapshot",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(mixed_bad_first_skip_flag, "A skip cannot hide a mismatch against the CPU's first snapshot",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(bad_later, "Rejects later submissions that differ from the first submission",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(init_snapshot_count, "Rejects element count mismatches against the CPU's init output",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(later_count, "Reports element count changes after the first submission",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(nan_fail, "Rejects changed NaN payloads",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(zero_fail, "Distinguishes positive and negative zero",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(padding_fail, "Rejects changed meaningful long double bytes",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(fail_return, "Preserves a worker's failure return",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(fail_flag, "Preserves a worker's error flag",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(bad_first_fail_flag, "An immediate local mismatch prevents a later worker error flag",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(noreturn, "Preserves a worker's nonreturning failure",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(error_init, "Releases captured storage after test_init() errors",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(retry, "Captures fresh init outputs and first submissions on retries",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(duplicate, "Checks repeated init output submission for invariance",
                          group_positive, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(c_conflict, "Reports C element type conflicts across translation units",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(wrapper_conflict, "Distinguishes wrapper and native element types",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(submit_cleanup, "Rejects output submission in test_cleanup()",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(invalid_pointer, "Rejects null init output data with a nonzero count",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(invalid_count, "Rejects excessive init output counts",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(worker_invalid_pointer, "Rejects null worker output data with a nonzero count",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(worker_invalid_count, "Rejects excessive worker output counts",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(c_bad_first, "Immediately rejects a C worker changing its CPU's init snapshot",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(c_bad_later, "Rejects changed later C submissions",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(c_init_snapshot_count, "Rejects C element count mismatches against the CPU's init output",
                          group_negative, -1, test_schedule_default)
CROSSCHECK_OUTPUT_SELFTEST(c_later_count, "Reports C element count changes after the first submission",
                          group_negative, -1, test_schedule_default)
