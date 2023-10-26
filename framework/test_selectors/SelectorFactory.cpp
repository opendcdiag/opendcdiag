/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "SelectorFactory.h"

#include "ListFileSelector.h"
#include "OrderedSelector.h"
#include "PrioritizedSelector.h"
#include "WeightedNonRepeatingSelector.h"
#include "WeightedRepeatingSelector.h"

#include "sandstone.h"
#include "sandstone_kvm.h"
#include "sandstone_p.h"

#include <vector>
#include <fnmatch.h>

using namespace std;
extern test mce_test;

enum TestSearchOptions : unsigned {
    MatchExact      = 0x00,
    MatchWildcard   = 0x01,
    MatchGroups     = 0x02,
};
static constexpr auto StandardTestMatchOptions = TestSearchOptions(MatchWildcard | MatchGroups);

enum NameMatchingStatus { NameDoesNotMatch = 0, NameMatches, NameMatchesExactly };

static void apply_group_inits(/*nonconst*/ struct test *test)
{
    // Create an array with the replacement functions per group and cache.
    // If the group_init function decides that the group cannot run at all, it
    // will return a pointer to a replacement function that will in turn cause
    // the test to fail or skip during test_init().

    std::span<const struct test_group> groups = { &__start_test_group, &__stop_test_group };
    static auto replacements = [=]() {
        struct Result {
            decltype(test_group::group_init) group_init;
            decltype(test_group::group_init()) replacement;
        };

        std::vector<Result> replacements(groups.size());
        size_t i = 0;
        for ( ; i < replacements.size(); ++i) {
            replacements[i].group_init = groups[i].group_init;
            replacements[i].replacement = nullptr;
        }
        return replacements;
    }();

    for (auto ptr = test->groups; *ptr; ++ptr) {
        for (size_t i = 0; i < groups.size(); ++i) {
            if (*ptr != &groups.begin()[i])
                continue;
            if (replacements[i].group_init && !replacements[i].replacement) {
                // call the group_init function, only once
                replacements[i].replacement = replacements[i].group_init();
                replacements[i].group_init = nullptr;
            }
            if (replacements[i].replacement) {
                test->test_init = replacements[i].replacement;
                return;
            }
        }
    }
}

static void prepare_test(/*nonconst*/ struct test *test)
{
    if (test->test_preinit) {
        test->test_preinit(test);
        test->test_preinit = nullptr;   // don't rerun in case the test is re-added
    }
    if (test->groups)
        apply_group_inits(test);

    if (test->flags & test_type_kvm) {
        if (!test->test_init) {
            test->test_init = kvm_generic_init;
            test->test_run = kvm_generic_run;
            test->test_cleanup = kvm_generic_cleanup;
        }
    }
}

void add_test(std::vector<struct test *> &test_list, /*nonconst*/ struct test *test)
{
    if (test)
        prepare_test(test);
    test_list.push_back(test);
}

static NameMatchingStatus test_matches_name(const struct test *test, const char *name,
                                            TestSearchOptions options = StandardTestMatchOptions)
{
    // match test ID exactly
    if (strcmp(name, test->id) == 0)
        return NameMatchesExactly;

    // match test ID as a wildcard
    if ((options & MatchWildcard) && fnmatch(name, test->id, 0) == 0)
        return NameMatches;

    // does it match one of the groups?
    if ((options & MatchGroups) && *name == '@') {
        for (auto ptr = test->groups; ptr && *ptr; ++ptr) {
            if (strcmp(name + 1, (*ptr)->id) == 0)
                return NameMatches;
        }
    }

    return NameDoesNotMatch;
}

static void print_unknown_test(const char *name)
{
    fprintf(stderr, "%s: Cannot find test '%s'\n", program_invocation_name, name);
    exit(EX_USAGE);
}

void add_tests(std::span<struct test> test_set, std::vector<struct test *> &test_list, const char *name)
{
    constexpr auto options = TestSearchOptions(MatchWildcard | MatchGroups);
    int count = 0;
    for (struct test &test: test_set) {
        auto matches = test_matches_name(&test, name, options);
        if (!matches)
            continue;

        prepare_test(&test);
        ++count;
        if (test.quality_level >= sApp->requested_quality) {
            add_test(test_list, &test);
        } else if (test_list.empty()) {
            // add a dummy entry just so the list isn't empty
            test_list.push_back(nullptr);
        }
    }

    if (count == 0)
        print_unknown_test(name);
}

void disable_tests(std::span<struct test> test_set, const char *name)
{
    constexpr auto options = TestSearchOptions(MatchWildcard | MatchGroups);
    int count = 0;
    for (struct test &test : test_set) {
        if (test_matches_name(&test, name, options)) {
            disable_test(&test);
            ++count;
        }
    }

    if (count == 0) {
        if (!strcmp(name, "mce_check")) {
            if constexpr (InterruptMonitor::InterruptMonitorWorks)
                disable_test(&mce_test);
        } else {
            print_unknown_test(name);
        }
    }
}

struct test *TestrunSelector::testid_to_test(const char *id, bool silent)
{
    for (struct test *test : testinfo) {
        auto matches = test_matches_name(test, id, MatchExact);
        if (!matches)
            continue;

        if (test->quality_level < sApp->requested_quality)
            return nullptr;

        prepare_test(test);
        return test;
    }

    if (!silent)
        print_unknown_test(id);
    return nullptr;
}

void generate_test_list(std::vector<struct test *> &test_list, std::span<struct test> test_set,
                        int min_quality)
{
    if (SandstoneConfig::RestrictedCommandLine || test_list.empty()) {
        if (!SandstoneConfig::RestrictedCommandLine && sApp->fatal_skips)
            fprintf(stderr, "# WARNING: --fatal-skips used with full test suite. This will probably fail.\n"
                            "# You may want to specify a controlled list of tests to run.\n");
        /* generate test list based on quality levels only */
        for (struct test &test : test_set) {
            if (test.quality_level >= min_quality)
                add_test(test_list, &test);
        }
    } else if (test_list.front() == nullptr) {
        /* remove the dummy entry we added (see add_tests()) */
        test_list.erase(test_list.begin());
    }
}

extern TestrunSelector * setup_test_selector(
        WeightedTestScheme         selectScheme,
        WeightedTestLength         lengthScheme,
        std::vector<struct test *> tests,
        struct weighted_run_info * weight_info)
{
    switch (selectScheme) {
    case Alphabetical:
    case Ordered:
        return new OrderedTestSelector(std::move(tests), selectScheme);
    default:
        break;
    }

    if constexpr (SandstoneConfig::RestrictedCommandLine) {
        SANDSTONE_UNREACHABLE("Should not have reached here");
        return nullptr;
    }

    WeightedTestrunSelector *selector;
    switch (selectScheme){
        case Repeating:
            selector = new RepeatingWeightedTestrunSelector(std::move(tests));
            break;
        case NonRepeating:
            selector = new NonRepeatingWeightedTestrunSelector(std::move(tests));
            break;
        case Prioritized:
            selector = new PrioritizedTestrunSelector(std::move(tests));
            break;
        default:
            fprintf(stderr, "ERROR: Cannot run with testrunner type (%d)", selectScheme);
            exit(EX_USAGE);
    }
    selector->load_weights(weight_info, lengthScheme);

    return selector;
}

// TODO: Next cleanup - change this from test selector to simply a test_list fileter
//       That way it can be used with any selector :-)
TestrunSelector *create_list_file_test_selector(std::vector<struct test *> tests, string file_path,
                                                int first_index, int last_index, bool randomize)
{
    if constexpr (SandstoneConfig::RestrictedCommandLine) {
        SANDSTONE_UNREACHABLE("Should not have reached here");
        return nullptr;
    }

    auto selector = new ListFileTestSelector(std::move(tests));
    selector->load_from_file(file_path);
    selector->set_selection_range(first_index, last_index, randomize);
    return selector;
}
