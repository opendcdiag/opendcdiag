/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gtest/gtest.h"
#include <unordered_map>
#include <vector>
#include <cstdlib>
#include <map>
#include <SelectorFactory.h>

extern "C" unsigned int  random32(){ return random(); }  // Mocked

#include "test_selectors/SelectorFactory.h"
#include "ListFileSelector.h"
#include "OrderedSelector.h"
#include "PrioritizedSelector.h"
#include "WeightedRepeatingSelector.h"
#include "WeightedNonRepeatingSelector.h"

struct test mce_test = {
    .id = "mce_check",
    .description = "mce_check"
};

class WeightedTestSelectorFixture : public ::testing::Test {
protected:
    std::unordered_map<std::string, int> counts;
    std::unordered_map<std::string, int> expected_counts;

    struct test the_tests[4] = {
        {.id="test0_id", .description="test0_name", .desired_duration=500, .quality_level=TEST_QUALITY_PROD},
        {.id="test1_id", .description="test1_name", .desired_duration=500, .quality_level=TEST_QUALITY_PROD},
        {.id="test2_id", .description="test2_name", .desired_duration=500, .quality_level=TEST_QUALITY_PROD},
        {.id="test3_id", .description="test3_name", .desired_duration=500, .quality_level=TEST_QUALITY_PROD},

    };
    std::vector<struct test *> one_test;
    std::vector<struct test *> two_tests;
    std::vector<struct test *> four_tests;

    struct weighted_run_info empty_weights[1] = { {nullptr} };

    struct weighted_run_info one_weight[2] = {
            {.test=&the_tests[0],   .weight=1,  .duration_ms = 100},
            {nullptr}
    };
    struct weighted_run_info two_weights[3] = {
            {.test=&the_tests[0],   .weight=1,  .duration_ms = 100},
            {.test=&the_tests[1],   .weight=1,  .duration_ms = 100},
            {nullptr}
    };

    struct weighted_run_info four_weights[5] = {
            {.test=&the_tests[0],   .weight=1,  .duration_ms = 100},
            {.test=&the_tests[1],   .weight=1,  .duration_ms = 100},
            {.test=&the_tests[2],   .weight=1,  .duration_ms = 100},
            {.test=&the_tests[3],   .weight=1,  .duration_ms = 100},
            {nullptr}
    };

    void SetUp() override {
        srand(time(nullptr));

        for (int i=0; i<4; i++){
            if (i<1) one_test.push_back(&the_tests[i]);
            if (i<2) two_tests.push_back(&the_tests[i]);
            four_tests.push_back(&the_tests[i]);
        }
    }

    void expectSelectorDistribution(TestrunSelector * selector, int num_calls, unordered_map<string, int> expected, bool debug = false) {
        _expectDistribution(selector, num_calls, expected, debug);
    }

    void _expectDistribution(TestrunSelector *selector, int num_calls, unordered_map<string, int> &expected, bool debug) {
        expected_counts = expected;

        collect_distribution_counts(selector, num_calls);

        if (debug) print_counts();

        // Check distributions using both maps to look for missing elements in
        // either one in case a bad value was selected at one point
        for (auto &ele : expected_counts)
            expectDistributionInRange(ele.first); // ele.first is test id

        for (auto &ele : counts)
            expectDistributionInRange(ele.first); // ele.first is test id

    }

    void collect_distribution_counts(TestrunSelector *selector, int num_calls) {
        for (int i = 0; i < num_calls; i++) {
            auto test = selector->get_next_test();
            if (test == nullptr)
                test = selector->get_next_test();

            const char *selected_test_id = test->id;
            counts[selected_test_id]++;
        }
    }

    void expectDistributionInRange(const string &testid) {
        int expected = expected_counts[testid];
        int actual = counts[testid];
        int tolerance = expected / 10;  // 10% tolerance for random distribution checking
        ASSERT_NEAR(actual, expected, tolerance)
                                    << "ERROR: Distribution Error for value " << testid << ":\n"
                                    << "    Got " << actual << " Hits.\n"
                                    << "    Expected " << expected << " +/- " << tolerance << "\n";
    }

    void print_counts() {
        for (auto ele : counts) {
            printf("%s : %d  exp=%d\n", ele.first.c_str(), ele.second, expected_counts["testA"]);
        }
    }
};


TEST_F(WeightedTestSelectorFixture, assertionKillsRunWhenNoWeightsLoaded)
{
    RepeatingWeightedTestrunSelector repeating_selector({});
    EXPECT_DEATH(repeating_selector.select_test(), "");
}

TEST_F(WeightedTestSelectorFixture, oneItemOnly) {
    auto selector = setup_test_selector(Repeating, NormalTestrunTimes, one_test, one_weight);
    EXPECT_STREQ(selector->get_next_test()->id, "test0_id");
}

TEST_F(WeightedTestSelectorFixture, twoItemsCanBothBeSelected)
{
    auto selector = setup_test_selector(Repeating, NormalTestrunTimes, two_tests, two_weights);
    expectSelectorDistribution(selector, 2000,
                               {{"test0_id", 1000},
                                {"test1_id", 1000}
                               });
}

TEST_F(WeightedTestSelectorFixture, FourItemsHaveProperDistribution)
{
    auto selector = setup_test_selector(Repeating, NormalTestrunTimes, four_tests, four_weights);
    expectSelectorDistribution(selector, 4000,
                               {{"test0_id", 1000},
                                {"test1_id", 1000},
                                {"test2_id", 1000},
                                {"test3_id", 1000},
                               });
}

TEST_F(WeightedTestSelectorFixture, FourItemsWithUnevenWeightsHaveProperDistribution)
{
    four_weights[0].weight = 1;
    four_weights[1].weight = 1;
    four_weights[2].weight = 2;
    four_weights[3].weight = 0;
    auto selector = setup_test_selector(Repeating, NormalTestrunTimes, four_tests, four_weights);
    expectSelectorDistribution(selector, 4000,
                               {{"test0_id", 1000},
                                {"test1_id", 1000},
                                {"test2_id", 2000},
                                {"test3_id",    0},
                               });
}

TEST_F(WeightedTestSelectorFixture, test_GivenRuninfoWithPositiveDuration_WhenLoaded_ThenDurationComesFromRuninfo)
{
    one_weight[0].test_index = -1;    // make sure index is initialized to bad value
    one_test[0]->desired_duration = 999;
    one_weight[0].duration_ms = 200;

    auto selector = setup_test_selector(Repeating, NormalTestrunTimes, one_test, one_weight);
    (void)selector;

    EXPECT_EQ(one_weight[0].duration_ms, 200);  // duration from runinfo not test
    EXPECT_EQ(one_weight[0].test_index, 0);    // Oppotunistically check the index is correct
}


TEST_F(WeightedTestSelectorFixture, loadingTestsAndWeightsAndGenerateTestDistributions)
{
    two_weights[0].weight = 10;
    two_weights[1].weight = 10;

    auto selector = setup_test_selector(Repeating, NormalTestrunTimes, two_tests, two_weights);

    expectSelectorDistribution(selector, 4000,
                               {{"test0_id", 2000},
                                {"test1_id", 2000}});
}


TEST_F(WeightedTestSelectorFixture, test_NonRepeatingSelector_WillNotAllowCountsToBeOffByMoreThanOne)
{
    two_weights[0].weight = 1;
    two_weights[1].weight = 9999999;

    auto selector = setup_test_selector(NonRepeating, NormalTestrunTimes, two_tests, two_weights);

    for(int i=0; i<10; i++) {
        counts.clear();
        selector->reset_selector();
        collect_distribution_counts(selector, 101);
        EXPECT_EQ(counts["test0_id"], 50);
        EXPECT_EQ(counts["test1_id"], 51);
    }
}

TEST_F(WeightedTestSelectorFixture, test_GivenTestDuration_WhenWeUseShortenedRuntime_ThenWeGetHalfTheDefaultDuration)
{
    one_test[0]->desired_duration = 500;
    one_weight[0].duration_ms = 100;

    auto selector = setup_test_selector(Repeating, ShortenedTestrunTimes, one_test, one_weight);
    EXPECT_EQ(selector->get_next_test()->desired_duration, 50);
}

TEST_F(WeightedTestSelectorFixture, test_GivenTestDuration_WhenWeUseNormalRuntime_ThenWeGetDefaultDuration)
{
    one_test[0]->desired_duration = 500;
    one_weight[0].duration_ms = 100;

    auto selector = setup_test_selector(Repeating, NormalTestrunTimes, one_test, one_weight);
    EXPECT_EQ(selector->get_next_test()->desired_duration, 100);
}

TEST_F(WeightedTestSelectorFixture, test_GivenTestDuration_WhenWeUseLongerRuntime_ThenWeGetLongerDuration)
{
    one_test[0]->desired_duration = 500;
    one_weight[0].duration_ms = 100;

    auto selector = setup_test_selector(Repeating, LongerTestrunTimes, one_test, one_weight);

    EXPECT_EQ(selector->get_next_test()->desired_duration, 500);
}


TEST_F(WeightedTestSelectorFixture, test_GivenOnePriorityTestInList_WhenSelectionAreMade_ThenWeDontRepeatThePriorityTest)
{
    two_weights[0].weight = SCREEN_PRIORITY_TEST_WEIGHT_THRESHOLD;
    two_weights[1].weight = SCREEN_PRIORITY_TEST_WEIGHT_THRESHOLD - 1;  // non priority

    for (int i=0; i<10; i++) {
        auto selector = setup_test_selector(Prioritized, LongerTestrunTimes, two_tests, two_weights);

        auto first_test = selector->get_next_test();
        auto second_test = selector->get_next_test();

        EXPECT_STREQ(first_test->id, "test0_id");
        EXPECT_STRNE(second_test->id, "test0_id");
    }
}



TEST_F(WeightedTestSelectorFixture, test_GivenATestIsNotInRuninfoList_WhenWeAddAllWeights_ThenUnspecifiedTestsHaveWeightOfOne)
{
    auto selector = (RepeatingWeightedTestrunSelector *) setup_test_selector(Repeating, NormalTestrunTimes, one_test, empty_weights);

    auto list = selector->get_weighted_runinfo_list();
    EXPECT_EQ(list.size(), 1);
    EXPECT_EQ(list.front()->weight, 1);
}

TEST_F(WeightedTestSelectorFixture, test_GivenAWeightForTestNotInRuninfoList_WhenWeAddAllWeights_ThenthatWeightIsNotAdded)
{
    two_weights[1].test = nullptr;
    auto selector = (RepeatingWeightedTestrunSelector *) setup_test_selector(Repeating, NormalTestrunTimes, one_test, two_weights);

    auto weight_records = selector->get_weighted_runinfo_list();
    EXPECT_EQ(weight_records.size(), 1);
    EXPECT_EQ(weight_records.front()->test->id, "test0_id");
}


TEST_F(WeightedTestSelectorFixture, test_GivenATestIsNotInRuninfoList_WhenWeAddAllWeights_ThenUnspecifiedTestsHaveWeightOfOne_PPV)
{
    struct test test_1 = {.id="priority_1", .description="test0_name", .desired_duration=500, .quality_level=TEST_QUALITY_PROD};
    struct test test_2 = {.id="priority_2", .description="test0_name", .desired_duration=500, .quality_level=TEST_QUALITY_PROD};
    struct test test_3 = {.id="lower", .description="test0_name", .desired_duration=500, .quality_level=TEST_QUALITY_PROD};
    struct weighted_run_info ppv_runinfo[] = {
            {.test=&test_1, .weight=SCREEN_PRIORITY_TEST_WEIGHT_THRESHOLD, .duration_ms = 100},
            {.test=&test_2, .weight=SCREEN_PRIORITY_TEST_WEIGHT_THRESHOLD, .duration_ms = 100},
            {.test=&test_3, .weight=SCREEN_PRIORITY_TEST_WEIGHT_THRESHOLD - 1, .duration_ms = 100},
            {nullptr}
    };

    std::vector<struct test *> tests;
    tests.push_back(&test_1);
    tests.push_back(&test_2);
    tests.push_back(&test_3);


    for (int trials = 0; trials < 50; ++trials) {
        auto selector = setup_test_selector(Prioritized, NormalTestrunTimes, tests, ppv_runinfo);

        std::vector<std::string> picks;
        std::map<std::string, int> counts;

        for (int num_selections = 0; num_selections < 50; ++num_selections) {
            auto test = selector->get_next_test();
            if (test == nullptr)
                test = selector->get_next_test();
            picks.emplace_back(test->id);
            counts[test->id]++;
        }
        ASSERT_TRUE(picks[0] == "priority_1" || picks[0] == "priority_2");
        ASSERT_TRUE(picks[1] == "priority_1" || picks[1] == "priority_2");
        ASSERT_TRUE(counts["lower"] > 0);
        ASSERT_TRUE(counts["priority_1"] > 1);
    }
}

TEST_F(WeightedTestSelectorFixture, GivenAphabeticalSelectorTestsExecuteAphabetically_AndEndInNull)
{
    four_tests[0]->id = "ghi";
    four_tests[1]->id = "def";
    four_tests[2]->id = "jkl";
    four_tests[3]->id = "abc";
    auto selector = setup_test_selector(Alphabetical, NormalTestrunTimes, four_tests, empty_weights);
    for (int i=0; i<3; i++) {
        ASSERT_STREQ(selector->get_next_test()->id, "abc");
        ASSERT_STREQ(selector->get_next_test()->id, "def");
        ASSERT_STREQ(selector->get_next_test()->id, "ghi");
        ASSERT_STREQ(selector->get_next_test()->id, "jkl");
        ASSERT_EQ(selector->get_next_test(), nullptr);
    }
}

TEST_F(WeightedTestSelectorFixture, GivenAphabeticalSelector_LastTestIs_mce_check)
{
    four_tests[0]->id = "z";
    four_tests[1] = &mce_test;
    four_tests[2]->id = "x";
    four_tests[3]->id = "a";
    auto selector = setup_test_selector(Alphabetical, NormalTestrunTimes, four_tests, empty_weights);
    for (int i=0; i<3; i++) {
        ASSERT_STREQ(selector->get_next_test()->id, "a");
        ASSERT_STREQ(selector->get_next_test()->id, "x");
        ASSERT_STREQ(selector->get_next_test()->id, "z");
        ASSERT_STREQ(selector->get_next_test()->id, "mce_check");
        ASSERT_EQ(selector->get_next_test(), nullptr);
    }
}

//=======================================================
TEST_F(WeightedTestSelectorFixture, GivenOrderedSelector_ExecuteTestsInOrderProvided)
{
    four_tests[0]->id = "test1";
    four_tests[1]->id = "test2";
    four_tests[2]->id = "test3";
    four_tests[3]->id = "test4";
    auto selector = setup_test_selector(Ordered, NormalTestrunTimes, four_tests, empty_weights);
    for (int i=0; i<3; i++) {
        ASSERT_STREQ(selector->get_next_test()->id, "test1");
        ASSERT_STREQ(selector->get_next_test()->id, "test2");
        ASSERT_STREQ(selector->get_next_test()->id, "test3");
        ASSERT_STREQ(selector->get_next_test()->id, "test4");
        ASSERT_EQ(selector->get_next_test(), nullptr);
    }
}

//=======================================================




// ====================================================================
// List file Selector Tests
// ====================================================================
TEST_F(WeightedTestSelectorFixture, assertionKillsRunWhenBadTestExists)
{
    stringstream  file_contents( "foo : 100\n" );

    auto selector = new ListFileTestSelector(four_tests);
    EXPECT_DEATH(selector->load_from_stream(file_contents), "");
}

TEST_F(WeightedTestSelectorFixture, assertionKillsRunWhenDurationStringIsBad)
{
    stringstream  file_contents( "test0_id : bad_value\n" );

    auto selector = new ListFileTestSelector(four_tests);
    EXPECT_DEATH(selector->load_from_stream(file_contents), "");
}


TEST_F(WeightedTestSelectorFixture, GivenInputFileForTestList_SelectAllTestsInOrder_EndInNull)
{
    stringstream  file_contents(
            "test1_id\n"
            "test2_id\n"
            "test1_id\n"
            "\n" // blank line
            "   \n" // blank line
            "# comment line\n"
            );

    auto selector = new ListFileTestSelector(four_tests);
    selector->load_from_stream(file_contents);
    for (int i=0; i<5; i++) {
        ASSERT_STREQ(selector->get_next_test()->id, "test1_id");
        ASSERT_STREQ(selector->get_next_test()->id, "test2_id");
        ASSERT_STREQ(selector->get_next_test()->id, "test1_id");
        ASSERT_EQ(selector->get_next_test(), nullptr);
    }
}

TEST_F(WeightedTestSelectorFixture, GivenInputFileForTestList_CheckDurationsAreConfigurable)
{
    stringstream  file_contents(
            "test1_id : 200 \n"
            "test2_id : 250s \n"
            "test1_id\n"   // not specified - should be original default (500)
            "test2_id : default\n"   // explicit default - should be original default (500)
            );

    auto selector = new ListFileTestSelector(four_tests);
    selector->load_from_stream(file_contents);
    ASSERT_EQ(selector->get_next_test()->desired_duration, 200);
    ASSERT_EQ(selector->get_next_test()->desired_duration, 250 * 1000);
    ASSERT_EQ(selector->get_next_test()->desired_duration, 500);
    ASSERT_EQ(selector->get_next_test()->desired_duration, 500);
    ASSERT_EQ(selector->get_next_test(), nullptr);
}

void assertTestID(struct test * intest, const char * expected){
    ASSERT_NE(intest, nullptr) << "Expected id but got null test ptr";
    ASSERT_STREQ(intest->id, expected);

}

TEST_F(WeightedTestSelectorFixture, GivenARangeOfTEstsToRun_WeOnlyRunThoseTests)
{
    stringstream  file_contents(
            "test1_id\n"
            "test2_id\n"
            "test3_id\n"
            "test0_id\n"
    );

    auto selector = new ListFileTestSelector(four_tests);
    selector->load_from_stream(file_contents);
    selector->set_selection_range(2, 3, false);
    for (int i=0; i<5; i++) {
        assertTestID(selector->get_next_test(), "test2_id");
        assertTestID(selector->get_next_test(), "test3_id");
        ASSERT_EQ(selector->get_next_test(), nullptr);
    }
}


TEST_F(WeightedTestSelectorFixture, GivenARangeThatIsTooBig_WeResetSelectorAtEndOfList)
{
    stringstream  file_contents(
            "test1_id\n"
            "test2_id\n"
            "test3_id\n"
            "test0_id\n"
    );

    auto selector = new ListFileTestSelector(four_tests);
    selector->load_from_stream(file_contents);
    selector->set_selection_range(2, 30, false);
    for (int i=0; i<5; i++) {
        assertTestID(selector->get_next_test(), "test2_id");
        assertTestID(selector->get_next_test(), "test3_id");
        assertTestID(selector->get_next_test(), "test0_id");
        ASSERT_EQ(selector->get_next_test(), nullptr);
    }

}


