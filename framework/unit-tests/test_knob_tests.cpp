/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <algorithm>
#include <vector>
#include "gtest/gtest.h"
#include "test_knobs.h"

#include "sandstone.h"       // for struct test

void clear_test_knobs();

struct UsedKeyValues
{
    std::string key;
    TestKnobValue value;
    KnobOrigin origin;
};
static std::vector<UsedKeyValues> used_key_values;

class KnobTestSuite : public ::testing::Test {
    void SetUp() override {
        // knobs are contained in a singleton so
        // we need to clear them out between tests
        clear_test_knobs();
        used_key_values.clear();;
    }
};

void logging_mark_knob_used(std::string_view key, TestKnobValue value, KnobOrigin origin)
{
    used_key_values.emplace_back(UsedKeyValues{std::string(key), value, origin});
}

// ------------------------------
// Helper Methods
// ------------------------------
__attribute__((unused))
static std::ostream &operator<<(std::ostream &s, TestKnobValue value)
{
    std::visit([&s](auto v) { s << v; }, value);
    return s;
}

static void assertUnsignedValues(const char *knob, uint64_t expect_64)
{
    uint64_t val_u64 = get_test_knob_value_uint(knob, 0xdead);
    EXPECT_EQ(val_u64, expect_64);
}

static void assertSignedValues(const char *knob, int64_t expect_64)
{
    int64_t val_64 = get_test_knob_value_int(knob, 0);
    EXPECT_EQ(val_64, expect_64);
}

static void assertKnobWasUsed(std::string_view knob, TestKnobValue expected, KnobOrigin origin)
{
    auto cmp = [knob](const UsedKeyValues &e) {
        return e.key == knob;
    };
    auto it = std::find_if(used_key_values.cbegin(), used_key_values.cend(), cmp);
    ASSERT_NE(it, used_key_values.cend());
    EXPECT_EQ(it->origin, origin);
    EXPECT_EQ(it->value, expected);
}

// ------------------------------
// Tests
// ------------------------------
TEST_F(KnobTestSuite, test_can_retrieve_simple_uint_value) {
    set_knob_from_key_value_string("One=1");
    set_knob_from_key_value_string("Ten=10");
    set_knob_from_key_value_string("SixteenHex=0x10");
    EXPECT_EQ(get_test_knob_value_uint("One", 0), 1);
    EXPECT_EQ(get_test_knob_value_uint("Ten", 0), 10);
    EXPECT_EQ(get_test_knob_value_uint("SixteenHex", 0), 16);

    assertKnobWasUsed("SixteenHex", UINT64_C(0x10), KnobOrigin::Options);
    assertKnobWasUsed("Ten", UINT64_C(10), KnobOrigin::Options);
    assertKnobWasUsed("One", UINT64_C(1), KnobOrigin::Options);
}

TEST_F(KnobTestSuite, if_key_exists_default_ignored) {
    set_knob_from_key_value_string("Ten=10");
    EXPECT_EQ(get_test_knob_value_uint("Ten", 20), 10);
    assertKnobWasUsed("Ten", UINT64_C(10), KnobOrigin::Options);
}

TEST_F(KnobTestSuite, if_key_does_not_exists_default_used){
    EXPECT_EQ(get_test_knob_value_uint("NonExistingKey", 20), 20);
    assertKnobWasUsed("NonExistingKey", UINT64_C(20), KnobOrigin::Defaulted);
};

TEST_F(KnobTestSuite, test_can_retrieve_int_value) {
    set_knob_from_key_value_string("One=1");
    set_knob_from_key_value_string("NegOne=-1");
    EXPECT_EQ(get_test_knob_value_int("One", 0), 1);
    EXPECT_EQ(get_test_knob_value_int("NegOne", 0), -1);
    assertKnobWasUsed("One", INT64_C(1), KnobOrigin::Options);
    assertKnobWasUsed("NegOne", INT64_C(-1), KnobOrigin::Options);
}

TEST_F(KnobTestSuite, test_can_retrieve_string_value) {
    set_knob_from_key_value_string("Key1=Key1_Value");
    EXPECT_STREQ(get_test_knob_value_string("Key1", "X"), "Key1_Value");
    assertKnobWasUsed("Key1", std::string("Key1_Value"), KnobOrigin::Options);
}

TEST_F(KnobTestSuite, if_key_exists_default_string_ignored) {
    set_knob_from_key_value_string("Key1=Key1_Value");
    EXPECT_STREQ(get_test_knob_value_string("Key1", "Default"), "Key1_Value");
    assertKnobWasUsed("Key1", std::string("Key1_Value"), KnobOrigin::Options);
}

TEST_F(KnobTestSuite, if_key_does_not_exists_default_string_used){
    EXPECT_STREQ(get_test_knob_value_string("NonExistingKey", "Default"), "Default");
    assertKnobWasUsed("NonExistingKey", std::string("Default"), KnobOrigin::Defaulted);
}

TEST_F(KnobTestSuite, test_name_prepended_to_key) {
    struct test t = { .id = "TestName" };
    set_knob_from_key_value_string("Key1=WrongValue");
    set_knob_from_key_value_string("TestName.Key1=Key1_Value");

    EXPECT_STREQ(get_testspecific_knob_value_string(&t, "Key1", "Default"), "Key1_Value");
    EXPECT_STREQ(get_testspecific_knob_value_string(&t, "NonExistingKey", "Default"), "Default");
    assertKnobWasUsed("TestName.Key1", std::string("Key1_Value"), KnobOrigin::Options);
    assertKnobWasUsed("TestName.NonExistingKey", std::string("Default"), KnobOrigin::Defaulted);
}

TEST_F(KnobTestSuite, read_knob_from_cmdline_argument_string){
    auto retval = set_knob_from_key_value_string("FOO=10");
    EXPECT_EQ(retval, true);
    EXPECT_EQ(get_test_knob_value_uint("FOO", 0), 10);
};

TEST_F(KnobTestSuite, malformed_cmdline_argument_with_no_value_returns_failure){
    EXPECT_EQ(set_knob_from_key_value_string("FOO"), false);
};

TEST_F(KnobTestSuite, malformed_cmdline_argument_with_extra_value_returns_failure){
    EXPECT_EQ(set_knob_from_key_value_string("FOO=5=6"), false);
};

TEST_F(KnobTestSuite, test_attempt_to_set_empty_value_is_parse_error){
    EXPECT_EQ(set_knob_from_key_value_string("FOO="), false);
};

TEST_F(KnobTestSuite, given_unset_knobs_when_repeated_gets_called_then_default_is_laways_returned){
    // make sure that repeated get calls do not accidentally create the keys in the knob map
    for (int i=0; i<5; i++) {
        auto first = get_test_knob_value_uint("FOO", 123);
        auto second = get_test_knob_value_int("FOO", 123);
        auto third = get_test_knob_value_string("FOO", "123");

        EXPECT_EQ(first, 123);
        EXPECT_EQ(second, 123);
        EXPECT_STREQ(third, "123");
    }
};

TEST_F(KnobTestSuite, set_knob_to_non_numeric_value_and_get_as_int_returns_default_value){
    set_knob_from_key_value_string("FOO=BAR");
    ASSERT_EQ(get_test_knob_value_uint("FOO", 123), 123);
};

TEST_F(KnobTestSuite, extreme_negative_value_testing_signed) {
    set_knob_from_key_value_string("Neg1=-1");
    assertUnsignedValues("Neg1", 0xFFFFFFFFFFFFFFFF);
    assertSignedValues("Neg1", -1);
}

TEST_F(KnobTestSuite, extreme_hex_value_testing_unsigned) {
    set_knob_from_key_value_string("AllOnes=0xFFFFFFFFFFFFFFFF");
    assertUnsignedValues("AllOnes", 0xFFFFFFFFFFFFFFFF);
    assertSignedValues("AllOnes", -1);
}

TEST_F(KnobTestSuite, test_all_ones_except_msb) {
    set_knob_from_key_value_string("NotAllOnes=0x7FFFFFFFFFFFFFFF");
    assertUnsignedValues("NotAllOnes", 0x7FFFFFFFFFFFFFFF);
    assertSignedValues("NotAllOnes", 0x7FFFFFFFFFFFFFFF);
}

TEST_F(KnobTestSuite, test_all_zero_except_msb_aka_zero_indefinite) {
    set_knob_from_key_value_string("NotAllOnes=0x8000000000000000");
    assertUnsignedValues("NotAllOnes", 0x8000000000000000);
    assertSignedValues("NotAllOnes", 0x8000000000000000);
}

TEST_F(KnobTestSuite, test_simple_float64_one_value) {
    set_knob_from_key_value_string("OneValue=1");
    auto value = get_test_knob_value_double("OneValue", 0xdead);
    EXPECT_EQ(value, 1.0);
}

TEST_F(KnobTestSuite, test_simple_float64_one_point_zero_value) {
    set_knob_from_key_value_string("OnePtZeroValue=1.0");
    auto value = get_test_knob_value_double("OnePtZeroValue", 0xdead);
    EXPECT_EQ(value, 1.0);
}

TEST_F(KnobTestSuite, test_simple_float64_one_point_five_value) {
    set_knob_from_key_value_string("OnePt5Value=1.5");
    auto value = get_test_knob_value_double("OnePt5Value", 0xdead);
    EXPECT_EQ(value, 1.5f);
}

TEST_F(KnobTestSuite, test_simple_float64_default_value) {
    auto value = get_test_knob_value_double("UnusedKnob", 2.5);
    EXPECT_EQ(value, 2.5f);
}

TEST_F(KnobTestSuite, test_simple_float64_malformed_value_string_returns_default) {
    set_knob_from_key_value_string("MalformedKnob=blah.0.0");
    auto value = get_test_knob_value_double("MalformedKnob", 3.5);
    EXPECT_EQ(value, 3.5f);
}


// If these tests fail delete it!
TEST_F(KnobTestSuite, extreme_test_value_out_of_64_bit_range_saturates) {
    // It is just documenting out of range behavior.
    // We should not count on this behavior - it is okay to change
    set_knob_from_key_value_string("OutOfRange=0x1FFFFFFFFFFFFFFFF");
    assertUnsignedValues("OutOfRange", 0xFFFFFFFFFFFFFFFF);
    assertSignedValues("OutOfRange", -1);
}
