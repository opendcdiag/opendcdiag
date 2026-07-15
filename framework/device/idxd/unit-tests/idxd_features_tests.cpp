/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "idxd_device.h"

#include "gtest/gtest.h"

class IdxdFeatureTestSuite : public ::testing::Test
{
protected:
    device_features_t device_features = 0;
};

TEST_F(IdxdFeatureTestSuite, NoFeaturesMeansNoMatch)
{
    EXPECT_FALSE(device_has_feature(device_feature_dsa));
    EXPECT_FALSE(device_has_feature(device_feature_iax));
    EXPECT_FALSE(device_has_feature(device_feature_dsa_v2));
    EXPECT_FALSE(device_has_feature(device_feature_iax_v3));
}

TEST_F(IdxdFeatureTestSuite, DsaVersionBitsMatchSameFamily)
{
    device_features = device_feature_dsa // we mimic what detect_features() do
            | device_feature_dsa_v1
            | device_feature_dsa_v2;

    EXPECT_TRUE(device_has_feature(device_feature_dsa));
    EXPECT_TRUE(device_has_feature(device_feature_dsa_v1));
    EXPECT_TRUE(device_has_feature(device_feature_dsa_v2));
    EXPECT_FALSE(device_has_feature(device_feature_dsa_v3));
    EXPECT_FALSE(device_has_feature(device_feature_iax));
}

// case with DSA V2 & IAX V3 in one system
TEST_F(IdxdFeatureTestSuite, MixedFamiliesDoNotCreateFalsePositiveTypeSpecificMatches)
{
    device_features = device_feature_dsa // we mimic what detect_features() do
            | device_feature_iax
            | device_feature_dsa_v1
            | device_feature_dsa_v2
            | device_feature_iax_v1
            | device_feature_iax_v2
            | device_feature_iax_v3;

    EXPECT_TRUE(device_has_feature(device_feature_dsa_v2));
    EXPECT_TRUE(device_has_feature(device_feature_iax_v3));
    EXPECT_FALSE(device_has_feature(device_feature_dsa_v3));
}

TEST_F(IdxdFeatureTestSuite, TypePresenceBitDoesNotImplyTypeSpecificVersionBit)
{
    device_features = device_feature_dsa;

    EXPECT_TRUE(device_has_feature(device_feature_dsa));
    EXPECT_FALSE(device_has_feature(device_feature_dsa_v1));
    EXPECT_FALSE(device_has_feature(device_feature_dsa_v2));
    EXPECT_FALSE(device_has_feature(device_feature_dsa_v3));
}

TEST(IdxdFeatureBits, FeatureBitsAreDistinct)
{
    static_assert((device_feature_dsa & device_feature_iax) == 0);
    static_assert((device_feature_dsa_v1 & device_feature_iax_v1) == 0);
    static_assert((device_feature_dsa_v2 & device_feature_iax_v2) == 0);
    static_assert((device_feature_dsa_v3 & device_feature_iax_v3) == 0);
    SUCCEED();
}
