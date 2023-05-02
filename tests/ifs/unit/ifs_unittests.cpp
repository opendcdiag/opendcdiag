/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(__x86_64__) && defined(__linux__)

#include "gtest/gtest.h"
#include "sandstone.h"

#undef log_warning
#define log_warning
#undef log_error
#define log_error
#undef log_info
#define log_info
#undef log_debug
#define log_debug

#include "../sandstone_ifs.c"

#undef PATH_SYS_IFS_BASE
#define PATH_SYS_IFS_BASE

#include "../ifs.c"
#include "ifs_test_cases.h"
#include "ifs_unit_utils.h"

struct cpu_info *cpu_info = nullptr;
int num_cpus() { return IFS_UNIT_NUM_CPUS; }

/*
 * @brief Setup all structs, directory and files needed by test
 */
void *test_setup(ifs_unit setup_data)
{
    // Setup dummy sysfs tree
    setup_sysfs_directory(setup_data);

    // Setup dummy test_t struct
    test *test_t = (test *) malloc(sizeof(test));
    test_t->id = setup_data.name;

    // Setup data
    ifs_test_t *ifs_info = (ifs_test_t *) malloc(sizeof(ifs_test_t));
    ifs_info->sys_dir = setup_data.name;
    test_t->data = ifs_info;

    return test_t;
}

/*
 * @brief Remove files, directory and free structs memory
 */
void test_cleanup(test *test_t, ifs_test_t *ifs_info, ifs_unit setup_data)
{
    // Remove files first
    for (size_t i = 0; i < setup_data.files_sz; i++)
    {
        char tmp_path[IFS_MAX_PATH];
        snprintf(tmp_path, IFS_MAX_PATH, "%s/%s", setup_data.name, setup_data.files[i].file);
        remove(tmp_path);
    }

    // Remove directory
    rmdir(setup_data.name);

    // Free memory allocated
    free(ifs_info);
    free(test_t);
}


/*
 * @test Sysfs driver directory is not present, driver is not supported.
 */
TEST(IFSRequirements, DriverNotFound)
{
    // Create a dummy test struct
    test *test_t = (test *) malloc(sizeof(test));

    // Setup data with dummy sysfs that does not exists
    ifs_test_t *ifs_info = (ifs_test_t *) malloc(sizeof(ifs_test_t));
    ifs_info->sys_dir = "/tmp/intel_ifs_0";
    test_t->data = ifs_info;

    EXPECT_EQ(scan_common_init(test_t), -ENOENT);

    // Free memory allocated
    free(ifs_info);
    free(test_t);
}

/*
 * @test The current_batch file is present, image loading is supported.
 */
TEST(IFSRequirements, CurrentBatchFound)
{
    // Setup dummy test_t struct
    test *test_t = (test *) test_setup(reqs_test2);
    ifs_test_t *ifs_info = (ifs_test_t *) test_t->data;

    // Clean errno, before running
    errno = 0;

    EXPECT_EQ(scan_common_init(test_t), EXIT_SUCCESS);
    EXPECT_TRUE(ifs_info->image_support);
    EXPECT_STREQ(ifs_info->image_id, "0x2");
    EXPECT_STREQ(ifs_info->image_version, reqs_test2.files[2].contents);

    test_cleanup(test_t, ifs_info, reqs_test2);
}

/*
 * @test The current_batch file is not present, image loading is not supported.
 */
TEST(IFSRequirements, CurrentBatchNotFound)
{
    // Setup dummy test_t struct
    test *test_t = (test *) test_setup(reqs_test3);
    ifs_test_t *ifs_info = (ifs_test_t *) test_t->data;

    // Clean errno, before running
    errno = 0;

    EXPECT_EQ(scan_common_init(test_t), EXIT_SUCCESS);
    EXPECT_FALSE(ifs_info->image_support);
    EXPECT_STREQ(ifs_info->image_id, "NA");
    EXPECT_STREQ(ifs_info->image_version, "NA");

    test_cleanup(test_t, ifs_info, reqs_test3);
}

#endif
