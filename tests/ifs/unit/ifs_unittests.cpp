/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(__x86_64__) && defined(__linux__)

#include "gtest/gtest.h"
#include "sandstone_unittests_utils.h"

#include "../sandstone_ifs.c"
#undef PATH_SYS_IFS_BASE
#define PATH_SYS_IFS_BASE

#include "../ifs.c"
#include "ifs_test_cases.h"
#include "ifs_unit_utils.h"

/*
 * @brief Setup all structs, directory and files needed by test
 */
void *test_setup(const ifs_unit &setup_data)
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
void test_cleanup(test *test_t, ifs_test_t *ifs_info, const ifs_unit &setup_data)
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

static const char *file_contents_by_name(const ifs_unit &setup_data, const char *name)
{
    for (size_t i = 0; i < setup_data.files_sz; ++i) {
        if (strcmp(name, setup_data.files[i].file) == 0) {
            return setup_data.files[i].contents;
        }
    }
    return nullptr;
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


/*
 * @test Previous image failed, current_batch file won't be updated.
 */
TEST(IFSRequirements, PreviousImageFail)
{
    // Setup dummy test_t struct
    test *test_t = (test *) test_setup(reqs_test4);
    ifs_test_t *ifs_info = (ifs_test_t *) test_t->data;

    EXPECT_EQ(scan_common_init(test_t), EXIT_SKIP);
    EXPECT_FALSE(ifs_info->image_support);
    EXPECT_STREQ(ifs_info->image_id, "");
    EXPECT_STREQ(ifs_info->image_version, "");

    // Check image wasn't updated
    char contents[256];
    read_sysfs_file(ifs_info->sys_dir, "current_batch", contents);
    EXPECT_STREQ(contents, reqs_test4.files[0].contents);

    test_cleanup(test_t, ifs_info, reqs_test4);
}

/*
 * @test Previous image value "none", then load default image.
 */
TEST(IFSLoadImage, PreviousImageNone)
{
    // Setup dummy test_t struct
    test *test_t = (test *) test_setup(load_test2);
    ifs_test_t *ifs_info = (ifs_test_t *) test_t->data;

    // Open dir and files
    char sys_path[PATH_MAX];
    IGNORE_RETVAL(snprintf(sys_path, PATH_MAX, PATH_SYS_IFS_BASE "%s", ifs_info->sys_dir));
    int ifs_fd = open_sysfs_ifs_base(sys_path);
    int batch_fd = openat(ifs_fd, "current_batch", O_RDWR);
    const char *status_buf = file_contents_by_name(load_test2, "status");

    EXPECT_TRUE(load_test_file(ifs_fd, batch_fd, test_t, ifs_info, status_buf));
    close(batch_fd);
    close(ifs_fd);

    // Check we load the right image
    char contents[256];
    read_sysfs_file(ifs_info->sys_dir, "current_batch", contents);
    EXPECT_STREQ(contents, "0x1e"); //Fix this

    test_cleanup(test_t, ifs_info, load_test2);
}

/*
 * @test Previous image value can be read, but not parsed.
 */
TEST(IFSLoadImage, PreviousImageCannotBeParsed)
{
    // Setup dummy test_t struct
    test *test_t = (test *) test_setup(load_test3);
    ifs_test_t *ifs_info = (ifs_test_t *) test_t->data;

    // Open dir and files
    char sys_path[PATH_MAX];
    IGNORE_RETVAL(snprintf(sys_path, PATH_MAX, PATH_SYS_IFS_BASE "%s", ifs_info->sys_dir));
    int ifs_fd = open_sysfs_ifs_base(sys_path);
    int batch_fd = openat(ifs_fd, "current_batch", O_RDWR);
    const char *status_buf = file_contents_by_name(load_test3, "status");

    EXPECT_FALSE(load_test_file(ifs_fd, batch_fd, test_t, ifs_info, status_buf));
    close(batch_fd);
    close(ifs_fd);

    // Check we load the right image
    char contents[256];
    read_sysfs_file(ifs_info->sys_dir, "current_batch", contents);
    EXPECT_STREQ(contents, load_test3.files[0].contents);

    test_cleanup(test_t, ifs_info, load_test3);
}

/*
 * @test Previous image remains untested, current_batch file won't be updated.
 */
TEST(IFSLoadImage, PreviousImageUntested)
{
    // Setup dummy test_t struct
    test *test_t = (test *) test_setup(load_test4);
    ifs_test_t *ifs_info = (ifs_test_t *) test_t->data;

    // Open dir and files
    char sys_path[PATH_MAX];
    IGNORE_RETVAL(snprintf(sys_path, PATH_MAX, PATH_SYS_IFS_BASE "%s", ifs_info->sys_dir));
    int ifs_fd = open_sysfs_ifs_base(sys_path);
    int batch_fd = openat(ifs_fd, "current_batch", O_RDWR);
    const char *status_buf = file_contents_by_name(load_test4, "status");

    EXPECT_TRUE(load_test_file(ifs_fd, batch_fd, test_t, ifs_info, status_buf));
    close(batch_fd);
    close(ifs_fd);

    // Check we load the right image
    char contents[256];
    read_sysfs_file(ifs_info->sys_dir, "current_batch", contents);
    EXPECT_STREQ(contents, load_test4.files[0].contents);

    test_cleanup(test_t, ifs_info, load_test4);
}

/*
 * @test Load next available image.
 */
TEST(IFSLoadImage, LoadNextImage)
{
    // Setup dummy test_t struct
    test *test_t = (test *) test_setup(load_test5);
    ifs_test_t *ifs_info = (ifs_test_t *) test_t->data;

    // Open dir and files
    char sys_path[PATH_MAX];
    IGNORE_RETVAL(snprintf(sys_path, PATH_MAX, PATH_SYS_IFS_BASE "%s", ifs_info->sys_dir));
    int ifs_fd = open_sysfs_ifs_base(sys_path);
    int batch_fd = openat(ifs_fd, "current_batch", O_RDWR);
    const char *status_buf = file_contents_by_name(load_test5, "status");

    EXPECT_TRUE(load_test_file(ifs_fd, batch_fd, test_t, ifs_info, status_buf));
    close(batch_fd);
    close(ifs_fd);

    // Check we load the right image
    char contents[256];
    read_sysfs_file(ifs_info->sys_dir, "current_batch", contents);
    EXPECT_STREQ(contents, "0xa5");

    test_cleanup(test_t, ifs_info, load_test5);
}


/*
 * @test Trigger IFS on all cores available and all cores succeed.
 */
TEST(IFSTrigger, AllCoresPass)
{
    // Setup dummy test_t struct
    test *test_t = (test *) test_setup(trigger_test1);
    ifs_test_t *ifs_info = (ifs_test_t *) test_t->data;

    // Setup dummy cpu_info array
    int cpu_num = 2;
    cpu_info = new struct cpu_info[cpu_num];
    cpu_info[1].cpu_number = 1;

    // Loop over each cpu
    for (size_t i=0; i < cpu_num; i++)
    {
        char contents[256], expected[256];
        EXPECT_EQ(scan_run(test_t, i), EXIT_SUCCESS);

        // Check we trigger the right cpu
        read_sysfs_file(ifs_info->sys_dir, "run_test", contents);
        sprintf(expected, "%ld", i);
        EXPECT_STREQ(contents, expected);
    }

    delete [] cpu_info;
    test_cleanup(test_t, ifs_info, trigger_test1);
}

/*
 * @test Trigger IFS on all cores available and all cores fail.
 */
TEST(IFSTrigger, AllCoresFail)
{
    // Setup dummy test_t struct
    test *test_t = (test *) test_setup(trigger_test2);
    ifs_test_t *ifs_info = (ifs_test_t *) test_t->data;

    // Setup dummy cpu_info array
    int cpu_num = 2;
    cpu_info = new struct cpu_info[cpu_num];
    cpu_info[1].cpu_number = 1;

    // Loop over each cpu
    for (size_t i=0; i < cpu_num; i++)
    {
        char contents[256], expected[256];
        EXPECT_EQ(scan_run(test_t, i), EXIT_FAILURE);

        // Check we trigger the right cpu
        read_sysfs_file(ifs_info->sys_dir, "run_test", contents);
        sprintf(expected, "%ld", i);
        EXPECT_STREQ(contents, expected);
    }

    delete [] cpu_info;
    test_cleanup(test_t, ifs_info, trigger_test2);
}

/*
 * @test Trigger IFS on all cores available and only one core fail.
 */
TEST(IFSTrigger, SingleCoreFail)
{
    // Setup dummy test_t struct
    test *test_t = (test *) test_setup(trigger_test3);
    ifs_test_t *ifs_info = (ifs_test_t *) test_t->data;

    // Setup dummy cpu_info array
    int cpu_num = 2;
    cpu_info = new struct cpu_info[cpu_num];
    cpu_info[1].cpu_number = 1;

    // First run is expected to pass
    EXPECT_EQ(scan_run(test_t, 0), EXIT_SUCCESS);

    // Second run us expected to fail
    setup_sysfs_file(ifs_info->sys_dir, "status", "fail");
    EXPECT_EQ(scan_run(test_t, 1), EXIT_FAILURE);

    delete [] cpu_info;
    test_cleanup(test_t, ifs_info, trigger_test3);
}

/*
 * @test Trigger IFS on all cores, but none of them can run due cooldown.
 */
TEST(IFSTrigger, AllCoresUntested)
{
    // Setup dummy test_t struct
    test *test_t = (test *) test_setup(trigger_test4);
    ifs_test_t *ifs_info = (ifs_test_t *) test_t->data;

    // Setup dummy cpu_info array
    int cpu_num = 2;
    cpu_info = new struct cpu_info[cpu_num];
    cpu_info[1].cpu_number = 1;

    // Loop over each cpu
    for (size_t i=0; i < cpu_num; i++)
    {
        char contents[256], expected[256];
        EXPECT_EQ(scan_run(test_t, i), -EAGAIN);

        // Check we trigger the right cpu
        read_sysfs_file(ifs_info->sys_dir, "run_test", contents);
        sprintf(expected, "%ld", i);
        EXPECT_STREQ(contents, expected);
    }

    delete [] cpu_info;
    test_cleanup(test_t, ifs_info, trigger_test4);
}

#endif
