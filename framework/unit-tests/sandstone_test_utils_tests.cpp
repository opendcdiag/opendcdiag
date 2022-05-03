/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <vector>
#include "gtest/gtest.h"
#include "sandstone_test_utils.h"


class CodeBufferTestFixture : public ::testing::Test {
public:
    ManagedCodeBuffer  code_buffer;
    const int function_return_value = 0xaced;

    // Copies the following asm into the buffer:
    //    mov eax, 0xaced
    //    ret
    void copy_code_to_buffer(){
        uint8_t code[] = {0xb8, 0xed, 0xac, 0x00, 0x00, 0xc3};  // returns 0xaced
        memcpy(code_buffer.ptr(), code, std::size(code));
    }
};

TEST_F(CodeBufferTestFixture, SuccessfulAllocateReturnsTrue) {
    auto success = code_buffer.allocate(100);
    EXPECT_EQ( success, true ) << "Pointer was " << code_buffer.ptr();
    EXPECT_EQ( code_buffer.is_valid(), true ) << "Pointer was " << code_buffer.ptr();
}

TEST_F(CodeBufferTestFixture, UnsuccessfulAllocateReturnsFalse) {
    auto success = code_buffer.allocate(INTMAX_MAX);  // definitely won't allocate
    EXPECT_EQ( success, false ) << "Pointer was " << code_buffer.ptr();
    EXPECT_EQ( code_buffer.is_valid(), false ) << "Pointer was " << code_buffer.ptr();
}

TEST_F(CodeBufferTestFixture, CanWriteAndExecuteBuffer) {
    code_buffer.allocate(100);
    copy_code_to_buffer();
    code_buffer.set_executable();

    auto funcptr = (int(*)()) code_buffer.ptr();
    auto return_value = funcptr();

    EXPECT_EQ(return_value, function_return_value );
}

TEST_F(CodeBufferTestFixture, CannotExecuteUntilSetExecutable) {
    code_buffer.allocate(100);
    copy_code_to_buffer();

    auto funcptr = (int(*)()) code_buffer.ptr();
    EXPECT_DEATH(funcptr(), "");
}

TEST_F(CodeBufferTestFixture, AllocatingBufferAtParticularAddress) {
    // Address must be page aligned or mmap gives invalid address
    code_buffer.allocate_at((void *) 0x1234560000, 100);
    EXPECT_EQ((size_t) code_buffer.ptr(), 0x1234560000);
}

