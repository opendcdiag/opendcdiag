/*
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * This file is intended for constructs and functions intended for tests to
 * use.
 *
 *  PLEASE READ BEFORE EDITING:
 *     This is a clean file, meaning everything in it is properly unit tested
 *     Please do not add anything to this file unless it is unit tested.
 *     All unit tests should be put in framework/unit-tests/sandstone_test_utils_tests.cpp
 *
 */


#ifndef SANDSTONE_TEST_UTILS_H
#define SANDSTONE_TEST_UTILS_H
#include <sys/mman.h>
#include <cstdint>

// These macros have been copied from sandstone_p.h because sandstone_p.h creates
// too many dependencies to get under unit-test.  Eventually we should refactor
// simple macros like this out of sandstone_p.h to  break these dependencies
#define ROUND_UP_TO(value, n)       (((value) + (n) - 1) & (~((n) - 1)))
#define ROUND_UP_TO_PAGE(value)     ROUND_UP_TO(value, 4096U)


/* ManagedCodeBuffer
 *
 * The purpose of this is to allocate, free and protect memory buffers
 * that are intended for self-modifying-code situations or times when
 * you want to use xbyak and lock down the address of a given code block
 *
 * In general the usage of this will look like:
 *    ManagedCodeBuffer code_buffer;
 *    if (code_buffer.allocate(size)){
 *        copy_or_assemble_code_to(code_buffer.ptr());
 *        code_buffer.set_executable();
 *    }
 *    // The code block will be freed in the destructor of the ManagedCodeBuffer
 *
 * You can also use allocate_at(address, size) to lock down an address that you want
 * for the code block but there are some restrictions imposed by the mmap call - namely
 * the address supplied must be page aligned.
 *
*/
class ManagedCodeBuffer {
    uint8_t * buffer_ptr{static_cast<uint8_t *>(MAP_FAILED)}; // nullptr is a valid address for mmap, MAP_FAILED is not
    size_t buffer_size{0};
public:
    ~ManagedCodeBuffer(){
        free_code_buffer();
    }

    bool allocate(size_t size) {
        free_code_buffer();
        buffer_ptr = static_cast<uint8_t *>(
                mmap(nullptr, ROUND_UP_TO_PAGE(size), (PROT_READ | PROT_WRITE), (MAP_ANONYMOUS | MAP_PRIVATE), -1, 0)
        );
        buffer_size = (is_valid()) ? size : 0;
        return is_valid();
    }

    // Address passed in MUST be page aligned
    bool allocate_at(void * at_address, size_t size){
        free_code_buffer();
        buffer_ptr = static_cast<uint8_t *>(
                mmap(at_address, size, (PROT_READ | PROT_WRITE), (MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED), -1, 0)
        );
        buffer_size = (is_valid()) ? size : 0;
        return is_valid();
    }
    // This method will allocate memory as close to the address as the OS can get you
    // but you may not get the exact address requested.
    // Address passed in MUST be page aligned
    bool allocate_near(void * at_address, size_t size){
        free_code_buffer();
        buffer_ptr = static_cast<uint8_t *>(
                mmap(at_address, size, (PROT_READ | PROT_WRITE), (MAP_ANONYMOUS | MAP_PRIVATE ), -1, 0)
        );
        buffer_size = (is_valid()) ? size : 0;
        return is_valid();
    }

    bool is_valid() const  {
        if (buffer_ptr == MAP_FAILED)  // NOTE: nullptr is a valid address
            return false;
        return true;
    }

    void free_code_buffer() {
        if (is_valid()) {
            munmap(buffer_ptr, buffer_size);
            buffer_ptr = nullptr;
        }
    }

    void set_executable() const {
        mprotect(buffer_ptr, buffer_size, PROT_READ | PROT_EXEC);
    }

    void * ptr() const { return buffer_ptr; }
    size_t size() const { return buffer_size; }

};



#endif //SANDSTONE_TEST_UTILS_H
