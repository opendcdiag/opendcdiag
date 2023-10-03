/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_WIN32_ERRORSTRING_h
#define SANDSTONE_WIN32_ERRORSTRING_h

#include <windows.h>

inline const char *status_code_to_string(DWORD code)
{
    // This list is not exhaustive. It mostly comes from:
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record

    switch (code) {
    case 0xC0000602:    // STATUS_FAIL_FAST_EXCEPTION
        return "Aborted";
    case STATUS_ACCESS_VIOLATION:
        return "Access violation";
    case STATUS_ARRAY_BOUNDS_EXCEEDED:
        return "Array bounds exceeded";
    case STATUS_BREAKPOINT:
        return "Breakpoint";
    case STATUS_DATATYPE_MISALIGNMENT:
        return "Data type misalignment";
    case STATUS_FLOAT_DENORMAL_OPERAND:
        return "Floating-pointe denormal";
    case STATUS_FLOAT_DIVIDE_BY_ZERO:
        return "Floating-point division by zero";
    case STATUS_FLOAT_INEXACT_RESULT:
        return "Floating-point inexact result";
    case STATUS_FLOAT_INVALID_OPERATION:
        return "Floating-point invalid operation";
    case STATUS_FLOAT_OVERFLOW:
        return "Floating-point overflow";
    case STATUS_FLOAT_STACK_CHECK:
        return "Floating-point stack overflow";
    case STATUS_FLOAT_UNDERFLOW:
        return "Floating-point underflow";
    case STATUS_ILLEGAL_INSTRUCTION:
    case STATUS_PRIVILEGED_INSTRUCTION:
        return "Illegal instruction";
    case STATUS_IN_PAGE_ERROR:
        return "Paging violation";
    case STATUS_INTEGER_DIVIDE_BY_ZERO:
        return "Integer division by zero";
    case STATUS_NO_MEMORY:
        return "Out of memory condition";
    case STATUS_STACK_BUFFER_OVERRUN:
        return "Program self-triggered abnormal termination";
    case STATUS_STACK_OVERFLOW:
        return "Stack overflow";
    }

    return "???";
}

#endif // SANDSTONE_WIN32_ERRORSTRING_h
