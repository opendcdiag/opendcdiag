/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <setjmp.h>

#ifdef _UCRT
// redirect old MSVCRT _setjmp to UCRT's __intrinsic_setjmp
#undef _setjmp
int _setjmp(jmp_buf Buf, void *ctx)
{
    return __intrinsic_setjmpex(Buf, ctx);
}
#endif
