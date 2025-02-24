/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SYSDEPS_WIN32_GETTID_H
#define SYSDEPS_WIN32_GETTID_H

using tid_t = unsigned;

extern tid_t gettid() noexcept;

#endif // SYSDEPS_WIN32_GETTID_H
