/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WIN32_PTHREAD_H
#define WIN32_PTHREAD_H

#include_next <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Extra GNU extension */
int pthread_yield(void);

#ifdef __cplusplus
}
#endif

#endif
