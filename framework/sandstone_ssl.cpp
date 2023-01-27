/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_ssl.h"

#include <exception>
#ifdef _WIN32
#  include <windows.h>
#else
#  include <dlfcn.h>
#endif

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"


#define DECLARE_SSL_POINTERS(Fn)        decltype(&Fn) s_ ## Fn = nullptr;
#define CHECK_SSL_POINTERS(Fn)          check(s_ ## Fn);

#if SANDSTONE_SSL_LINKED
#define INITIALIZE_SSL_POINTERS(Fn)     s_ ## Fn = &Fn;
#else
#define INITIALIZE_SSL_POINTERS(Fn)     s_ ## Fn = reinterpret_cast<decltype(&Fn)>(resolve(SANDSTONE_STRINGIFY(Fn)));
#endif

bool OpenSSLWorking = false;

SANDSTONE_SSL_FUNCTIONS(DECLARE_SSL_POINTERS)

void sandstone_ssl_init()
{
// Load library when not linked
#if SANDSTONE_SSL_LINKED == 0
#ifdef _WIN32
    struct Libs {
        HMODULE ssleay32;
        HMODULE libeay32;
    } libs = {};

    // insert LoadLibrary code here

    auto inner_resolve = [=](const char *name) {
        if (FARPROC ptr = GetProcAddress(libs.ssleay32, name))
            return ptr;
        return GetProcAddress(libs.libeay32, name);
    };
#else
    void *libcrypto;

    // Try open openssl 1.1
    libcrypto = dlopen("libcrypto.so.1.1", RTLD_NOW);

    // If previous not avialble, try open openssl 3.0
    if (!libcrypto)
    {
        libcrypto = dlopen("libcrypto.so.3", RTLD_NOW);
    }

    // When none available, don't continue
    if (!libcrypto) {
        return;
    }

    auto inner_resolve = [=](const char *name) {
        return dlsym(libcrypto, name);
    };
#endif

    auto resolve = [&](const char *name) {
        void (*result)(void) = nullptr;
        if (auto ptr = inner_resolve(name))
            result = reinterpret_cast<void (*)(void)>(ptr);
        return result;
    };
#endif // SANDSTONE_SSL_LINKED == 0

    // Initialize pointers and do check ups
    bool failed = false;
    auto check = [&](auto fn) {
        failed = failed || fn == nullptr;
    };

    SANDSTONE_SSL_FUNCTIONS(INITIALIZE_SSL_POINTERS)

    SANDSTONE_SSL_GENERIC_FUNCTIONS(CHECK_SSL_POINTERS)
    if (!failed) {
        s_OPENSSL_init();
        OpenSSLWorking = true;
    }
}

