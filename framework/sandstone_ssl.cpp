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

#ifndef SANDSTONE_OPENSSL_LINKED

#define DECLARE_SSL_POINTERS(Fn)        decltype(&Fn) s_ ## Fn = nullptr;
#define INITIALIZE_SSL_POINTERS(Fn)     s_ ## Fn = reinterpret_cast<decltype(&Fn)>(resolve(SANDSTONE_STRINGIFY(Fn)));
#define CHECK_SSL_POINTERS(Fn)          check(s_ ## Fn);

bool OpenSSLWorking = false;

SANDSTONE_SSL_FUNCTIONS(DECLARE_SSL_POINTERS)

void sandstone_ssl_init()
{
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
#ifdef SHLIB_VERSION_NUMBER
    // For openssl 1.0 and 1.1
    libcrypto = dlopen("libcrypto.so." SHLIB_VERSION_NUMBER, RTLD_NOW);
#else
    // For openssl 3.0 and above
    libcrypto = dlopen("libcrypto.so." SANDSTONE_STRINGIFY(OPENSSL_SHLIB_VERSION), RTLD_NOW);
#endif
    if (!libcrypto) {
        return;
    }

    auto inner_resolve = [=](const char *name) {
        return dlsym(libcrypto, name);
    };
#endif

    bool failed = false;
    auto resolve = [&](const char *name) {
        void (*result)(void) = nullptr;
        if (auto ptr = inner_resolve(name))
            result = reinterpret_cast<void (*)(void)>(ptr);
        return result;
    };
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

#endif
