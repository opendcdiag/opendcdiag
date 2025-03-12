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
#if defined(__ELF__)
#  include <elf.h>
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

    // Try open openssl 3
    libcrypto = dlopen("libcrypto.so.3", RTLD_NOW);

    // If not available, don't continue
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

#if SANDSTONE_SSL_LINKED == 0 && defined(__ELF__)
// Add metadata indicating we do dlopen() OpenSSL
// https://systemd.io/ELF_DLOPEN_METADATA/
#ifndef ELF_NOTE_FDO
#  define ELF_NOTE_FDO              "FDO"
#endif
#ifndef NT_FDO_DLOPEN_METADATA
#  define NT_FDO_DLOPEN_METADATA    0x407c0c0a
#endif

namespace {
struct alignas(void*) ElfDlopenMetadata
{
    static constexpr const char s_payload[] =
        "["
            "{"
                "\"soname\":[\"libcrypto.so.3\"],"
                "\"description\":\"OpenSSL-based tests\","
                "\"priority\":\"recommended\""
            "}"
        "]";

    // Pedantic: Elf64_Nhdr and Elf32_Nhdr are identical
    using Header = std::conditional_t<sizeof(void *) == 8, Elf64_Nhdr, Elf32_Nhdr>;
    Header header = {
        .n_namesz = sizeof(name),
        .n_descsz = sizeof(payload),
        .n_type = NT_FDO_DLOPEN_METADATA,
    };
    char name[sizeof(ELF_NOTE_FDO)] = ELF_NOTE_FDO;
    char payload[sizeof(s_payload)] = {};

    consteval ElfDlopenMetadata()
    {
        std::copy_n(s_payload, sizeof(s_payload), payload);
    }
};

[[gnu::used, gnu::section(".note.dlopen")]]
static constexpr ElfDlopenMetadata elfDlopenMetadata = {};
} // unnamed namespace
#endif
