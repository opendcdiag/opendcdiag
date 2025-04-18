/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_context_dump.h"
#include "sandstone_utils.h"
#include "sandstone.h"

#ifdef __x86_64__
#include "amx_common.h"
#include "cpu_features.h"
#include "fp_vectors/Floats.h"

#include <algorithm>
#include <limits>

#ifdef __unix__
#  include <dlfcn.h>
#endif
#include <inttypes.h>
#include <string.h>
#include <x86intrin.h>

#ifndef signature_INTEL_ebx
#  include <cpuid.h>
#endif

#ifdef _WIN32
#  include <windows.h>
#endif

union xmmreg
{
    __m128  f;
    __m128d d;
    __m128i i;
    __uint128_t u;
};

union ymmreg
{
    __m256  f;
    __m256d d;
    __m256i i;
    xmmreg  xmm[2];
};

union zmmreg
{
    __m512  f;
    __m512d d;
    __m512i i;
    xmmreg  xmm[4];
    ymmreg  ymm[2];
};

struct Fxsave
{
    static constexpr ptrdiff_t size = FXSAVE_SIZE;

    uint16_t fcw;       // FPU control word
    uint16_t fsw;       // FPU status word
    uint16_t ftw;       // FPU tag word
    uint16_t fop;
    uint64_t fip;       // FPU RIP
    uint64_t fdp;       // FPU data pointer
    uint32_t mxcsr;
    uint32_t mcxsr_mask;

    static_assert(sizeof(Float80) == 16);
    Float80 st[8];

    static_assert(sizeof(xmmreg) == 16);
    xmmreg xmm[16];

    uint8_t padding[size - 416];
};
static_assert(sizeof(Fxsave) == Fxsave::size);

using char4 = char[4];
static constexpr char4 eflags[] = {
    "CF",           // bit 0 - carry flag
    "",             // bit 1 - fixed
    "PF",           // bit 2 - parity flag
    "",             // bit 3
    "AF",           // bit 4 - auxiliary flag
    "",             // bit 5
    "ZF",           // bit 6 - zero flag
    "SF",           // bit 7 - sign flag
    "TF",           // bit 8 - trap flag
    "IF",           // bit 9 - interrupt flag
    "DF",           // bit 10 - direction flag
    "OF",           // bit 11 - overflow flag
    "",             // bit 12 - IOPL bit
    "",             // bit 13 - IOPL bit
    "NT",           // bit 14 - nested task flag
    "",             // bit 15
    "RF",           // bit 16 - resume flag
    "VM",           // bit 17 - virtual mode flag
    "AC",           // bit 18 - alignment check flag
    "VIF",          // bit 19 - virtual interrupt flag
    "VIP",          // bit 20 - virtual interrupt pending
//  "ID",           // bit 21 - CPUID available (we don't print it)
};

static constexpr char4 fsw[] = {
    "IE",           // bit 0 - invalid exception
    "DE",           // bit 1 - denormal exception
    "ZE",           // bit 2 - division by zero exception
    "OE",           // bit 3 - overflow exception
    "UE",           // bit 4 - underflow exception
    "PE",           // bit 5 - inexact/precision exception
    "SF",           // bit 6 - stack fault
    "ES",           // bit 7 - exception summary
    "C0",           // bit 8 - code C0
    "C1",           // bit 9 - code C1
    "C2",           // bit 10 - code C2
    "",             // bit 11 - top of stack bit
    "",             // bit 12 - top of stack bit
    "",             // bit 13 - top of stack bit
    "C3",           // bit 14 - code C3
//  "B",            // bit 15 - FPU busy
};

static constexpr char4 mxcsr[] = {
    "IE",           // bit 0 - invalid exception
    "DE",           // bit 1 - denormal exception
    "ZE",           // bit 2 - division by zero exception
    "OE",           // bit 3 - overflow exception
    "UE",           // bit 4 - underflow exception
    "PE",           // bit 5 - inexact/precision exception
    "DAZ",          // bit 6 - denormals are zero
    "IM",           // bit 7 - invalid exceptions masked
    "DM",           // bit 8 - denormal exceptions masked
    "ZM",           // bit 9 - division by zero exceptions masked
    "OM",           // bit 10 - overflow exceptions masked
    "UM",           // bit 11 - underflow exceptions masked
    "PM",           // bit 12 - inexact/precision exceptions masked
    "",             // bit 13 - round control
    "",             // bit 14 - round control
    "FTZ",          // bit 15 - flush to zero
};

static constexpr char rounding_modes[][9] = {
    "nearest", "down", "up", "truncate"
};

static ptrdiff_t xsave_offset(XSaveBits bit)
{
    int n = __bsfd(bit);
    uint32_t eax, ebx, ecx, edx;
    __cpuid_count(0xd, n, eax, ebx, ecx, edx);
    return ebx;
};

template <int N, typename T>
static void print_flag_description(std::string &f, uint64_t value, T (&array)[N])
{
    for (size_t i = 0; i < std::size(array); ++i) {
        uint64_t bit = UINT64_C(1) << i;
        const char *name = array[i];
        if ((value & bit) && *name) {
            f += name;
            f += ' ';
        }
    }
}

static void print_gpr(std::string &f, const char *name, int64_t value)
{
    f += stdprintf(" %-5s = 0x%016" PRIx64, name, value);
    if (value <= 4096 && value >= -4096)
        f += stdprintf(" (%d)", int(value));
    f += '\n';
}

static void print_rip(std::string &f, uintptr_t rip)
{
    f += stdprintf(" %-5s = 0x%016tx", "rip", rip);
#ifdef __unix__
    uint8_t *ptr = reinterpret_cast<uint8_t *>(rip);
    Dl_info dli;
    if (dladdr(ptr, &dli) && dli.dli_sname)
        f += stdprintf(" <%s+%#tx>", dli.dli_sname, ptr - static_cast<uint8_t *>(dli.dli_saddr));
#endif
    f += '\n';
}

static void print_eflags(std::string &f, uint64_t value)
{
    f += stdprintf(" flags = 0x%08" PRIx64 " [ ", value);
    print_flag_description(f, value, eflags);
    f += "]\n";
}

static void print_segment(std::string &f, const char *name, uint16_t value)
{
    f += stdprintf(" %-5s = 0x%x\n", name, value);
}

#if defined(__linux__)
void dump_gprs(std::string &f, SandstoneMachineContext mc)
{
    static constexpr struct {
        char name[4];
        int idx;
    } registers[] = {
        { "rax", REG_RAX },
        { "rbx", REG_RBX },
        { "rcx", REG_RCX },
        { "rdx", REG_RDX },
        { "rsi", REG_RSI },
        { "rdi", REG_RDI },
        { "rbp", REG_RBP },
        { "rsp", REG_RSP },
        { "r8", REG_R8 },
        { "r9", REG_R9 },
        { "r10", REG_R10 },
        { "r11", REG_R11 },
        { "r12", REG_R12 },
        { "r13", REG_R13 },
        { "r14", REG_R14 },
        { "r15", REG_R15 },
    };
    for (auto reg : registers)
        print_gpr(f, reg.name, mc->gregs[reg.idx]);
    print_rip(f, mc->gregs[REG_RIP]);
    print_eflags(f, mc->gregs[REG_EFL]);

    // Linux always writes 0 to these fields, so this is useless. Don't waste
    // log space.
    if (false) {
        print_segment(f, "fs", mc->gregs[REG_CSGSFS] >> 16);
        print_segment(f, "gs", mc->gregs[REG_CSGSFS] >> 8);
    }
}
#elif defined(__FreeBSD__)
void dump_gprs(std::string &f, SandstoneMachineContext mc)
{
    using register_t = decltype(mc->mc_rax);
    static constexpr struct {
        char name[4];
        register_t mcontext_t:: *ptr;
    } registers[] = {
        { "rax", &mcontext_t::mc_rax },
        { "rbx", &mcontext_t::mc_rbx },
        { "rcx", &mcontext_t::mc_rcx },
        { "rdx", &mcontext_t::mc_rdx },
        { "rsi", &mcontext_t::mc_rsi },
        { "rdi", &mcontext_t::mc_rdi },
        { "rbp", &mcontext_t::mc_rbp },
        { "rsp", &mcontext_t::mc_rsp },
        { "r8", &mcontext_t::mc_r8 },
        { "r9", &mcontext_t::mc_r9 },
        { "r10", &mcontext_t::mc_r10 },
        { "r11", &mcontext_t::mc_r11 },
        { "r12", &mcontext_t::mc_r12 },
        { "r13", &mcontext_t::mc_r13 },
        { "r14", &mcontext_t::mc_r14 },
        { "r15", &mcontext_t::mc_r15 },
    };
    for (auto reg : registers)
        print_gpr(f, reg.name, mc->*(reg.ptr));
    print_rip(f, mc->mc_rip);
    print_eflags(f, mc->mc_rflags);
    print_segment(f, "fs", mc->mc_fs);
    print_segment(f, "gs", mc->mc_gs);
}
#elif defined(__APPLE__) || defined(__MACH__)
void dump_gprs(std::string &f, SandstoneMachineContext mc)
{
    auto *state = &mc->__ss;
    using ThreadState = std::decay_t<decltype(*state)>;
    using register_t = decltype(state->__rax);
    static constexpr struct {
        char name[4];
        register_t ThreadState:: *ptr;
    } registers[] = {
        { "rax", &ThreadState::__rax },
        { "rbx", &ThreadState::__rbx },
        { "rcx", &ThreadState::__rcx },
        { "rdx", &ThreadState::__rdx },
        { "rsi", &ThreadState::__rsi },
        { "rdi", &ThreadState::__rdi },
        { "rbp", &ThreadState::__rbp },
        { "rsp", &ThreadState::__rsp },
        { "r8", &ThreadState::__r8 },
        { "r9", &ThreadState::__r9 },
        { "r10", &ThreadState::__r10 },
        { "r11", &ThreadState::__r11 },
        { "r12", &ThreadState::__r12 },
        { "r13", &ThreadState::__r13 },
        { "r14", &ThreadState::__r14 },
        { "r15", &ThreadState::__r15 },
    };
    for (auto reg : registers)
        print_gpr(f, reg.name, state->*(reg.ptr));
    print_rip(f, state->__rip);
    print_eflags(f, state->__rflags);
    print_segment(f, "fs", state->__fs);
    print_segment(f, "gs", state->__gs);
}
#elif defined(_WIN32)
void dump_gprs(std::string &f, SandstoneMachineContext mc)
{
    static constexpr struct {
        char name[4];
        DWORD64 CONTEXT:: *ptr;
    } registers[] = {
        { "rax", &CONTEXT::Rax },
        { "rbx", &CONTEXT::Rbx },
        { "rcx", &CONTEXT::Rcx },
        { "rdx", &CONTEXT::Rdx },
        { "rsi", &CONTEXT::Rsi },
        { "rdi", &CONTEXT::Rdi },
        { "rbp", &CONTEXT::Rbp },
        { "rsp", &CONTEXT::Rsp },
        { "r8", &CONTEXT::R8 },
        { "r9", &CONTEXT::R9 },
        { "r10", &CONTEXT::R10 },
        { "r11", &CONTEXT::R11 },
        { "r12", &CONTEXT::R12 },
        { "r13", &CONTEXT::R13 },
        { "r14", &CONTEXT::R14 },
        { "r15", &CONTEXT::R15 },
    };
    for (auto reg : registers)
        print_gpr(f, reg.name, mc->*(reg.ptr));
    print_rip(f, mc->Rip);
    print_eflags(f, mc->EFlags);
    print_segment(f, "fs", mc->SegFs);
    print_segment(f, "gs", mc->SegGs);
}
#endif

static void print_x87mmx_registers(std::string &f, const Fxsave *state)
{
    int fptop = (state->fsw >> 11) & 7;
    f += stdprintf(" fcw   = %#x\n fsw   = %#x [ ", state->fcw, state->fsw);
    print_flag_description(f, state->fsw, fsw);
    f += stdprintf("top=%d ]\n ftw   = %#x\n", fptop, state->ftw);

    if (state->ftw == 0)
        return;                 // no tags, nothing to display, so save space

    // put them back in order according to the FP top
    for (size_t i = 0; i < std::size(state->st); ++i) {
        int effective = (i + fptop) % std::size(state->st); // ### is this right?
        effective = i;

        auto st = state->st + effective;
        f += stdprintf(" st(%zu) = %04x%016" PRIx64 " (%La)\n",
                i, st->as_hex.high16, st->as_hex.low64, st->as_float);
    }
}

static void print_xmm_register(std::string &f, const xmmreg &ptr)
{
    uint64_t low = uint64_t(ptr.u);
    uint64_t high = uint64_t(ptr.u >> 8 * sizeof(low));
    f += stdprintf("%016" PRIx64 ":%016" PRIx64 " ", high, low);
}

static void print_avx_registers(std::string &f, const Fxsave *state, XSaveBits mask)
{
    // start with the MXCSR
    f += stdprintf(" mxcsr = 0x%08x [ ", state->mxcsr);
    print_flag_description(f, state->mxcsr, mxcsr);
    f += stdprintf("RC=%s ]\n", rounding_modes[(state->mxcsr & _MM_ROUND_MASK) / _MM_ROUND_DOWN]);

    char nameprefix = 'x';
    auto base = reinterpret_cast<const uint8_t *>(state);
    const xmmreg *ymmhstate = nullptr;
    const ymmreg *zmmhstate = nullptr;
    const zmmreg *hizmmstate = nullptr;
    const __mmask64 *opmaskstate = nullptr;

    if (mask & XSave_Ymm_Hi128) {
        nameprefix = 'y';
        if (int offset = xsave_offset(XSave_Ymm_Hi128); offset > Fxsave::size)
            ymmhstate = reinterpret_cast<const xmmreg *>(base + offset);
    }
    if (mask & XSave_Zmm_Hi256) {
        nameprefix = 'z';
        if (int offset = xsave_offset(XSave_Zmm_Hi256); offset > Fxsave::size)
            zmmhstate = reinterpret_cast<const ymmreg *>(base + offset);
    }
    if (mask & XSave_Hi16_Zmm) {
        if (int offset = xsave_offset(XSave_Hi16_Zmm); offset > Fxsave::size)
            hizmmstate = reinterpret_cast<const zmmreg *>(base + offset);
    }
    if (mask & XSave_OpMask) {
        if (int offset = xsave_offset(XSave_OpMask); offset > Fxsave::size)
            opmaskstate = reinterpret_cast<const __mmask64 *>(base + offset);
    }

    for (int i = 0; i < int(std::size(state->xmm)); ++i) {
        f += stdprintf(" %cmm%-2d = ", nameprefix, i);
        if (zmmhstate) {
            print_xmm_register(f, zmmhstate[i].xmm[1]);
            print_xmm_register(f, zmmhstate[i].xmm[0]);
        }
        if (ymmhstate)
            print_xmm_register(f, ymmhstate[i]);
        print_xmm_register(f, state->xmm[i]);
        f += '\n';
    }
    for (int i = 0; hizmmstate && i < 16; ++i) {
        nameprefix = 'z';
        f += stdprintf(" %cmm%-2d = ", nameprefix, i + 16);
        for (int j = std::size(hizmmstate->xmm) - 1; j >= 0; --j)
            print_xmm_register(f, hizmmstate[i].xmm[j]);
        f += '\n';
    }
    for (int i = 0; opmaskstate && i < 8; ++i)
        f += stdprintf("    k%d = 0x%016" PRIx64 "\n", i, uint64_t(opmaskstate[i]));
}

static void print_amx_tiles_palette1(std::string &f, const Fxsave *state, const amx_tileconfig *tileconfig)
{
    // should we even print the 8 kB of tile data?
    //auto info = amx_palette1_info();
    constexpr struct amx_palette1_info info = {
        .total_tile_bytes = 8192,
        .bytes_per_tile = 1024,
        .bytes_per_row = 64,
        .max_names = 8,
        .max_rows = 16
    };

    int offset = xsave_offset(XSave_Xtiledata);
    if (offset + info.total_tile_bytes <= Fxsave::size)
        return;

    auto base = reinterpret_cast<const uint8_t *>(state) + offset;
    for (int reg = 0; reg < info.max_names; ++reg) {
        f += stdprintf(" tmm%-2d =", reg);
        if (tileconfig->rows[reg] == 0) {
            f += stdprintf(" <0 rows>\n");
            continue;
        }

        const uint8_t *tiledata = base + reg * info.bytes_per_tile;
        for (int row = 0; row < tileconfig->rows[reg]; ++row) {
            const uint8_t *rowdata = tiledata + row * info.bytes_per_row;
            f += stdprintf(" %d: {", row);
            for (int i = 0; i < tileconfig->colsb[reg]; ++i)
                f += stdprintf(" %02x", rowdata[i]);
            f += stdprintf(" }\n");
        }
    }
}

static void print_amx_state(std::string &f, const Fxsave *state, XSaveBits mask)
{
    int offset = xsave_offset(XSave_Xtilecfg);
    if (offset + sizeof(amx_tileconfig) <= Fxsave::size)
        return;

    auto base = reinterpret_cast<const uint8_t *>(state);
    auto tileconfig = reinterpret_cast<const amx_tileconfig *>(base + offset);
    f += stdprintf(" xtilecfg = palette: %u, start_row: %u\n", tileconfig->palette, tileconfig->start_row);
    for (size_t i = 0; i < std::size(tileconfig->colsb); ++i)
        f += stdprintf("            tile%-2zu { colsb: %u, rows: %u }\n",
                i, tileconfig->colsb[i], tileconfig->rows[i]);

    if (mask & XSave_Xtiledata) {
        if (tileconfig->palette == 1)
            return print_amx_tiles_palette1(f, state, tileconfig);
    }
}

static inline uint64_t __attribute__((target("xsave"))) do_xgetbv()
{
    return _xgetbv(0);
}

void dump_xsave(std::string &f, const void *xsave_area, size_t xsave_size, int xsave_dump_mask)
{
    // sanity check the state
    XSaveBits mask = XSaveBits(xsave_dump_mask);
    if (xsave_size < Fxsave::size)
        return;         // too small to be FXSAVE state

    auto state = static_cast<const Fxsave *>(xsave_area);

    if (xsave_size > Fxsave::size) {
        if (xsave_size < Fxsave::size + 64)
            return;     // XSAVE extended header missing

        // get the bit vector of saved features
        uint64_t xsave_bv;
        memcpy(&xsave_bv, state + 1, sizeof(xsave_bv));
        mask = XSaveBits(mask & xsave_bv);

        // sanity check it
        uint64_t xgetbv0 = XSave_X87 | XSave_SseState;

        // some Atoms have XSAVE but not AVX, but until there's interesting
        // state in them, the check for AVX suffices
        if (cpu_has_feature(cpu_feature_avx))
            xgetbv0 = do_xgetbv();

        if (xsave_bv & ~xgetbv0)
            return;     // bit vector contains invalid bits
    } else {
        // only the legacy state
        mask = XSaveBits(mask & (XSave_X87 | XSave_SseState));
    }

    if (mask & XSave_X87)
        print_x87mmx_registers(f, state);

    if (mask & XSave_Avx512State)
        print_avx_registers(f, state, mask);

    if (mask & XSave_AmxState)
        print_amx_state(f, state, mask);
}

// C API
char *dump_gprs(SandstoneMachineContext mc)
{
    std::string out;
    dump_gprs(out, mc);
    if (out.size())
        return strdup(out.c_str());
    return nullptr;
}

char *dump_xsave(const void *xsave_area, size_t xsave_size, int xsave_dump_mask)
{
    std::string out;
    dump_xsave(out, xsave_area, xsave_size, xsave_dump_mask);
    if (out.size())
        return strdup(out.c_str());
    return nullptr;
}

#endif // x86-64
