/*
 * SPDX-License-Identifier: Apache-2.0
 */

// PLEASE READ BEFORE EDITING:
//     This is a clean file, meaning everyrthing in it is properly unit tested
//     Please do not add anything to this file unless it is unit tested.
//     All unit tests should be put in framework/unit-tests/sandstone_utils_tests.cpp

#include "sandstone_data.h"

#include <type_traits>

template <typename T, typename X>
static T bit_cast(X src)
{
    static_assert(sizeof(T) == sizeof(X));
    T dst;
    memcpy(&dst, &src, sizeof(T));
    return dst;
}

// This *should* work for double->fp16 and double->float too, but
// it's only tested for float->fp16.
// Original: encode_half in https://github.com/intel/tinycbor/blob/master/src/cborinternal_p.h
template <typename T> static inline uint16_t ieee754_downconvert(T f)
{
    using OutputLimits = Float16;
    using InputLimits = std::numeric_limits<T>;
    using UInt = std::conditional_t<sizeof(f) == sizeof(uint32_t), uint32_t, uint64_t>;
    static constexpr int TotalBits = sizeof(f) * 8;
    static constexpr int MantissaBits = InputLimits::digits - 1;    // because of the implicit bit
    static constexpr uint64_t MantissaMask = (uint64_t(1) << MantissaBits) - 1;
    static constexpr int ExponentBits = __builtin_ctz(InputLimits::max_exponent) + 1;
    static constexpr uint64_t ExponentMask = ((uint64_t(1) << ExponentBits) - 1) << MantissaBits;
    static constexpr uint64_t SignMask = uint64_t(1) << (MantissaBits + ExponentBits);
    static_assert(MantissaBits + ExponentBits + 1 == TotalBits);

    UInt v = bit_cast<UInt>(f);

    int sign = (v & SignMask) >> (MantissaBits + ExponentBits);
    int exp = (v & ExponentMask) >> MantissaBits;
    int mant = (v & MantissaMask) >> (InputLimits::digits - OutputLimits::digits); // keep only the most significant bits of the mantissa

    // move sign bit to the right bit position
    sign <<= sizeof(Float16) * 8 - 1;

    exp -= InputLimits::max_exponent - 1;           // remove incoming exponent bias
    if (exp == InputLimits::max_exponent) {
        /* infinity or NaN */
        exp = 2 * OutputLimits::max_exponent - 1;
#if defined(__i386__) || defined(__x86_64__)
        /* x86 always quiets any SNaN, so do the same */
        if (mant)
            mant |= 1 << (OutputLimits::digits - 2);
#endif
    } else if (exp >= OutputLimits::max_exponent) {
        /* overflow, make it FLT16_MAX or -FLT16_MAX */
        return Float16::max().as_hex | sign;
    } else if (exp >= OutputLimits::min_exponent - 1) {
        /* regular normal */
        exp += OutputLimits::max_exponent - 1;      // apply outgoing exponent bias
    } else if (exp >= OutputLimits::min_exponent - OutputLimits::digits) {
        /* subnormal */
        mant |= 1 << (OutputLimits::digits - 1);    // make implicit bit explicit
        mant >>= -(exp - (OutputLimits::min_exponent - 1));
        exp = 0;
    } else {
        /* underflow or zero (including negative zero), make zero */
        sign = exp = mant = 0;
    }

    exp <<= OutputLimits::digits - 1;
    return sign | exp | mant;
}

template <typename T> static inline uint16_t to_bfloat16(T f)
{
    using OutputLimits = BFloat16;
    using InputLimits = std::numeric_limits<T>;
    using UInt = std::conditional_t<sizeof(f) == sizeof(uint32_t), uint32_t, uint64_t>;
    static constexpr int TotalBits = sizeof(f) * 8;
    static constexpr int MantissaBits = InputLimits::digits - 1;    // because of the implicit bit
    static constexpr uint64_t MantissaMask = (uint64_t(1) << MantissaBits) - 1;
    static constexpr int ExponentBits = __builtin_ctz(InputLimits::max_exponent) + 1;
    static constexpr uint64_t ExponentMask = ((uint64_t(1) << ExponentBits) - 1) << MantissaBits;
    static constexpr uint64_t SignMask = uint64_t(1) << (MantissaBits + ExponentBits);
    static_assert(MantissaBits + ExponentBits + 1 == TotalBits);

    UInt v = bit_cast<UInt>(f);

    int sign = (v & SignMask) >> (MantissaBits + ExponentBits);
    int exp = (v & ExponentMask) >> MantissaBits;
    int mant = (v & MantissaMask) >> (InputLimits::digits - OutputLimits::digits); // keep only the most significant bits of the mantissa

    // move sign bit to the right bit position
    sign <<= sizeof(BFloat16) * 8 - 1;

    if (exp == 0) {
        // zero or denormal
        return sign;
    } else if (exp == 2 * InputLimits::max_exponent - 1) {
        uint16_t r = v >> 8 * (sizeof(T) - sizeof(BFloat16));
#if defined(__i386__) || defined(__x86_64__)
        /* x86 always quiets any SNaN, so do the same */
        if (mant)
            r |= 1 << (OutputLimits::digits - 2);
#endif
        return r;
    }

    /* normal number */
    int rounding_bias = 0x7fff + (mant & 1);
    v += rounding_bias;
    return v >> 8 * (sizeof(T) - sizeof(BFloat16));
}

/* this function was copied & adapted from RFC 7049 Appendix D */
// Original: decode_half in https://github.com/intel/tinycbor/blob/master/src/cborinternal_p.h
static float decode_half(uint16_t half)
{
    int exp = (half >> 10) & 0x1f;
    int mant = half & 0x3ff;
    double val;
    if (exp == 0) val = ldexp(mant, -24);
    else if (exp != 31) val = ldexp(mant + 1024, exp - 25);
    else val = mant == 0 ? INFINITY : NAN;
    return half & 0x8000 ? -val : val;
}

Float16 tofp16_emulated(float f)
{
    Float16 r;
    r.as_hex = ieee754_downconvert(f);
    return r;
}

float fromfp16_emulated(Float16 f)
{
    // is it a NaN?
    auto isnan = [](uint16_t v) {
        uint16_t inf = Float16::infinity().as_hex;
        if (v == inf || v == Float16::neg_infinity().as_hex)
            return false;
        if ((v & inf) != inf)
            return false;
        return true;
    };
    if (__builtin_expect(!isnan(f.as_hex), 1))
        return decode_half(f.as_hex);

    // preserve NaN's bit pattern
    uint32_t p = f.as_hex & ~Float16::infinity().as_hex;

#if defined(__i386__) || defined(__x86_64__)
    /* x86 always quiets any SNaN, so do the same */
    p |= 1 << (Float16::digits - 2);
#endif

    p <<= std::numeric_limits<float>::digits - Float16::digits;
    p |= bit_cast<uint32_t>(std::numeric_limits<float>::infinity());
    return bit_cast<float>(p);
}

BFloat16 tobf16_emulated(float f)
{
    BFloat16 r;
    r.as_hex = to_bfloat16(f);
    return r;
}
