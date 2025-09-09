/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_DATA_H
#define SANDSTONE_DATA_H

#include <float.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fp_vectors/Floats.h"

#ifdef __cplusplus
extern "C" {
#endif

enum DataType {
    //SizeMask = 0x3f,
    UInt8Data = 0,
    UInt16Data = 1,
    UInt32Data = 3,
    UInt64Data = 7,
    UInt128Data = 15,

    DataIsSigned = 0x80,
    Int8Data = UInt8Data | DataIsSigned,
    Int16Data = UInt16Data | DataIsSigned,
    Int32Data = UInt32Data | DataIsSigned,
    Int64Data = UInt64Data | DataIsSigned,
    Int128Data = UInt128Data | DataIsSigned,

    DataIsFloatingPoint = 0x40,
    HFloat8Data = 6 | DataIsFloatingPoint,
    BFloat8Data = 8 | DataIsFloatingPoint,
    Float16Data = UInt16Data | DataIsFloatingPoint,
    BFloat16Data = 2 | DataIsFloatingPoint,
    Float32Data = UInt32Data | DataIsFloatingPoint,
    Float64Data = UInt64Data | DataIsFloatingPoint,
    Float80Data = 9 | DataIsFloatingPoint,
    Float128Data = UInt128Data | DataIsFloatingPoint
};

#ifdef __cplusplus
} // extern "C"

namespace SandstoneDataDetails {
enum { MaxDataTypeSize = 16 };

static constexpr const char *type_name(DataType type)
{
    switch (type) {
    case UInt8Data: return "uint8_t";
    case UInt16Data: return "uint16_t";
    case UInt32Data: return "uint32_t";
    case UInt64Data: return "uint64_t";
    case UInt128Data: return "uint128_t";

    case Int8Data: return "int8_t";
    case Int16Data: return "int16_t";
    case Int32Data: return "int32_t";
    case Int64Data: return "int64_t";
    case Int128Data: return "int128_t";

    case HFloat8Data: return "HFloat8";
    case BFloat8Data: return "BFloat8";
    case Float16Data: return "_Float16";
    case BFloat16Data: return "_BFloat16";
    case Float32Data: return "float";
    case Float64Data: return "double";
    case Float80Data: return "_Float64x";   // long double is IEEE-754 extended precision binary64
    case Float128Data: return "_Float128";

    //case DataIsSigned:
    case DataIsFloatingPoint:
        __builtin_unreachable();
    }
    return nullptr;
}

template <DataType V> struct TypeToDataType_helper
{
    static constexpr DataType Type = V;
    static const char *name() { return type_name(Type); }
    enum { IsValid = true };
};

template <typename T> struct TypeToDataType { enum { IsValid = false }; };
template<> struct TypeToDataType<void>  : TypeToDataType_helper<UInt8Data> {};
template<> struct TypeToDataType<bool>  : TypeToDataType_helper<UInt8Data> {};
template<> struct TypeToDataType<char>  : TypeToDataType_helper<UInt8Data> {};
template<> struct TypeToDataType<uint8_t>  : TypeToDataType_helper<UInt8Data> {};
template<> struct TypeToDataType<uint16_t> : TypeToDataType_helper<UInt16Data> {};
template<> struct TypeToDataType<uint32_t> : TypeToDataType_helper<UInt32Data> {};
template<> struct TypeToDataType<uint64_t> : TypeToDataType_helper<UInt64Data> {};
template<> struct TypeToDataType<__uint128_t> : TypeToDataType_helper<UInt128Data> {};
template<> struct TypeToDataType<int8_t>  : TypeToDataType_helper<Int8Data> {};
template<> struct TypeToDataType<int16_t> : TypeToDataType_helper<Int16Data> {};
template<> struct TypeToDataType<int32_t> : TypeToDataType_helper<Int32Data> {};
template<> struct TypeToDataType<int64_t> : TypeToDataType_helper<Int64Data> {};
template<> struct TypeToDataType<__int128_t> : TypeToDataType_helper<Int128Data> {};

template<> struct TypeToDataType<BFloat8> : TypeToDataType_helper<BFloat8Data> {};
template<> struct TypeToDataType<HFloat8> : TypeToDataType_helper<HFloat8Data> {};
template<> struct TypeToDataType<Float16> : TypeToDataType_helper<Float16Data> {};
template<> struct TypeToDataType<BFloat16> : TypeToDataType_helper<BFloat16Data> {};
template<> struct TypeToDataType<float> : TypeToDataType_helper<Float32Data> {};
template<> struct TypeToDataType<double> : TypeToDataType_helper<Float64Data> {};
template<> struct TypeToDataType<long double> :
        TypeToDataType_helper<sizeof(long double) == sizeof(double) ? Float64Data : Float80Data> {};
#ifdef __SIZEOF_FLOAT128__
template<> struct TypeToDataType<Float128> : TypeToDataType_helper<Float128Data> {};
template<> struct TypeToDataType<__float128> : TypeToDataType_helper<Float128Data> {};
#endif
#ifdef SANDSTONE_FP16_TYPE
template<> struct TypeToDataType<fp16_t> : TypeToDataType_helper<Float16Data> {};
#endif

static constexpr size_t type_real_size(DataType type)
{
    constexpr unsigned SizeMask = 0x3f;
    // exceptions
    if ((type == HFloat8Data) || (type == BFloat8Data))
        return 1;
    if (type == BFloat16Data)
        return 2;
    return (type & SizeMask) + 1;
}

static constexpr size_t type_size(DataType type)
{
    // special case: long double has 10 bytes of data but occupies 16 bytes
    if (type == Float80Data)
        return sizeof(long double);
    return type_real_size(type);
}

static constexpr size_t type_alignment(DataType type)
{
    return type_size(type);
}
} // namespace SandstoneDataDetails

#else
/* for C mode, we'll have to use _Generic */
#define DATATYPEFORTYPE(X) _Generic((X), \
        _Bool: UInt8Data, \
        char: UInt8Data, \
        uint8_t: UInt8Data, \
        uint16_t: UInt16Data, \
        uint32_t: UInt32Data, \
        unsigned long: (sizeof(unsigned long) == sizeof(unsigned long long) ? UInt64Data : UInt32Data), \
        unsigned long long: UInt64Data, \
        __uint128_t: UInt128Data, \
        int8_t: Int8Data, \
        int16_t: Int16Data, \
        int32_t: Int32Data, \
        long: (sizeof(long) == sizeof(long long) ? Int64Data : Int32Data), \
        long long: Int64Data, \
        __int128_t: Int128Data, \
        HFloat8: HFloat8Data, \
        BFloat8: BFloat8Data, \
        BFloat16: BFloat16Data, \
        Float16: Float16Data, \
        float: Float32Data, \
        double: Float64Data, \
        long double: (sizeof(long double) == sizeof(double) ? Float64Data : Float80Data) \
    )

#endif /* __cplusplus */

#endif /* SANDSTONE_DATA_H */
