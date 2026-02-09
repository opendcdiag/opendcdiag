/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"
#include "sandstone_p.h"

#include <algorithm>
#include <memory>
#include <new>
#include <random>
#include <span>
#include <sstream>

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__x86_64__) && !defined(signature_INTEL_ebx)
#   include <cpuid.h>
#endif

#ifdef __linux__
#  include <elf.h>
#  include <sys/auxv.h>
#endif

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>

// MS docs at https://msdn.microsoft.com/en-us/library/windows/desktop/aa387694(v=vs.85).aspx say:
// > This function has no associated import library. This function is available as a resource
// > named SystemFunction036 in Advapi32.dll.
// Argument why this is safe to use: https://bugzilla.mozilla.org/show_bug.cgi?id=504270
extern "C" {
DECLSPEC_IMPORT BOOLEAN WINAPI SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);
}
#endif

#ifdef __x86_64__
#  include <immintrin.h>
#  define RANDOM_HAS_AES        1
#endif

#ifndef O_CLOEXEC
#  define O_CLOEXEC 0
#endif

namespace {
union alignas(64) thread_rng {
    uint8_t u8[64];
    uint32_t u32[sizeof(u8) / sizeof(uint32_t)];
    uint64_t u64[sizeof(u8) / sizeof(uint64_t)];
    __uint128_t u128[sizeof(u8) / sizeof(__uint128_t)];
#ifdef __x86_64__
    __m128i m128[sizeof(u8) / sizeof(__m128i)];
#endif
};

// std::seed_seq does too much. This class simply copies the buffer as the seed.
struct SeedSequence
{
    using result_type = uint32_t;
    const uint32_t *seed;
    SeedSequence(const uint32_t *s) : seed(s) {}
    void generate(uint32_t *begin, uint32_t *end)
    {
        std::copy_n(seed, end - begin, begin);
    }
};

// -- the global (not per thread) state --

enum EngineType {
    Constant = 0,
    LCG = 1,
    AESSequence = 3
};
static constexpr std::initializer_list<EngineType> engine_types = {
    Constant,
    LCG,
#ifdef RANDOM_HAS_AES
    AESSequence,
#endif
};

} // unnamed namespace

struct RandomEngineWrapper
{
    std::vector<thread_rng> per_thread;
    EngineType engine_type;

    RandomEngineWrapper(EngineType type)
        : per_thread(thread_count() + 1), engine_type(type)
    {}

    virtual ~RandomEngineWrapper();
    virtual size_t stateSize() = 0;
    virtual std::string globalState() = 0;
    virtual void reloadGlobalState(const char *argument) = 0;
    virtual void seedGlobalEngine(SeedSequence &sseq) = 0;
    virtual void seedThread(thread_rng *thread_buffer, uint32_t mixin) = 0;
    virtual uint32_t generate32(thread_rng *thread_buffer) = 0;
    virtual uint64_t generate48(thread_rng *thread_buffer) = 0;
    virtual uint64_t generate64(thread_rng *thread_buffer) = 0;
    virtual int generateInt(thread_rng *thread_buffer) = 0;
    virtual __uint128_t generate128(thread_rng *thread_buffer) = 0;
    virtual uint64_t get_random_bits(thread_rng* ctx, uint32_t bits) = 0;
};
RandomEngineWrapper::~RandomEngineWrapper() {}

void RandomEngineDeleter::operator()(RandomEngineWrapper *ptr) const
{
    delete ptr;
}

namespace {

static thread_rng *rng_for_thread(int thread_num)
{
    assert(thread_num < thread_count());
    assert(thread_num >= -1);

    auto &rngs = sApp->random_engine->per_thread;
    assert(rngs.size());
    return &rngs[thread_num + 1];
}

static thread_rng *thread_local_rng()
{
    return rng_for_thread(thread_num);
}

template <typename E> struct EngineWrapper : public RandomEngineWrapper
{
    using engine_type = E;

    EngineWrapper(EngineType type) : RandomEngineWrapper(type)
    {
        static_assert(sizeof(engine_type) <= sizeof(thread_rng), "engine is too big");
        static_assert(std::is_trivially_copyable_v<engine_type>,
                "engine is not trivially copyable on this platform");
        static_assert(std::is_trivially_destructible_v<engine_type>,
                "engine is not trivially destructible on this platform");
        staticAssertions();
    }
    void staticAssertions() {}      // specialiseable

    size_t stateSize() override
    {
        return sizeof(engine_type);
    }

    std::string globalState() override
    {
        std::ostringstream ss;
        ss << globalEngine();
        return ss.str();
    }

    void reloadGlobalState(const char *argument) override
    {
        std::istringstream ss(argument);
        ss >> globalEngine();
    }

    void seedGlobalEngine(SeedSequence &sseq) override
    {
        new (rng_for_thread(-1)->u8) engine_type(sseq);
    }

    void seedThread(thread_rng *buffer, uint32_t mixin) override
    {
        // generic version: just XOR the mixin to the global engine's current state
        thread_rng *global = rng_for_thread(-1);
        for (size_t i = 0; i < std::size(buffer->u32); ++i)
            buffer->u32[i] = global->u32[i] ^ mixin;
    }

    uint32_t generate32(thread_rng *buffer) override
    {
        return uint32_t(engine(buffer)());
    }

    uint64_t generate48(thread_rng *thread_buffer) override
    {
        return generate64(thread_buffer) & ((UINT64_C(1) << 48) - 1U);
    }

    uint64_t generate64(thread_rng *thread_buffer) override
    {
        return generate32(thread_buffer) | (uint64_t(generate32(thread_buffer)) << 32);
    }

    int generateInt(thread_rng *thread_buffer) override
    {
        return generate32(thread_buffer) & 0x7fffffff;
    }

    __uint128_t generate128(thread_rng *thread_buffer) override
    {
        return generate64(thread_buffer) | (__uint128_t(generate64(thread_buffer)) << 64);
    }

    uint64_t get_random_bits(thread_rng* ctx, uint32_t bits) override;

protected:
    static E &engine(thread_rng *generator)
    {
        return *reinterpret_cast<E *>(generator->u8);
    }

    static E &globalEngine()
    {
        return engine(rng_for_thread(-1));
    }

    template<typename T>
    constexpr T get_mask(uint32_t bits) {
        return (bits < sizeof(T) * 8) ? ((T(1) << bits) - 1) : ~T(0);
    }
    template<typename T, auto F, uint32_t B, typename C>
    T get_random_bits(thread_rng* ctx, uint32_t bits) {
        assert((bits <= sizeof(T) * 8) && "Requested number of bits must fit the return type");

        // it is not allowed to use this function in the context of different cache sizes (as the
        // number of available bits might be bigger than the actual per-type cache holds).
        // AES uses first 256 bits of CTX for the seed/IV, therefore we must fit cache state in the remaining.
        static_assert(sizeof(C) + sizeof(uint32_t) <= sizeof(*ctx) / 2, "Cache and bits availability must fit withing second CTX half");
        C& cache = *reinterpret_cast<C*>(&ctx->u8[sizeof(*ctx) / 2]);
        uint32_t& available = *reinterpret_cast<uint32_t*>(&ctx->u8[sizeof(*ctx)-sizeof(uint32_t)]);

        T val;
        if (bits <= B) {
            if constexpr (B * 2 <= sizeof(C) * 8) {
                // the cache is able to hold at least two generated values.
                while (available < bits) {
                    assert((available <= sizeof(C) * 8 - B) && "generated value must fit remaining space in the cache");
                    cache |= C((this->*F)(ctx)) << available;
                    available += B;
                }
                val = static_cast<T>(cache) & get_mask<T>(bits);
                available -= bits;
                cache >>= bits;
            } else  {
                // the cache is able to hold only one generated value, we need to use additional value
                // if too few bits are "cached".
                static_assert(sizeof(T) <= sizeof(C), "cache type must be able to hold requested value");
                if (available < bits) {
                    C gen = C((this->*F)(ctx));
                    cache |= gen << available;
                    val = static_cast<T>(cache) & get_mask<T>(bits);
                    // we know that the number of generated bits is bigger than requested (no underflow possible)
                    available += B - bits;
                    cache = gen >> (bits - available);
                } else {
                    val = static_cast<T>(cache) & get_mask<T>(bits);
                    available -= bits;
                    cache >>= bits;
                }
            }
        } else {
            // if requested number of bits is bigger than number of bits fetched at once,
            // we need to iterate to get all the bits
            val = 0;
            uint32_t act = 0;
            while (bits != act) {
                if (available == 0) {
                    cache = C((this->*F)(ctx));
                    available = B;
                }
                uint32_t b = (bits <= available) ? bits : available;
                assert((act < sizeof(T) * 8) && "requested bits must fit into the return type");
                val |= (static_cast<T>(cache) & get_mask<T>(b)) << act;
                act += b;

                available -= b;
                cache >>= b;
            }
        }
        return val;
    }
};

// -- constant return engine --
// NOT random!!

struct constant_value_engine
{
    using result_type = uint32_t;
    result_type value;
    constant_value_engine(result_type v) : value(v) {}
    constant_value_engine(const SeedSequence &sseq) : value(*sseq.seed) {}
    result_type operator()() { return value;}
    constexpr static result_type min() { return 0; }
    constexpr static result_type max() { return std::numeric_limits<result_type>::max(); }

    friend std::ostringstream &operator<<(std::ostringstream &ss, constant_value_engine x)
    {
        ss.flags(std::ios_base::showbase);
        if (x.value > 255)
            ss << std::hex;
        ss << x.value;
        return ss;
    }

    friend std::istringstream &operator>>(std::istringstream &ss, constant_value_engine &x)
    {
        ss.flags(std::ios_base::showbase);
        ss >> x.value;
        return ss;
    }
};
template struct EngineWrapper<constant_value_engine>;

template<>
uint64_t EngineWrapper<constant_value_engine>::get_random_bits(thread_rng* ctx, uint32_t bits) {
    return get_random_bits<uint64_t, &EngineWrapper<constant_value_engine>::generate32, 32, uint64_t>(ctx, bits);
}

// -- linear congruential engine (minimum standard) --

template <> void EngineWrapper<std::minstd_rand>::staticAssertions()
{
    static_assert(engine_type::min() == 1, "invalid internal assumption");
    static_assert(engine_type::max() == 0x7ffffffe, "invalid internal assumption");
}

template <>
void EngineWrapper<std::minstd_rand>::seedThread(thread_rng *generator, uint32_t mixin)
{
    mixin &= engine_type::max();
    std::minstd_rand global = globalEngine();   // copies, so we don't modify the global
    new (&engine(generator)) std::minstd_rand(global() ^ mixin);
}

template <>
uint32_t EngineWrapper<std::minstd_rand>::generate32(thread_rng *generator)
{
    // need two samples to make 32 bits
    return (engine(generator)() & 0xffff) |
            ((engine(generator)() & 0xffff) << 16);
}

template <>
uint64_t EngineWrapper<std::minstd_rand>::generate48(thread_rng *generator)
{
    // need two samples to make 48 bits
    return (engine(generator)() & 0xffffff) |
            (uint64_t(engine(generator)() & 0xffffff) << 24);
}

template <>
uint64_t EngineWrapper<std::minstd_rand>::generate64(thread_rng *generator)
{
    // need three samples to make 64 bits
    return generate48(generator) |
            (uint64_t(engine(generator)() & 0xffffff) << 48);
}

template <>
int EngineWrapper<std::minstd_rand>::generateInt(thread_rng *generator)
{
    // need a single sample to make positive int
    return engine(generator)();
}

template<>
uint64_t EngineWrapper<std::minstd_rand>::get_random_bits(thread_rng* ctx, uint32_t bits) {
    // two Int values fit single 64b cache entry
    return get_random_bits<uint64_t, &EngineWrapper<std::minstd_rand>::generateInt, 31, uint64_t>(ctx, bits);
}

template struct EngineWrapper<std::minstd_rand>;

#ifdef RANDOM_HAS_AES
// -- AES engine (generates numbers by running AES over a state) --
static bool haveAes()
{
#if !defined(__x86_64__)
    return cpu_has_feature(cpu_feature_aes);
#else
    uint32_t eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    return bit_AES & ecx;
#endif
}

#pragma GCC push_options
#pragma GCC target("aes")
struct aes_engine
{
    __m128i state[2];
    aes_engine(const SeedSequence &sseq)
    {
        __m128i pattern = _mm_loadu_si128(reinterpret_cast<const __m128i *>(sseq.seed));
        _mm_store_si128(state + 0, pattern);
        pattern = _mm_xor_si128(pattern, _mm_set1_epi32(-1));
        _mm_store_si128(state + 1, pattern);
    }

    __m128i generateM128()
    {
        __m128i v1 = _mm_aesenc_si128(state[0], state[1]);
        _mm_store_si128(state + 0, v1);
        return v1;
    }
};

template<>
std::string EngineWrapper<aes_engine>::globalState()
{
    static const char hexdigits[] = "0123456789abcdef";
    const uint8_t *state = rng_for_thread(-1)->u8;
    std::string result;
    result.resize(2 * sizeof(aes_engine::state));
    for (size_t i = 0; i < sizeof(aes_engine::state); ++i) {
        result[2 * i + 0] = hexdigits[state[i] >> 4];
        result[2 * i + 1] = hexdigits[state[i] & 0xf];
    }
    return result;
}

template<>
void EngineWrapper<aes_engine>::reloadGlobalState(const char *ptr)
{
    uint8_t *state = rng_for_thread(-1)->u8;
    for (size_t i = 0; ptr[i]; ++i) {
        unsigned char c = ptr[i];
        // dirty, doesn't check if it's out of range!
        unsigned char nibble = c >= 'a' ? c - 'a' + 10 :
                                          c >= 'A' ? c - 'A' + 10 : c - '0';

        auto b = state + i / 2;
        if (i % 2 == 0)
            *b = nibble << 4;
        else
            *b |= nibble;
    }
}

template<>
uint32_t EngineWrapper<aes_engine>::generate32(thread_rng *generator)
{
    return _mm_cvtsi128_si32(engine(generator).generateM128());
}

template<>
uint64_t EngineWrapper<aes_engine>::generate64(thread_rng *generator)
{
    return _mm_cvtsi128_si64(engine(generator).generateM128());
}

template<>
__uint128_t EngineWrapper<aes_engine>::generate128(thread_rng *generator)
{
    __m128i r = engine(generator).generateM128();
    uint64_t l = _mm_extract_epi64(r, 0);
    uint64_t h = _mm_extract_epi64(r, 1);
    return l | (__uint128_t(h) << 64);
}
#pragma GCC pop_options

template<>
uint64_t EngineWrapper<aes_engine>::get_random_bits(thread_rng* ctx, uint32_t bits) {
    // for AES engine fetching 64 bits is the fastest option, lets not struggle with cache handling
    return generate64(ctx) & get_mask<uint64_t>(bits);
}


template struct EngineWrapper<aes_engine>;
#else
static bool haveAes()
{
    return false;
}
#endif // RANDOM_HAS_AES

} // unnamed namespace

// -- global stuff --

static const char *engineNameFromType(EngineType t)
{
    switch (t) {
    case Constant:
        return "Constant:";
    case LCG:
        return "LCG:";
    case AESSequence:
        return "AES:";
    }
    __builtin_unreachable();
    return nullptr;
}

static EngineType engineFromName(const char *argument)
{
    auto starts_with = [=](const char *name) {
        return strncmp(argument, name, strlen(name)) == 0;
    };
    for (EngineType type : engine_types) {
        if (starts_with(engineNameFromType(type))) {
            if (type == AESSequence && !haveAes()) {
                fprintf(stderr, "%s: engine type '%s' not available on this system.\n",
                        program_invocation_name, engineNameFromType(type));
                exit(EX_USAGE);
            }
            return type;
        }
    }
    fprintf(stderr, "%s: invalid random engine seed '%s'\n", program_invocation_name, argument);
    exit(EX_USAGE);
}

static inline int open_random_file(const char *filename)
{
    if (SandstoneConfig::RestrictedCommandLine || !filename) {
#ifdef _WIN32
        return -1;          // fall back to RtlGenRandom
#endif
        filename = "/dev/urandom";
    }
    return open(filename, O_RDONLY | O_CLOEXEC);
}

void random_init_global(const char *seed_from_user)
{
    auto make_engine = [](EngineType engine_type) {
        switch (engine_type) {
        case Constant:
            sApp->random_engine.reset(new EngineWrapper<constant_value_engine>(engine_type));
            return;
        case AESSequence:
#ifdef RANDOM_HAS_AES
            sApp->random_engine.reset(new EngineWrapper<aes_engine>(engine_type));
            return;
#else
            assert("Impossible condition: shouldn't have reached here");
            __builtin_unreachable();
#endif
        case LCG:
            sApp->random_engine.reset(new EngineWrapper<std::minstd_rand>(engine_type));
            return;
        }
        __builtin_unreachable();
    };
    assert(thread_count() > 0);
    assert(thread_num == -1);

    // treat the argument as if it were a file, see if it works
    int fd = open_random_file(seed_from_user);
    if (fd == -1 && !seed_from_user) {
        // misconfigured system without /dev/urandom!! Or Windows.
#if defined(AT_RANDOM) || defined(_WIN32)
#   ifdef AT_RANDOM
        // On Linux, AT_RANDOM was added on kernel 2.6.29, so we rely on it always
        // being present. We'll crash if it is not, but I guess you deserve it.
        // AT_RANDOM provides us with 128 bits of random data, which is sufficient to
        // either the LCG or AES generators.
        unsigned long randomdata = getauxval(AT_RANDOM);
        auto randomdataptr = reinterpret_cast<const uint32_t *>(randomdata);
#  else // _WIN32
        // On Windows, /dev/urandom won't exist, so let's use RtlGenRandom to
        // generate 128 bits of random data.
        auto RtlGenRandom = SystemFunction036;
        uint32_t randomdataptr[16 / sizeof(uint32_t)];
        if (!RtlGenRandom(randomdataptr, sizeof(randomdataptr))) {
            // RtlGenRandom failed, fall back to rand_s
            for (unsigned &u : randomdataptr)
                IGNORE_RETVAL(rand_s(&u));
        }

        uintptr_t randomdata = uintptr_t(&randomdataptr);
#  endif
        SeedSequence sseq(randomdataptr);

        // create the engine from the seed
        EngineType engine_type = LCG;
        if (haveAes() && randomdata & 0x80)
            engine_type = AESSequence;
        make_engine(engine_type);
        sApp->random_engine->seedGlobalEngine(sseq);
#else
        exit(EX_OSFILE);
#endif
    } else if (fd == -1) {
        // not a file (or does not exist), attempt to parse
        EngineType engine_type = engineFromName(seed_from_user);
        make_engine(engine_type);

        const char *ptr = strchr(seed_from_user, ':') + 1;
        sApp->random_engine->reloadGlobalState(ptr);
    } else {
        // it was a file, read our seed from there
        auto read_from_seed = [&](auto &where) {
            off_t n = read(fd, &where, sizeof(where));
            if (n != sizeof(where)) {
                if (seed_from_user)
                    fprintf(stderr, "%s: could not read from %s: %s\n", program_invocation_name,
                            seed_from_user, n < 0 ? strerror(errno) : "File too short");
                exit(EX_IOERR);
            }
            return true;
        };

        EngineType engine_type = LCG;
        if (haveAes()) {
            if (uint8_t type; read_from_seed(type) && (type & 2))
                engine_type = AESSequence;
        }
        make_engine(engine_type);

        thread_rng buffer;
        read_from_seed(buffer);
        close(fd);

        // create the engine from the seed
        SeedSequence sseq(buffer.u32);
        sApp->random_engine->seedGlobalEngine(sseq);
    }
}

std::string random_format_seed()
{
    std::string result = engineNameFromType(sApp->random_engine->engine_type);
    result += sApp->random_engine->globalState();
    return result;
}

void random_advance_seed()
{
    rand();
}

void random_init_thread(int thread_num)
{
    // nothing should be modifying the global engine now
    sApp->random_engine->seedThread(rng_for_thread(thread_num), mixin_from_device_info(thread_num));
}

template <typename FP> static inline FP random_template(FP scale)
{
    constexpr int extra_bits = std::max(64 - std::numeric_limits<FP>::digits, 0);
    static_assert(std::numeric_limits<FP>::is_specialized, "FP type is invalid");
    //    static_assert(extra_bits >= 0, "FP type too big");

    uint64_t mantissa_mask = UINT64_C(~0);
    mantissa_mask >>= extra_bits;
    FP max_integral = 0x1p64 / (UINT64_C(1) << extra_bits);

    uint64_t mantissa;
    if (std::numeric_limits<FP>::digits > 32)
        mantissa = sApp->random_engine->generate64(thread_local_rng());
    else
        mantissa = sApp->random_engine->generate32(thread_local_rng());
    mantissa &= mantissa_mask;
    return mantissa / max_integral * scale;
}

[[gnu::noinline]] uint32_t random32()
{
    return sApp->random_engine->generate32(thread_local_rng());
}

[[gnu::noinline]] uint64_t random64()
{
    return sApp->random_engine->generate64(thread_local_rng());
}

[[gnu::noinline]] __uint128_t random128()
{
    return sApp->random_engine->generate128(thread_local_rng());
}

[[gnu::noinline]] uint64_t get_random_bits(uint32_t bits)
{
    return sApp->random_engine->get_random_bits(thread_local_rng(), bits);
}

[[gnu::noinline]] float frandomf_scale(float scale)
{
    return random_template<float>(scale);
}

[[gnu::noinline]] double frandom_scale(double scale)
{
    return random_template<double>(scale);
}

[[gnu::noinline]] long double frandoml_scale(long double scale)
{
    return random_template<long double>(scale);
}

extern "C" {
// banned functions: seeding
#pragma GCC visibility push(default)
#pragma GCC diagnostic ignored "-Wmissing-noreturn"
#ifdef __clang__
#pragma GCC diagnostic ignored "-Wunreachable-code-return"
#endif

void srand(unsigned)
{
    abort();
}
void srandom(unsigned)
{
    abort();
}
int srandom_r(unsigned int, struct random_data *)
{
    abort();
    return 0;
}
void srand48(long)
{
    abort();
}

// override the libc random functions with ours
// ISO C-defined to return from 0 to RAND_MAX
[[gnu::noinline]] int rand()
{
    int result = random();
    if (RAND_MAX != std::numeric_limits<int>::max()) {
        static_assert(__builtin_popcount(unsigned(RAND_MAX) + 1) == 1);
        result &= RAND_MAX;
    }
    return result;
}

#ifdef _WIN32
int rand_r(unsigned int *)
{
    return rand();
}
#endif

// POSIX-defined to return in the interval [0, 2^31).
long int random()
{
    return sApp->random_engine->generateInt(thread_local_rng());
}

// POSIX-defined to return in the interval [0.0, 1.0)
double drand48()
{
    return frandom();
}

// POSIX-defined to return in the interval [0.0, 1.0)
double erand48(unsigned short *)
{
    return drand48();
}

// POSIX-defined to return in the interval [0, 2^31).
long int lrand48()
{
    return random();
}

// POSIX-defined to return in the interval [0, 2^31).
long int nrand48(unsigned short *)
{
    return random();
}

// POSIX-defined to return in the interval [-2^31, 2^31)
long int mrand48()
{
    return int(random32());
}

// POSIX-defined to return in the interval [-2^31, 2^31)
long int jrand48(unsigned short *)
{
    return mrand48();
}

// for tinycrypt:
//typedef int(*uECC_RNG_Function)(uint8_t *dest, unsigned int size);
int default_CSPRNG(uint8_t *dest, unsigned int size)
{
    memset_random(dest, size);
    return 1;
}

} // extern "C"

using std::random_device;
static_assert(std::is_same_v<decltype(random32()), random_device::result_type>);
static_assert(random_device::min() == 0);
static_assert(random_device::max() == UINT_MAX);

#ifdef __GLIBCXX__
void random_device::_M_init(const char *, size_t) {}
void random_device::_M_init(const std::string &) {}
void random_device::_M_init_pretr1(const std::string &) {}
void random_device::_M_fini() {}
unsigned random_device::_M_getval()
{
    return random32();
}
#elif defined(_LIBCPP_VERSION)
random_device::random_device(const std::string &) {}
random_device::~random_device() {}
unsigned random_device::operator()()
{
    return random32();
}
#endif
