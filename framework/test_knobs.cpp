/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_knobs.h"

#include "sandstone.h"

#include <map>
#include <string>
#include <boost/algorithm/string.hpp>

namespace {
class TestKeyWrapper
{
    std::string storage;
    std::string_view key;

public:
    TestKeyWrapper(const struct test *test, const char *k)
        : key(k)
    {
        if (test) {
            // prepare full name for this key
            storage.reserve(strlen(test->id) + key.size() + 1);
            storage = test->id;
            storage += '.';
            storage += key;
            key = storage;
        }
    }
    operator std::string_view() const { return key; }
};

class TestKnobSingleton {
private:
    struct Entry {
        std::string key;
        std::string value;
    };
    std::vector<Entry> test_knobs;
    Entry *find_key(std::string_view key)
    {
        for (auto it = test_knobs.begin(); it != test_knobs.end(); ++it) {
            if (it->key == key)
                return &*it;
        }
        return nullptr;
    }

    static TestKnobSingleton & instance()
    {
        static TestKnobSingleton instance;
        return instance;
    }

public:
    static void set_knob(std::string key, std::string value)
    {
        Entry *e = instance().find_key(key);
        if (e)
            e->value = std::move(value);
        else
            instance().test_knobs.emplace_back(Entry{std::move(key), std::move(value)});
    }

    static std::string_view get_knob(std::string_view key)
    {
        const Entry *e = instance().find_key(key);
        return e ? e->value : std::string_view();
    }

    static void clear()
    {
        instance().test_knobs.clear();
    }
};
}  // end anonymous namespace


void clear_test_knobs(){
    TestKnobSingleton::clear();
}

// external interface methods

const char *get_testspecific_knob_value_string(const struct test *test, const char *key,
                                               const char *value_if_not_present)
{
    TestKeyWrapper k(test, key);
    std::string_view s = TestKnobSingleton::get_knob(k);
    if (s.data()) {
        logging_mark_knob_used(k, s, KnobOrigin::Options);
        return s.data();
    }
    std::string_view v;
    if (value_if_not_present)
        v = value_if_not_present;
    logging_mark_knob_used(k, v, KnobOrigin::Defaulted);
    return value_if_not_present;
}

template <typename Int> static
Int knob_value_integer(const struct test *test, const char *k, Int value_if_not_present)
{
    TestKeyWrapper key(test, k);
    std::string_view s = TestKnobSingleton::get_knob(key);
    if (s.data()) {
        // convert to integer
        char * endptr;
        errno = 0;
        unsigned long long value = strtoull(s.data(), &endptr, 0);
        if (endptr == s.end()) {
            logging_mark_knob_used(key, Int(value), KnobOrigin::Options);
            return Int(value);
        };
    }
    logging_mark_knob_used(key, value_if_not_present, KnobOrigin::Defaulted);
    return value_if_not_present;
}

uint64_t get_testspecific_knob_value_uint(const struct test *test, const char *key, uint64_t value_if_not_present)
{
    return knob_value_integer(test, key, value_if_not_present);
}

int64_t get_testspecific_knob_value_int(const struct test *test, const char *key, int64_t value_if_not_present)
{
    return knob_value_integer(test, key, value_if_not_present);
}

bool set_knob_from_key_value_string(const char *key_value_pair) {
    std::string key_value_string = key_value_pair;
    std::vector<std::string> words;

    boost::split(words, key_value_string, boost::is_any_of("="));

    // Sanitizing inputs:
    // must be exactly 1 key and 1 value and neither can be an empty string
    if ((words.size() != 2) || (words[0].empty() || words[1].empty()))
        return false;

    TestKnobSingleton::set_knob(std::move(words[0]), std::move(words[1]));
    return true;  // exit success
}


