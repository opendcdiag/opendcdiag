/*
 * Copyright 2024 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fnmatch.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "sandstone_p.h"
#include "sandstone_tests.h"
#include "sandstone_chrono.h"

/* Special tests that apply regardless of which device backend was built
 * (as opposed to special_tests_for_device(), which is backend-specific).
 * Tests run very last, after device-specific tests, in the order they
 * are appended. */
static std::vector<struct test*> special_tests_common()
{
    std::vector<struct test*> tests;
#if defined(__linux__) && defined(__x86_64__)
    tests.push_back(&_test_smi_count);
#endif
    tests.push_back(&_test_mce_check);
    return tests;
}

void SandstoneTestSet::load_all_tests()
{
    std::span<struct test> known_tests = test_source();

    auto add_to_all_group_map = [&](struct test &t) {
        if (SandstoneConfig::RestrictedCommandLine)
            return;
        // only populate all_group_map if we're parsing command-line
        for (auto ptr = t.groups; ptr && *ptr; ++ptr) {
            all_group_map[(*ptr)->id].push_back(&t);
        }
    };

    for (struct test &t : known_tests) {
        all_tests.push_back(&t);
        if (is_selftest()) {
            // self tests don't have hardcoded test IDs, so add them now
            t.shortid = std::hash<std::string_view>()(t.id) & 0xffffff;
        }
        add_to_all_group_map(t);
    }

    /* add "special" tests */
    special_tests = special_tests_for_device();
    for (struct test *t : special_tests_common())
        special_tests.push_back(t);
    for (struct test *t : special_tests) {
        add_to_all_group_map(*t);
    }
}

/* Looks up a name or a pattern among all "known" tests. Returns all the
 * matching results, empty vector if nothing matches. */
std::vector<struct test *> SandstoneTestSet::lookup(const char *name)
{
    std::vector<struct test*> res;
    if (!name || !strlen(name)) return res;
    if (strchr(name, '*')) { /* if it has an asterisk, it's a glob, so expand it. */
        for (struct test *t : all_tests) {
            if (t->quality_level >= sApp->requested_quality && !fnmatch(name, t->id, 0))
                res.push_back(t);
        }
    } else if (name[0] == '@') { /* it's a group name */
        const char *group_name = name + 1;
        auto it = all_group_map.find(group_name);
        if (it != all_group_map.end()) {
            for (auto test : it->second) {
                if ((test->flags & test_is_optional) && !sApp->include_optional)
                    continue;
                res.push_back(test);
            }
        }
    } else {
        for (struct test *t : all_tests) {
            if (!strcmp(t->id, name)) {
                return {t};
            }
        }
        for (struct test *t : special_tests) {
            if (!strcmp(t->id, name)) {
                return {t};
            }
        }
    }
    return res;
}

SandstoneTestSet::SandstoneTestSet(struct test_set_cfg cfg, unsigned int flags)
    : cfg(cfg), flags(flags)
{
    load_all_tests(); /* initialize the catalog */
    if (!(flags & enable_all_tests)) return;

    for (struct test &test : test_source()) {
        if ((test.flags & test_is_optional) && !sApp->include_optional)
            continue;
        if (test.quality_level < sApp->requested_quality)
            continue;
        struct test_cfg_info ti;
        ti.status = test_cfg_info::enabled;
        ti.test = &test;
        test_set.push_back(&test);
    }
};

struct test_cfg_info SandstoneTestSet::add(test_cfg_info t)
{
    struct test_cfg_info &ti = test_set.emplace_back(t);
    // ensure it's enabled
    ti.status = test_cfg_info::enabled;
    return ti;
}

std::vector<struct test_cfg_info> SandstoneTestSet::add(const char *name)
{
    if (SandstoneConfig::RestrictedCommandLine) {
        assert(false && "There is no --enable command-line option");
        __builtin_unreachable();
    }
    std::vector<struct test_cfg_info> res;
    std::vector<struct test *> tests = lookup(name);
    for (auto t : tests) {
        struct test_cfg_info ti = add(t);
        res.push_back(ti);
    }
    return res;
}

/// Returns the number of tests that were removed from the test list, which may
/// be zero.
int SandstoneTestSet::remove(const struct test *test)
{
    auto it = std::remove_if(test_set.begin(), test_set.end(), [&](const test_cfg_info &ti) {
        return ti.test == test;
    });
    int count = test_set.end() - it;
    test_set.erase(it, test_set.end());
    return count;
}

/// Returns the number of tests that were removed from the test list, which may
/// be zero if the test is valid but did not match. An unmatched "*" is a no-op;
/// other names or patterns that match nothing return -1.
int SandstoneTestSet::remove(const char *name)
{
    if (SandstoneConfig::RestrictedCommandLine) {
        assert(false && "There is no --disable command-line option");
        __builtin_unreachable();
    }

    std::vector tests = lookup(name);
    if (tests.size() == 0)
        return name && !strcmp(name, "*") ? 0 : -1;

    int res = 0;
    for (auto t : tests) {
        res += remove(t);
    }
    return res;
}

static inline bool is_ignored(char c) {
    switch (c) {
        case ' ':
        case '\t':
            return true;
        default:
            return false;
    }
}

enum line_type {
    LT_VALID_TEST,
    LT_TEST_NOT_FOUND,
    LT_SYNTAX_ERROR,
    LT_INVALID_SEED,
    LT_EMPTY,
};

static line_type parse_test_list_line(std::string line, SandstoneTestSet *test_set, struct test_cfg_info &ti)
{
    std::string_view remaining(line);
    remaining = remaining.substr(0, remaining.find('#'));
    auto skip_space = [&] {
        while (!remaining.empty() && is_ignored(remaining.front()))
            remaining.remove_prefix(1);
    };
    auto token = [&] {
        auto end = remaining.find_first_of(" \t");
        auto result = remaining.substr(0, end);
        remaining.remove_prefix(result.size());
        return result;
    };
    skip_space();
    if (remaining.empty()) return LT_EMPTY;
    auto end = remaining.find_first_of(": \t");
    std::string name(remaining.substr(0, end));
    remaining.remove_prefix(name.size());
    skip_space();
    std::string_view duration;
    if (remaining.starts_with(':')) {
        remaining.remove_prefix(1);
        bool separated = !remaining.empty() && is_ignored(remaining.front());
        skip_space();
        duration = separated && remaining.starts_with("seed=") ? std::string_view{} : token();
        skip_space();
    }
    if (!remaining.empty()) {
        auto seed = token();
        if (!seed.starts_with("seed=")) return LT_SYNTAX_ERROR;
        if (random_load_seed_checked(seed.substr(5), false, &ti.seed) != RandomSeedResult::Success)
            return LT_INVALID_SEED;
        skip_space();
        if (!remaining.empty()) return LT_SYNTAX_ERROR;
    }
    SandstoneTestSet::TestSet set = test_set->lookup(name.c_str());
    if (!set.size()) return LT_TEST_NOT_FOUND;
    if (set.size() != 1) return LT_SYNTAX_ERROR; /* Artificially do not allow specifying wildcards or groups in the list file. */
    ti.test = set[0];
    if (!duration.empty() && strcasecmp(std::string(duration).c_str(), "default") != 0)
        ti.duration = string_to_millisecs(duration);
    return LT_VALID_TEST;
}

static std::vector<struct test_cfg_info> load_test_list(std::ifstream &fstream, SandstoneTestSet *test_set, bool ignore_unknown_tests, std::vector<std::string> &errors)
{
    std::vector<struct test_cfg_info> res;
    std::string line;
    bool error = false;
    int lineno = 1;
    while (std::getline(fstream, line)) {
        struct test_cfg_info ti;
        auto type = parse_test_list_line(line, test_set, ti);
        switch (type) {
            case LT_VALID_TEST:
                res.push_back(ti);
                break;
            case LT_SYNTAX_ERROR:
            case LT_INVALID_SEED:
            {
                std::stringstream msg_strm;
                msg_strm << (type == LT_INVALID_SEED ? "Invalid seed: line " : "Syntax error: line ")
                         << lineno << ": " << line;
                errors.push_back(msg_strm.str());
                error = true;
                break;
            }
            case LT_EMPTY:
                break;
            case LT_TEST_NOT_FOUND:
                if (!ignore_unknown_tests) {
                    std::stringstream msg_strm;
                    msg_strm << "Unknown test:  " << line;
                    errors.push_back(msg_strm.str());
                    error = true;
                }
                break;
        }
        ++lineno;
    }
    if (error) {
        res.clear();
    }
    return res;
}

std::vector<struct test_cfg_info> SandstoneTestSet::add_test_list(const char *fname, std::vector<std::string> &errors)
{
    if (SandstoneConfig::RestrictedCommandLine) {
        assert(false && "There is no --test-list-name command-line option");
        __builtin_unreachable();
    }

    std::ifstream list_file(fname, std::ios_base::in);
    if (!list_file) {
        errors.push_back(strerror(errno));
        return {};
    }
    std::vector<struct test_cfg_info> entries = load_test_list(list_file, this, cfg.ignore_unknown_tests, errors);
    if (!errors.empty()) return {};
    if (test_set.empty()) {
        test_set = entries;
    } else {
        test_set.reserve(test_set.capacity() + entries.size());
        for (auto e : entries) {
            test_set.push_back(e);
        }
    }
    return entries;
}

std::vector<struct test_cfg_info> SandstoneTestSet::add_builtin_test_list(const char *name, std::vector<std::string> &errors) {
    std::vector<struct test_cfg_info> res;
    BuiltinTestSet builtin = get_builtin_test_set(name);
    if (!builtin.tests) {
        std::stringstream msg_strm;
        msg_strm << "Builtin test list '" << name << "' does not contain any tests.";
        errors.push_back(msg_strm.str());
        return res;
    }
    for (auto t : *builtin.tests) {
        res.push_back(add(t));
        test_set.push_back(t);
    }
    return res;
}
