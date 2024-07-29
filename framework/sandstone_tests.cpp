/*
 * Copyright 2024 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fnmatch.h>

#include <charconv>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "sandstone_p.h"
#include "sandstone_tests.h"
#include "sandstone_chrono.h"

#if !defined(__linux__) || !defined(__x86_64__)
// no MCE test outside Linux
static_assert(!InterruptMonitor::InterruptMonitorWorks);
struct test mce_test = {
#ifdef TEST_ID_mce_check
    .id = SANDSTONE_STRINGIFY(TEST_ID_mce_check),
    .description = nullptr,
#else
    .id = "mce_check",
    .description = "Machine Check Exceptions/Events count",
#endif
    .quality_level = TEST_QUALITY_SKIP
};
#endif

void SandstoneTestSet::load_all_tests()
{
    std::span<struct test> known_tests = cfg.is_selftest ? selftests : regular_tests;

    for (struct test &t : known_tests) {
        all_tests.push_back(&t);
        for (auto ptr = t.groups; ptr && *ptr; ++ptr) {
            all_group_map[(*ptr)->id].push_back(&t);
        }
    }
    /* add "special" mce_check as well */
    all_tests.push_back(&mce_test);
}

/* Looks up a name or a pattern among all "known" tests. Returns all the
 * matching results, empty vector if nothing matches. */
std::vector<struct test *> SandstoneTestSet::lookup(const char *name)
{
    std::vector<struct test*> res;
    if (!name || !strlen(name)) return res;
    if (strchr(name, '*')) { /* if it has an asterisk, it's a glob, so expand it. */
        for (struct test *t : all_tests) {
            if (!fnmatch(name, t->id, 0))
                res.push_back(t);
        }
    } else if (name[0] == '@') { /* it's a group name */
        const char *group_name = name + 1;
        auto it = all_group_map.find(group_name);
        if (it != all_group_map.end())
            res = it->second;
    } else {
        for (struct test *t : all_tests) {
            if (!strcmp(t->id, name)) {
                res.push_back(t);
                break;
            }
        }
    }
    return res;
}

SandstoneTestSet::SandstoneTestSet(struct test_set_cfg cfg, unsigned int flags) : cfg(cfg), flags(flags) {
    load_all_tests(); /* initialize the catalog */
    if (!(flags & enable_all_tests)) return;
    std::span<struct test> source = !cfg.is_selftest ? regular_tests : selftests;
    for (struct test &test : source) {
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

std::vector<struct test_cfg_info> SandstoneTestSet::add(const char *name) {
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
/// be zero if the test is valid but did not match. If it matched nothing, this
/// function returns -1.
int SandstoneTestSet::remove(const char *name)
{
    std::vector tests = lookup(name);
    if (tests.size() == 0)
        return -1;

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

static inline bool is_terminator(char c) {
    switch (c) {
        case '#':
        case ':':
            return true;
        default:
            return false;
    }
}

enum line_type {
    LT_VALID_TEST,
    LT_TEST_NOT_FOUND,
    LT_SYNTAX_ERROR,
    LT_EMPTY,
};

static line_type parse_test_list_line(std::string line, SandstoneTestSet *test_set, struct test_cfg_info &ti)
{
    std::vector<std::string> tokens;
    auto it = line.begin();
    while (is_ignored(*it)) ++it;
    if (*it == '#' || it == line.end()) return LT_EMPTY;
    for (; ; ++it) {
        auto cit = it;
        /* scroll while it's valid token contents: till end of line, a
         * terminator, or a space. */
        while (cit != line.end() && !is_terminator(*cit) && !is_ignored(*cit)) ++cit;
        auto tend = cit;
        while (cit != line.end() && is_ignored(*cit)) ++cit;
        if (cit != line.end() && !is_terminator(*cit)) return LT_SYNTAX_ERROR;
        tokens.emplace_back(it, tend);
        if (cit == line.end() || *cit == '#') break;
        it = cit;
    }
    if (!tokens.size()) __builtin_unreachable();
    if (tokens.size() > 2) return LT_SYNTAX_ERROR;
    SandstoneTestSet::TestSet set = test_set->lookup(tokens[0].c_str());
    if (!set.size()) return LT_TEST_NOT_FOUND;
    if (set.size() != 1) return LT_SYNTAX_ERROR; /* Artificially do not allow specifying wildcards or groups in the list file. */
    ti.test = set[0];
    if (tokens.size() == 2) {
        if (tokens[1].size() && strcasecmp(tokens[1].c_str(), "default") != 0)
            ti.duration = string_to_millisecs(tokens[1]);
    }
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
        switch (parse_test_list_line(line, test_set, ti)) {
            case LT_VALID_TEST:
                res.push_back(ti);
                break;
            case LT_SYNTAX_ERROR:
            {
                std::stringstream msg_strm;
                msg_strm <<  "Syntax error: line " << lineno << ": " << line;
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
    std::ifstream list_file(fname, std::ios_base::in);
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
