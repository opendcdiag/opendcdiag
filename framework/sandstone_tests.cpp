#include <fnmatch.h>
#include "sandstone_tests.h"

static std::map<const char *, struct test *, SandstoneTestSet::cstr_cmp> all_test_map; /* maps test name to test */
static std::map<const char *, std::vector <struct test *>> all_group_map; /* maps group name to a vector of tests it contains */
static bool initialized = false;

void SandstoneTestSet::init(enum InitSet init_set)
{
    std::span<struct test> known_tests;
    switch (init_set) {
        case REGULAR_TESTS:
            known_tests = regular_tests;
            break;
        case SELF_TESTS:
            known_tests = selftests;
            break;
        default:
            break;
    }
    for (struct test &t: known_tests) {
        all_test_map[t.id] = &t;
    }
    /* add "special" mce_check as well */
    all_test_map[mce_test.id] = &mce_test;
    initialized = true;
}

/* Looks up a name or a pattern among all "known" tests. Returns all the
 * matching results, empty vector if nothing matches. */
std::vector<struct test *> SandstoneTestSet::lookup(const char *name)
{
    std::vector<struct test*> res;
    if (!name || !strlen(name)) return res;
    if (!strchr(name, '*')) { /* if it has an asterisk, it's a glob, so expand it. */
        try {
            struct test *t = all_test_map.at(name);
            res.push_back(t);
        } catch(const std::out_of_range &e) {
        }
    } else if (name[0] == '@') { /* it's a group name */
        // TODO: implement
    } else {
        for (auto pair : all_test_map) {
            if (!fnmatch(name, pair.first, 0))
                res.push_back(pair.second);
        }
    }
    return res;
}

struct test *SandstoneTestSet::get_by_name(const char *name)
{
    try {
        return test_map.at(name)->test;
    } catch (const std::out_of_range &e) {
        return nullptr;
    }
}

std::vector<struct test *> SandstoneTestSet::enable(const char *name) {
    std::vector<struct test *> res = lookup(name);
    for (auto t : res) {
        struct test_info *ti;
        if (!test_map.contains(t->id)) {
            ti = new struct test_info;
            ti->st = TEST_ENABLED;
            ti->test = t;
            test_map[t->id] = ti;
        } else {
            ti = test_map[t->id];
            ti->st = TEST_ENABLED;
        }
        test_set.push_back(t);
    }
    return res;
}

std::vector<struct test *> SandstoneTestSet::disable(const char *name) {
    std::vector<struct test *> res;
    std::vector tests = lookup(name);
    for (auto t : tests) {
        struct test_info *ti;
        if (test_map.contains(t->id)) {
            test_map[t->id]->st = TEST_DISABLED;
        } else {
            ti = new struct test_info;
            ti->st = TEST_DISABLED;
            ti->test = t;
            test_map[t->id] = ti;
        }
        for (auto it = test_set.begin(); it != test_set.end(); ) {
            if (*it == t) {
                res.push_back(t);
                test_set.erase(it);
            } else {
                ++it;
            }
        }
    }
    return res;
}
