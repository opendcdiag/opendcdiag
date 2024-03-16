#include <fnmatch.h>
#include "sandstone_p.h"
#include "sandstone_tests.h"

#if defined(__linux__) && defined(__x86_64__)
extern struct test mce_test;
#else
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

static std::vector<struct test *> all_tests;
static std::map<const char *, std::vector <struct test *>, SandstoneTestSet::cstr_cmp> all_group_map; /* maps group name to a vector of tests it contains */
static bool initialized = false;

static void init(bool is_selftest)
{
    std::span<struct test> known_tests = is_selftest ? selftests : regular_tests;

    for (struct test &t : known_tests) {
        all_tests.push_back(&t);
        for (auto ptr = t.groups; ptr && *ptr; ++ptr) {
            all_group_map[(*ptr)->id].push_back(&t);
        }
    }
    /* add "special" mce_check as well */
    all_tests.push_back(&mce_test);
    initialized = true;
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
        if (all_group_map.contains(group_name)) {
            res = all_group_map[group_name];
        }
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

SandstoneTestSet::SandstoneTestSet(bool all_tests, bool is_selftest) : is_selftest(is_selftest) {
    if (!initialized) init(is_selftest);
    if (!all_tests) return;
    std::span<struct test> source = !is_selftest ? regular_tests : selftests;
    for (struct test &test : source) {
        struct test_info *ti = new struct test_info;
        ti->st = TEST_ENABLED;
        ti->test = &test;
        test_map[test.id] = ti;
        test_set.push_back(&test);
    }
};

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
