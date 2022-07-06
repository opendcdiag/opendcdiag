/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * List file Test Selector
 *    Allows test id's to be specified in an external file.
 *    When selector->load_from(<file>) is called, it cause the tests to be selected
 *    based on contents of the file (one test per line of file)
 */

#ifndef SANDSTONE_LISTFILESELECTOR_H
#define SANDSTONE_LISTFILESELECTOR_H

#include "TestrunSelectorBase.h"
#include <fstream>
#include <stddef.h>

class ListFileTestSelector : public TestrunSelector
{
public:
    ListFileTestSelector(std::vector<test *> _tests)
        : TestrunSelector(std::move(_tests))
    {
    }

    class listfile_rec {  // Inner class
    public:
        struct test *test_ptr;
        int test_duration;
    };

    std::vector<listfile_rec> listfile_recs;
    int currect_test_index = 0;
    int first_test_index = 0;
    int last_test_index = 999999;

    struct test *get_next_test() override {
        if (currect_test_index == min(last_test_index, listfile_recs.size())) {
            reset_selector();
            return nullptr;
        }

        auto runinfo_rec = listfile_recs[currect_test_index];
        runinfo_rec.test_ptr->desired_duration = runinfo_rec.test_duration;
        currect_test_index++;
        return runinfo_rec.test_ptr;
    }


    void reset_selector() override {
        currect_test_index = first_test_index;
    }

    size_t get_test_count() const override {
        size_t range_size = last_test_index - first_test_index;
        return std::min(listfile_recs.size(), range_size);
   };

    void load_from_file(const std::string &path) {   // WARNING: This method not covered by unit tests
        std::ifstream infile(path);

        if (infile.is_open()) {
            load_from_stream(infile);
        } else {
            fprintf(stderr, "\nERROR: Cannot open test list file [%s] for read\n", path.c_str());
            exit(EX_NOINPUT);
        }
    }


    void load_from_stream(std::istream &instream) {
        std::string line;

        while (getline(instream, line)) {
            listfile_rec rec{};
            if (line_parsed_into_record(line, rec, false)) {
                listfile_recs.push_back(rec);
            }
        }
    }


    bool line_parsed_into_record(std::string line, listfile_rec &rec, bool silent) {
        std::vector<std::string> values = split_line(line.c_str(), ": \t");

        if (values.empty() || line[0] == '#')
            return false;

        rec.test_ptr = testid_to_test(values[0].c_str(), silent);

        if (!rec.test_ptr)
                  return false;

        if (values.size() >= 2) {
            if (values[1] == "default")
                rec.test_duration = rec.test_ptr->desired_duration;
            else
                rec.test_duration =  try_parse_duration(values[1]).count();
        } else {
            rec.test_duration = rec.test_ptr->desired_duration;
        }

        return true;
    }


    static std::chrono::milliseconds try_parse_duration(const std::string &str) {
        try {
            return string_to_millisecs(str);
        } catch (const std::invalid_argument &ia) {
            fprintf(stderr, "\nERROR: Malformed test duration in test list file (token = %s)", str.c_str());
            exit(EX_DATAERR);
        }
    }


    static std::vector<std::string> split_line(const char *line, const char *separators) {
        char *buffer = strdup(line);  // prevent changing original line
        std::vector<std::string> parts;

        for (auto token = strtok(buffer, separators); (token != nullptr); token = strtok(nullptr, separators))
            parts.emplace_back(token);

        free(buffer);
        return parts;
    }


    void set_selection_range(int first, int last, bool randomize) {
        first_test_index = std::min(static_cast<int>(listfile_recs.size()), first - 1);
        last_test_index = last;
        reset_selector();

        if (!randomize)
            return;

        size_t end = std::min(static_cast<size_t>(last_test_index), listfile_recs.size());
        size_t count = end - first_test_index;
        if (count <= 1)
            return;
        for (size_t i = 0; i < count; i++) {
            size_t tmp1 = first_test_index + (random32() % count);
            size_t tmp2 = first_test_index + (random32() % count);
            if (tmp1 != tmp2)
                std::swap(listfile_recs[tmp1], listfile_recs[tmp2]);
        }
    }


    static int min(int a, int b) {
        return (a < b) ? a : b;
    }

};


#endif //SANDSTONE_LISTFILESELECTOR_H
