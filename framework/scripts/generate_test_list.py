#!/usr/bin/env python3
# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

arguments_desc="""
Arguments are (in order, all required):
  - the name of the .h file to generate;
  - the name of the .cpp file to generate;
  - the absolute path to the repo (needed to locate the list files);
  - comma-separated list of tuples <id>:<test list file>;
    e.g. default:data/default_test_list.csv,skylake:data/skylake_test_list.csv
"""

import sys
import os

# print usage
def usage():
    name = os.path.basename(sys.argv[0])
    print(f'Usage: {name} [ARGS]')
    print(arguments_desc)

def main():
    if len(sys.argv) < 5:
        usage()
        exit(2)
    args = sys.argv
    h_file = args[1]
    h_file_basename = os.path.basename(h_file)
    cpp_file = args[2]
    root = args[3]
    config_str = args[4] # the rest is config tuples
    # test_list_files = { "name1" => "test_list_file1", "name2" =>
    # "test_list_file2", ... }
    test_list_files = {}
    if (config_str == ''):
        config = {}
    else:
        config = config_str.split(',')
    default_name = None
    for pair in config:
        parsed = pair.split(':')
        if len(parsed) != 2:
            print(f'Incorrect configuration string: {pair}')
            exit(2)
        name = parsed[0]
        path = parsed[1]
        if default_name is None:
            default_name = name # the first on the list is the default one,
                                # it should be called "default", but this does
                                # not rely on that
        test_list_files[name] = root + "/" + path

    # test_lists = { "name1" => [ "test1", "test2", ... ], "name2" => [ "test2",
    # "test4", ..] }
    # contains all the .c files to generate mapped to the ordered list of tests
    test_lists = {}
    all_tests = {}

    # read and process all the arguments
    for name, file in test_list_files.items():
        with open(file, 'r') as f:
            lines = f.readlines()

        test_lists[name] = []
        test_list = test_lists[name]
        for l in lines:
            l = l.split('#', 1)[0]
            l = l.strip()
            if len(l) == 0:
                continue
            test_list.append(l)
            all_tests[l] = 1

    has_any_lists = len(test_lists) > 0

    # generate the .cpp file
    with open(cpp_file, 'w') as f:
        f.write('#include <span>\n')
        f.write(f'#include "{h_file_basename}"\n')
        f.write('#include "sandstone_tests.h"\n')
        f.write('#include "SelectorFactory.h"\n')
        decls = [ f'extern struct test _test_{test};' for test in sorted(all_tests.keys()) ]
        f.write('\n'.join(decls))
        f.write('\n\n')

        for name, tests in test_lists.items():
            f.write(f'static constexpr struct test * const {name}_test_list_[] = {{')
            test_list = [ f'    &_test_{test}' for test in tests ]
            f.write(',\n'.join(test_list))
            f.write('\n};\n\n')
            f.write(f'static const struct TestList {name}_test_list = {{ {"cpu_" + name if name != "default" else 0}, "{name}", {name}_test_list_ }};\n\n')

        if has_any_lists:
            f.write('static const struct TestList* test_lists[] = {\n')
            for name, _ in test_lists.items():
                if default_name is not None and name != default_name:
                    f.write(f'    &{name}_test_list,\n')
            if default_name is not None:
                f.write(f'    &{default_name}_test_list\n') # put default list as last one
            f.write('};\n\n')

        # write selector function
        f.write('std::optional<const std::span<struct test * const>> get_test_list(const char *test_list_name) {\n')
        if has_any_lists:
            if default_name is not None:
                f.write(f'    if (!test_list_name || !strcmp(test_list_name, "auto")) return auto_detect_test_list(test_lists, &{default_name}_test_list);\n')
            else:
                f.write(f'    if (!test_list_name || !strcmp(test_list_name, "auto")) return auto_detect_test_list(test_lists);\n')
        for name in test_lists.keys():
            f.write(f'    if (!strcmp(test_list_name, "{name}")) return {name}_test_list.content;\n')
        if default_name is not None:
            f.write(f'    return {default_name}_test_list.content;\n')
        else:
            f.write('    return std::nullopt;\n')
        f.write('}\n')

    # generate .h file
    with open(h_file, 'w') as f:
        f.write('#include <optional>\n')
        f.write('#include <span>\n')
        f.write('#include "sandstone.h"\n\n')
        f.write('std::optional<const std::span<struct test * const>> get_test_list(const char *);\n')

    exit(0)

if __name__ == '__main__':
    main()
