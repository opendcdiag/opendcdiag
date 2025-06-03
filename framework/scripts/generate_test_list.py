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
    config_str = args[4]
    test_list_files = {}
    default_name = None
    other_names = False
    test_lists = {}
    all_tests = {}
    files = {}

    if (config_str == ''):
        config = {}
    else:
        config = config_str.split(',')
    for pair in config:
        parsed = pair.split(':')
        if len(parsed) == 2:
            name = parsed[0]
            path = parsed[1]
        elif len(parsed) == 1:
            name = "default"
            path = parsed[0]
        else:
            print(f'Incorrect configuration string: {pair}')
            exit(2)

        if name == 'auto':
            print(f'Reserved generation name used for {path}')
            exit(2)
        if name == 'default':
            default_name = name
        else:
            other_names = True

        test_list_files[name] = path

    # collect file names
    for name, path in test_list_files.items():
        if path not in files:
            files[path] = len(files)

    # read and process all files
    for path, file_id in files.items():
        with open(root + "/" + path, 'r') as f:
            lines = f.readlines()

        test_lists[path] = []
        test_list = test_lists[path]
        for l in lines:
            l = l.split('#', 1)[0]
            l = l.strip()
            if len(l) == 0:
                continue
            test_list.append(l)
            all_tests[l] = 1

    # generate the .cpp file
    with open(cpp_file, 'w') as f:
        f.write('// THIS IS GENERATED FILE, DO NOT EDIT\n\n')
        f.write(f'#include "{h_file_basename}"\n')
        f.write(f'#include <sandstone_p.h>\n\n')

        # list of tests (all from files, in alphabetical order)
        if len(all_tests) != 0:
            decls = [ f'extern struct test _test_{test};' for test in sorted(all_tests.keys()) ]
            f.write('\n'.join(decls))
            f.write('\n\n')

        if len(files) != 0:
            for path, tests in test_lists.items():
                file_id = files[path]
                num_tests = len(tests)
                f.write(f'// content of {path}\n')
                f.write(f'static const std::vector<struct test *> test_set_{file_id}{{')
                test_list = [ f'\n    &_test_{test}' for test in tests ]
                f.write(','.join(test_list))
                f.write('\n};\n')
            f.write('\n')

        # build all defined lists
        for name, path in test_list_files.items():
            file_id = files[path]
            # this uses cpu_<code name> defined via simd.conf
            f.write(f'static const BuiltinTestSet {name}_test_set{{ {"cpu_" + name if name != "default" else 0}, "{name}", test_set_{file_id} }};\n')
        # create default "null" list if not defined
        if default_name is None:
            f.write(f'static const BuiltinTestSet default_test_set{{ 0, "default", std::nullopt }};\n')
        f.write('\n')

        # function to check if the list is selected, applied to non-default lists only
        if other_names:
            f.write('static bool test_list_matches(const BuiltinTestSet* test_set, const char* name)\n')
            f.write('{\n')
            f.write('#ifdef SANDSTONE\n')
            f.write('    if ((name == nullptr) || (strcmp(name, "auto") == 0)) {\n')
            f.write('        return (test_set->features & cpu_features) == test_set->features;\n')
            f.write('    }\n')
            f.write('#endif\n')
            f.write('    return (name != nullptr) && (strcmp(name, test_set->name) == 0);\n')
            f.write('}\n\n')

        # selector function
        f.write('const BuiltinTestSet& get_builtin_test_set(const char *name)\n')
        f.write('{\n')
        for name in test_list_files.keys():
            if default_name is None or name != default_name:
                f.write(f'    if (test_list_matches(&{name}_test_set, name)) return {name}_test_set;\n')

        # emit warning if neither list matches
        if default_name is not None:
            f.write('    if (name && (strcmp(name, "default") != 0)) {\n')
            f.write('        logging_printf(LOG_LEVEL_QUIET, "# ERROR: list for %s not found. Using default\\n", name);\n')
            f.write('    }\n')
        f.write('    return default_test_set;\n')
        f.write('}\n')

    # generate .h file
    with open(h_file, 'w') as f:
        f.write('// THIS IS GENERATED FILE, DO NOT EDIT\n\n')
        f.write('#ifndef INC_SANDSTONE_TEST_LISTS_H\n');
        f.write('#define INC_SANDSTONE_TEST_LISTS_H\n');
        f.write('#include <sandstone.h>\n')
        f.write('#include <optional>\n')
        f.write('#include <vector>\n\n')

        # per-gen list definition
        f.write('typedef struct BuiltinTestSet {\n')
        f.write('    cpu_features_t features;\n')
        f.write('    const char* name;\n')
        f.write('    const std::optional<std::vector<struct test *>> tests;\n')
        f.write('} BuiltinTestSet ;\n\n')

        f.write('const BuiltinTestSet& get_builtin_test_set(const char *);\n')
        f.write('#endif /* INC_SANDSTONE_TEST_LISTS_H */\n')

    exit(0)

if __name__ == '__main__':
    main()
