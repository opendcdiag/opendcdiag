/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_YAML_H
#define SANDSTONE_YAML_H

#include <map>
#include <string>
#include <variant>

#include <stdint.h>

namespace YamlFormatter {
using SimpleValue = std::variant<bool, int64_t, uint64_t, double, std::string_view, std::string>;

std::string format_yaml(std::string_view key, const YamlFormatter::SimpleValue &value);
std::string format_yaml(const std::map<std::string, YamlFormatter::SimpleValue> &values);
}

using YamlFormatter::format_yaml;

#endif // SANDSTONE_YAML_H
