#include "sandstone_containers.h"

#if __linux__

#include <unistd.h>

static std::string detect_container_via_systemd(const std::string& path) {
    std::string cmd = path + " -c";
    FILE* fp = popen(cmd.c_str(), "r");

    if (fp == NULL) {
        return std::string("none");
    }

    char container_type[256];

    if(fgets(container_type, 256, fp) == NULL) {
        return std::string("none");
    }

    pclose(fp);

    auto type_str = std::string(container_type);
    type_str.pop_back(); // remove the newline character read
                         // from stdout of systemd-detect-virt

    return type_str;
}

static constexpr const char* detect_virt_paths[2] = {
    "/usr/bin/systemd-detect-virt",
    "/bin/systemd-detect-virt",
};

static std::optional<std::string> find_detect_virt_path() {
    for (auto path : detect_virt_paths) {
        if (access(path, X_OK) == 0) {
            return std::optional<std::string>(path);
        }
    }
    return std::nullopt;
}

std::optional<std::string> detect_running_container() {
    auto path = find_detect_virt_path();

    if (path.has_value()) {
        std::string detected = detect_container_via_systemd(path.value());

        if (detected.compare("none") == 0) {
            return std::nullopt;
        } else {
            return std::optional<std::string>(detected);
        }
    }

    /* either failed to detect of not running inside of a container */
    return std::nullopt;
}

#else

std::optional<std::string> detect_running_container() {
    return std::nullopt;
}

#endif /* __linux__ */
