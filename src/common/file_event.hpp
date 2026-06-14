#pragma once

#include <cstdint>
#include <string>

struct FileEvent {
    double timestamp_seconds{};
    std::string user_name;
    std::string process_name;
    int process_id{};
    std::string operation;
    std::string path;
    std::uint64_t bytes{};
    double byte_entropy{};
};
