#pragma once

/*
 * FileEvent: one observed filesystem operation, as the collector reports it.
 *
 * This is the single shared vocabulary between the C collector and the C++
 * daemon. The field order matches the eight columns of the collector's CSV
 * output exactly (see fanotify_collector.c), so the parser in main.cpp can walk
 * the fields in order without a lookup table. Changing the order here means
 * changing the collector's printf and the CSV header together.
 */

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
