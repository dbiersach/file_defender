#pragma once

#include "file_event.hpp"

#include <deque>
#include <string>
#include <vector>

struct FeatureVector {
    double events_per_second{};
    double writes_per_second{};
    double rename_delete_rate{};
    double average_byte_entropy{};
    double unique_directory_count{};
    double unique_extension_count{};
};

class FeatureWindow {
public:
    explicit FeatureWindow(double window_seconds);
    void add_event(const FileEvent& event);
    FeatureVector features() const;

private:
    void expire_old_events(double now_seconds);
    double window_seconds_;
    std::deque<FileEvent> events_;
};

std::vector<double> to_vector(const FeatureVector& features);
std::string to_string(const FeatureVector& features);
