#pragma once

/*
 * FeatureWindow: the rolling per-process window and the six-number feature
 * vector computed from it.
 *
 * FeatureVector's member order is the contract with the trained model. The
 * exported JSON lists its feature_columns in this same order, and
 * AnomalyModel::score indexes the vector positionally, so reordering these
 * members silently mis-scores every window. See python/features.py for the
 * canonical definition.
 */

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
