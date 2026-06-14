#include "feature_window.hpp"

#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <numeric>
#include <set>
#include <sstream>

FeatureWindow::FeatureWindow(double window_seconds) : window_seconds_(window_seconds) {}

void FeatureWindow::add_event(const FileEvent& event) {
    events_.push_back(event);
    expire_old_events(event.timestamp_seconds);
}

void FeatureWindow::expire_old_events(double now_seconds) {
    while (!events_.empty() && now_seconds - events_.front().timestamp_seconds > window_seconds_) {
        events_.pop_front();
    }
}

FeatureVector FeatureWindow::features() const {
    FeatureVector f{};
    if (events_.empty()) {
        return f;
    }

    std::set<std::string> directories;
    std::set<std::string> extensions;
    int writes = 0;
    int rename_or_delete = 0;
    double entropy_sum = 0.0;

    for (const auto& event : events_) {
        if (event.operation == "write") {
            ++writes;
        }
        if (event.operation == "rename" || event.operation == "delete") {
            ++rename_or_delete;
        }

        std::filesystem::path path(event.path);
        directories.insert(path.parent_path().string());
        extensions.insert(path.extension().string());
        entropy_sum += event.byte_entropy;
    }

    const double n = static_cast<double>(events_.size());
    f.events_per_second = n / window_seconds_;
    f.writes_per_second = static_cast<double>(writes) / window_seconds_;
    f.rename_delete_rate = static_cast<double>(rename_or_delete) / window_seconds_;
    f.average_byte_entropy = entropy_sum / n;
    f.unique_directory_count = static_cast<double>(directories.size());
    f.unique_extension_count = static_cast<double>(extensions.size());
    return f;
}

std::vector<double> to_vector(const FeatureVector& features) {
    return {
        features.events_per_second,
        features.writes_per_second,
        features.rename_delete_rate,
        features.average_byte_entropy,
        features.unique_directory_count,
        features.unique_extension_count,
    };
}

std::string to_string(const FeatureVector& features) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(3)
        << "events/s=" << features.events_per_second
        << " writes/s=" << features.writes_per_second
        << " rename_delete/s=" << features.rename_delete_rate
        << " entropy=" << features.average_byte_entropy
        << " dirs=" << features.unique_directory_count
        << " extensions=" << features.unique_extension_count;
    return out.str();
}
