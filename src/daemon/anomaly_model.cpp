#include "anomaly_model.hpp"

#include <cmath>
#include <fstream>

#include <nlohmann/json.hpp>

namespace {

// Average path length of an unsuccessful search in a binary search tree of n
// points. This is scikit-learn's c(n) normalization constant, used both to
// adjust early-terminated leaves and to normalize the final score.
double average_path_length(double n) {
    if (n <= 1.0) {
        return 0.0;
    }
    if (n == 2.0) {
        return 1.0;
    }
    const double euler_mascheroni = 0.5772156649015329;
    return 2.0 * (std::log(n - 1.0) + euler_mascheroni) - 2.0 * (n - 1.0) / n;
}

}  // namespace

double AnomalyModel::path_length(const Tree& tree, const std::vector<double>& scaled) const {
    int node = 0;
    int depth = 0;

    // Walk down the tree until we reach a leaf (a node with no children).
    while (tree.children_left[node] != -1) {
        const int split_feature = tree.feature[node];
        if (scaled[split_feature] <= tree.threshold[node]) {
            node = tree.children_left[node];
        } else {
            node = tree.children_right[node];
        }
        depth++;
    }

    // Leaves may contain more than one training sample (the tree stops at a
    // height limit), so we add the expected extra depth for that subset.
    return static_cast<double>(depth) +
           average_path_length(static_cast<double>(tree.n_node_samples[node]));
}

double AnomalyModel::score(const std::vector<double>& features) const {
    if (trees_.empty() || features.size() != scaler_mean_.size()) {
        return 0.0;
    }

    // Apply the same standardization the Python pipeline used before training.
    std::vector<double> scaled(features.size());
    for (std::size_t i = 0; i < features.size(); ++i) {
        const double denom = (scaler_scale_[i] != 0.0) ? scaler_scale_[i] : 1.0e-9;
        scaled[i] = (features[i] - scaler_mean_[i]) / denom;
    }

    // Mean isolation depth across the whole forest.
    double total_depth = 0.0;
    for (const auto& tree : trees_) {
        total_depth += path_length(tree, scaled);
    }
    const double mean_depth = total_depth / static_cast<double>(trees_.size());

    // Convert mean depth to the Isolation Forest anomaly score in (0, 1).
    const double normalizer = average_path_length(max_samples_);
    return std::pow(2.0, -mean_depth / normalizer);
}

bool AnomalyModel::load(const std::string& path) {
    std::ifstream input(path);
    if (!input) {
        return false;
    }

    nlohmann::json model;
    try {
        input >> model;

        feature_columns_ = model.at("feature_columns").get<std::vector<std::string>>();
        scaler_mean_ = model.at("scaler_mean").get<std::vector<double>>();
        scaler_scale_ = model.at("scaler_scale").get<std::vector<double>>();
        max_samples_ = model.at("max_samples").get<double>();

        // Prefer the data-driven threshold exported by the trainer (a high
        // percentile of benign training scores). Fall back to scikit-learn's
        // offset_ boundary (-offset_) only if it is missing.
        if (model.contains("recommended_threshold")) {
            recommended_threshold_ = model.at("recommended_threshold").get<double>();
        } else {
            recommended_threshold_ = -model.at("offset").get<double>();
        }

        trees_.clear();
        for (const auto& tree_json : model.at("trees")) {
            Tree tree;
            tree.feature = tree_json.at("feature").get<std::vector<int>>();
            tree.threshold = tree_json.at("threshold").get<std::vector<double>>();
            tree.children_left = tree_json.at("children_left").get<std::vector<int>>();
            tree.children_right = tree_json.at("children_right").get<std::vector<int>>();
            tree.n_node_samples = tree_json.at("n_node_samples").get<std::vector<int>>();
            trees_.push_back(std::move(tree));
        }
    } catch (const nlohmann::json::exception&) {
        return false;
    }

    return !trees_.empty() && scaler_mean_.size() == scaler_scale_.size();
}
