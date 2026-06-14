#pragma once

#include <string>
#include <vector>

/*
 * AnomalyModel: a faithful C++ re-implementation of scikit-learn's
 * IsolationForest scoring.
 *
 * The model is trained in Python (python/train_isolation_forest.py) and
 * exported to JSON as a set of decision trees plus the feature scaler. This
 * class loads that JSON and reproduces the same anomaly score the Python model
 * would give, with no Python runtime needed at inference time.
 *
 * score() returns the Isolation Forest anomaly score s(x) in the range (0, 1):
 *   - values near 1.0  -> strongly anomalous (isolated quickly, few questions)
 *   - values near 0.5  -> typical / benign
 * This matches the intuition "higher score = more suspicious", so the daemon
 * can compare it directly against a threshold.
 */
class AnomalyModel {
public:
    // Load the exported model JSON. Returns false on any error.
    bool load(const std::string& path);

    // Anomaly score in (0, 1); higher means more anomalous.
    double score(const std::vector<double>& features) const;

    // Recommended alert threshold derived from the model's training
    // contamination setting (scikit-learn's offset_).
    double recommended_threshold() const { return recommended_threshold_; }

    const std::vector<std::string>& feature_columns() const { return feature_columns_; }

private:
    // One isolation tree stored as flat arrays, indexed by node id.
    struct Tree {
        std::vector<int> feature;          // split feature index, -1 for a leaf
        std::vector<double> threshold;     // split threshold
        std::vector<int> children_left;    // left child id, -1 for a leaf
        std::vector<int> children_right;   // right child id, -1 for a leaf
        std::vector<int> n_node_samples;   // training samples that reached node
    };

    double path_length(const Tree& tree, const std::vector<double>& scaled) const;

    std::vector<std::string> feature_columns_;
    std::vector<double> scaler_mean_;
    std::vector<double> scaler_scale_;
    std::vector<Tree> trees_;
    double max_samples_ = 256.0;
    double recommended_threshold_ = 0.5;
};
