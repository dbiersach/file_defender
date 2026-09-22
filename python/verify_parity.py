#!/usr/bin/env python3
"""verify_parity.py

Check that the exported JSON model scores the same way scikit-learn does.

The C++ daemon cannot be compiled or run on every machine (it needs Linux), so
this script does not run it. Instead, it re-implements the JSON scoring
algorithm in pure Python - the SAME algorithm the C++ AnomalyModel uses - and
checks it matches scikit-learn's own score to within a tiny tolerance.

Be precise about what a pass means. It shows that the JSON export is complete
and that the scoring math written in Python is right. It does NOT run the C++
code, and it does NOT compare the C++ feature computation against
python/features.py. Those two checks live in verify_cpp_parity.py, which runs
the real daemon and must be run on Linux.

One more caveat: scikit-learn converts the rows it scores to float32 before
walking the trees, while this script and the C++ daemon use doubles. A value
that sits exactly on a split threshold could go left in one and right in the
other. The boundary check at the end of this script measures how much that
matters on the trained model.

It is self-contained: it trains a small synthetic model in memory, exports it
to the same JSON format the C++ daemon reads, and compares scores. Just run:

  python3 verify_parity.py
"""

from __future__ import annotations

import argparse
import json
import math
import tempfile
from pathlib import Path

import numpy as np
from features import FEATURE_COLUMNS
from simulate_activity import generate_feature_dataset
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from train_isolation_forest import export_model_json


def average_path_length(n: float) -> float:
    """scikit-learn's c(n): expected path length of an unsuccessful BST search."""
    if n <= 1.0:
        return 0.0
    if n == 2.0:
        return 1.0
    euler_mascheroni = 0.5772156649015329
    return 2.0 * (math.log(n - 1.0) + euler_mascheroni) - 2.0 * (n - 1.0) / n


def score_from_json(model: dict, x_raw: np.ndarray) -> np.ndarray:
    """
    Reproduce the Isolation Forest anomaly score from the exported JSON.

    This is the reference for the C++ implementation in anomaly_model.cpp.

    Parameters
    ----------
    model : dict
        The parsed model JSON, holding the scaler, max_samples, and every tree.
    x_raw : np.ndarray
        Unscaled feature rows, shape (n_samples, n_features).

    Returns
    -------
    np.ndarray
        One score per row in (0, 1); higher means more anomalous.
    """
    mean = np.asarray(model["scaler_mean"])
    scale = np.asarray(model["scaler_scale"])
    max_samples = float(model["max_samples"])
    trees = model["trees"]

    x = (x_raw - mean) / scale  # apply the same standardization as training
    normalizer = average_path_length(max_samples)
    scores = np.zeros(len(x))

    for i, sample in enumerate(x):
        total_depth = 0.0
        for tree in trees:
            feature = tree["feature"]
            threshold = tree["threshold"]
            left = tree["children_left"]
            right = tree["children_right"]
            n_node = tree["n_node_samples"]

            node = 0
            depth = 0
            while left[node] != -1:  # not a leaf
                if sample[feature[node]] <= threshold[node]:
                    node = left[node]
                else:
                    node = right[node]
                depth += 1
            total_depth += depth + average_path_length(float(n_node[node]))

        mean_depth = total_depth / len(trees)
        scores[i] = 2.0 ** (-mean_depth / normalizer)

    return scores


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tolerance", type=float, default=1.0e-9)
    args = parser.parse_args()

    # Train a small synthetic model in memory (benign cluster only).
    train_data = generate_feature_dataset(seed=42)
    x_train = train_data[train_data["label"] == "normal"][FEATURE_COLUMNS].to_numpy(
        dtype=float
    )
    scaler = StandardScaler().fit(x_train)
    sk_model = IsolationForest(
        n_estimators=200, max_samples=256, contamination="auto", random_state=42
    ).fit(scaler.transform(x_train))

    # Export to the JSON format the C++ daemon consumes, then read it back.
    train_scores = -sk_model.score_samples(scaler.transform(x_train))
    threshold = float(np.quantile(train_scores, 0.995))
    with tempfile.TemporaryDirectory() as tmp:
        json_path = Path(tmp) / "model.json"
        export_model_json(scaler, sk_model, threshold, json_path)
        model_json = json.loads(json_path.read_text(encoding="utf-8"))

    # Evaluate on a fresh dataset with both clusters.
    data = generate_feature_dataset(seed=7)
    x_raw = data[FEATURE_COLUMNS].to_numpy(dtype=float)

    json_scores = score_from_json(model_json, x_raw)
    # scikit-learn's score_samples = -(anomaly score); negate to compare.
    sklearn_scores = -sk_model.score_samples(scaler.transform(x_raw))

    max_diff = float(np.max(np.abs(json_scores - sklearn_scores)))
    print(f"Samples compared : {len(x_raw)}")
    print(f"Max abs difference: {max_diff:.3e}")

    # Show that the model actually separates the two clusters, using the same
    # data-driven threshold the C++ daemon will use.
    threshold = float(model_json.get("recommended_threshold", -float(sk_model.offset_)))
    labels = data["label"].to_numpy()
    flagged = json_scores >= threshold
    normal_flagged = int(flagged[labels == "normal"].sum())
    ransom_flagged = int(flagged[labels == "ransomware"].sum())
    print(f"Threshold        : {threshold:.4f}")
    print(f"Normal flagged    : {normal_flagged} / {(labels == 'normal').sum()}")
    print(f"Ransomware flagged: {ransom_flagged} / {(labels == 'ransomware').sum()}")

    # Boundary check. Build rows that sit exactly on split thresholds, score
    # them both ways, and report the worst disagreement. This is where the
    # float32 cast inside scikit-learn could, in principle, send a value down
    # a different branch than the double-precision JSON walk does.
    boundary_diff = boundary_case_difference(sk_model, scaler, model_json)
    print(f"Boundary rows max abs difference: {boundary_diff:.3e}")

    if max_diff <= args.tolerance:
        print(
            "\nPARITY OK: the JSON export scores the same way scikit-learn does.\n"
            "The C++ scorer mirrors this Python reference line for line, but it\n"
            "was NOT run here. Run python/verify_cpp_parity.py on Linux for that."
        )
    else:
        raise SystemExit(
            f"\nPARITY FAILED: difference {max_diff} exceeds {args.tolerance}"
        )


def boundary_case_difference(
    sk_model: IsolationForest, scaler: StandardScaler, model_json: dict
) -> float:
    """
    Score rows placed exactly on split thresholds both ways; return the gap.

    For each of the first few trees, take the root's split feature and
    threshold, build a standardized row whose other coordinates are zero and
    whose split coordinate equals the threshold exactly, then map it back to
    raw units and score it with scikit-learn and with the JSON walk.

    Parameters
    ----------
    sk_model : IsolationForest
        The fitted scikit-learn forest.
    scaler : StandardScaler
        The scaler used at training time.
    model_json : dict
        The exported model, as read back from JSON.

    Returns
    -------
    float
        The largest absolute score difference over the boundary rows.
    """
    n_features = len(model_json["scaler_mean"])
    rows = []
    for tree in model_json["trees"][:25]:
        feature = int(tree["feature"][0])
        threshold = float(tree["threshold"][0])
        scaled = np.zeros(n_features)
        scaled[feature] = threshold
        rows.append(scaled)
    scaled_rows = np.asarray(rows)
    raw_rows = scaled_rows * np.asarray(model_json["scaler_scale"]) + np.asarray(
        model_json["scaler_mean"]
    )
    json_scores = score_from_json(model_json, raw_rows)
    sklearn_scores = -sk_model.score_samples(scaler.transform(raw_rows))
    return float(np.max(np.abs(json_scores - sklearn_scores)))


if __name__ == "__main__":
    main()
