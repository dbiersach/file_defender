#!/usr/bin/env python3
"""train_isolation_forest.py

Train an Isolation Forest on benign file-activity features and export it to a
JSON file that the C++ daemon can load and score without any Python runtime.

The export contains the full forest (every tree's structure) plus the feature
scaler, so the C++ AnomalyModel reproduces scikit-learn's anomaly score exactly.
A joblib copy of the (scaler, model) is also saved for use in Python.

Data sources (pick one):
  --synthetic            Train on the built-in synthetic "normal" cluster.
  --events events.csv    Train on features built from a raw event log.
  --features feats.csv   Train on a precomputed feature CSV.

Examples:
  python3 train_isolation_forest.py --synthetic --out ../models/model.json
  python3 train_isolation_forest.py --events ../testdata/sample_events.csv \\
      --out ../models/model.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from features import FEATURE_COLUMNS, build_feature_rows
from simulate_activity import generate_feature_dataset
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


def load_training_features(args: argparse.Namespace) -> pd.DataFrame:
    """Return a DataFrame of FEATURE_COLUMNS rows to train on."""
    if args.synthetic:
        data = generate_feature_dataset(seed=42)
        # Train only on benign behavior (the core idea of the project).
        return data[data["label"] == "normal"][FEATURE_COLUMNS].reset_index(drop=True)
    if args.events:
        events = pd.read_csv(args.events)
        return build_feature_rows(events, window_seconds=args.window)
    if args.features:
        return pd.read_csv(args.features)[FEATURE_COLUMNS]
    raise SystemExit("Choose a data source: --synthetic, --events, or --features")


def export_model_json(
    scaler: StandardScaler,
    model: IsolationForest,
    recommended_threshold: float,
    out_path: Path,
) -> None:
    """Serialize the scaler and every tree to the JSON the C++ daemon reads."""
    trees = []
    for estimator in model.estimators_:
        tree = estimator.tree_
        trees.append(
            {
                "feature": tree.feature.tolist(),
                "threshold": tree.threshold.tolist(),
                "children_left": tree.children_left.tolist(),
                "children_right": tree.children_right.tolist(),
                "n_node_samples": tree.n_node_samples.tolist(),
            }
        )

    export = {
        "feature_columns": FEATURE_COLUMNS,
        "scaler_mean": scaler.mean_.tolist(),
        "scaler_scale": np.maximum(scaler.scale_, 1.0e-9).tolist(),
        "max_samples": int(model.max_samples_),
        # Data-driven alert threshold: a high percentile of the benign training
        # scores. This is far more useful than scikit-learn's fixed offset_,
        # which assumes a 0.5 inlier/outlier boundary that does not fit every
        # dataset. The C++ daemon uses this value by default.
        "recommended_threshold": recommended_threshold,
        # scikit-learn's offset_ is kept for reference.
        "offset": float(model.offset_),
        "trees": trees,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(export), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--synthetic", action="store_true", help="use built-in synthetic data"
    )
    source.add_argument("--events", help="raw event CSV to build features from")
    source.add_argument("--features", help="precomputed feature CSV")
    parser.add_argument(
        "--out", default="../models/model.json", help="output model JSON path"
    )
    parser.add_argument(
        "--joblib", default="../models/model.joblib", help="output joblib path"
    )
    parser.add_argument(
        "--window", type=float, default=10.0, help="rolling window seconds"
    )
    parser.add_argument(
        "--trees", type=int, default=200, help="number of isolation trees"
    )
    parser.add_argument("--max-samples", type=int, default=256, help="samples per tree")
    parser.add_argument(
        "--max-fpr",
        type=float,
        default=0.005,
        help="target false-positive rate; sets the alert threshold from the "
        "benign training scores (default 0.5%%)",
    )
    args = parser.parse_args()

    features = load_training_features(args)
    if len(features) < 5:
        raise SystemExit(
            f"Not enough training rows ({len(features)}); need at least 5."
        )

    x = features[FEATURE_COLUMNS].to_numpy(dtype=float)

    scaler = StandardScaler().fit(x)
    x_scaled = scaler.transform(x)

    model = IsolationForest(
        n_estimators=args.trees,
        max_samples=min(args.max_samples, len(x)),
        contamination="auto",
        random_state=42,
    ).fit(x_scaled)

    # Anomaly scores on the benign training set. The alert threshold is the
    # (1 - max_fpr) percentile of these scores: by construction at most max_fpr
    # of benign windows will exceed it, while genuinely anomalous activity
    # (which the model has never seen) scores much higher.
    anomaly_scores = -model.score_samples(x_scaled)
    recommended_threshold = float(np.quantile(anomaly_scores, 1.0 - args.max_fpr))

    out_json = Path(args.out)
    export_model_json(scaler, model, recommended_threshold, out_json)
    joblib.dump((scaler, model), args.joblib)

    print(f"Trained on {len(x)} benign feature rows.")
    print(f"  trees           : {args.trees}")
    print(f"  train score min : {anomaly_scores.min():.4f}")
    print(f"  train score max : {anomaly_scores.max():.4f}")
    print(f"  target max FPR  : {args.max_fpr:.3%}")
    print(f"  recommended thr : {recommended_threshold:.4f}")
    print(f"Wrote model JSON : {out_json}")
    print(f"Wrote joblib     : {args.joblib}")


if __name__ == "__main__":
    main()
