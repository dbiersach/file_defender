#!/usr/bin/env python3
"""subsample_sweep.py

Measure what the subsample size (psi, scikit-learn's `max_samples`) does to an
Isolation Forest, in two settings that must not be confused with each other.

Setting 1 - one-class training, which is what this project does
-----------------------------------------------------------------
The forest is trained on benign windows only, then scored on a fresh set that
contains both benign and ransomware windows. This is the honest test of
whether psi matters for File Defender.

Setting 2 - contaminated training, which is what the original paper studied
-----------------------------------------------------------------------------
The forest is trained on a mixture that already contains a dense cluster of
anomalies. This is the setting where the paper's "masking" effect lives: a
crowd of anomalies in the training set can hide each other, and a small
subsample breaks the crowd up. It is included here so a student can see the
effect that the textbooks talk about, but it is NOT the setting this project
runs in, and its result should not be used to justify File Defender's psi.

Every number in docs/ABOUT_THE_TREE.md that involves psi comes from this
script, with the seeds below, so anyone can rerun it:

  uv run python python/subsample_sweep.py
"""

from __future__ import annotations

import argparse

import numpy as np
from features import FEATURE_COLUMNS
from simulate_activity import generate_feature_dataset
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


def one_class_sweep(psi_values: list[int], trees: int) -> None:
    """
    Sweep psi with benign-only training on the project's six features.

    Parameters
    ----------
    psi_values : list[int]
        Subsample sizes to try.
    trees : int
        Number of trees per forest.

    Returns
    -------
    None
        Prints one row per psi: the 99.5th-percentile threshold on the benign
        training scores, the share of ransomware windows caught, and the share
        of held-out benign windows wrongly flagged.
    """
    train = generate_feature_dataset(seed=42)
    x_train = train[train["label"] == "normal"][FEATURE_COLUMNS].to_numpy(float)
    test = generate_feature_dataset(seed=7)
    x_test = test[FEATURE_COLUMNS].to_numpy(float)
    labels = test["label"].to_numpy()

    scaler = StandardScaler().fit(x_train)
    print(f"benign training rows: {len(x_train)}, trees per forest: {trees}")
    print(
        f"{'psi':>6} {'threshold':>10} {'ransomware caught':>18} {'benign flagged':>15}"
    )
    for psi in psi_values:
        forest = IsolationForest(
            n_estimators=trees,
            max_samples=min(psi, len(x_train)),
            random_state=42,
        ).fit(scaler.transform(x_train))
        train_scores = -forest.score_samples(scaler.transform(x_train))
        threshold = float(np.quantile(train_scores, 0.995))
        scores = -forest.score_samples(scaler.transform(x_test))
        caught = float((scores[labels == "ransomware"] >= threshold).mean())
        flagged = float((scores[labels == "normal"] >= threshold).mean())
        print(
            f"{min(psi, len(x_train)):>6} {threshold:>10.4f} {caught:>17.1%} {flagged:>14.1%}"
        )


def contaminated_sweep(psi_values: list[int], trees: int) -> None:
    """
    Sweep psi with a dense anomaly cluster INCLUDED in the training data.

    Parameters
    ----------
    psi_values : list[int]
        Subsample sizes to try.
    trees : int
        Number of trees per forest.

    Returns
    -------
    None
        Prints one row per psi with the mean benign score, the mean anomaly
        score, and the gap between them. A bigger gap means the two groups
        are easier to tell apart on this data. It is a gap between averages,
        not a detection rate, so do not read it as "twice as good".
    """
    rng = np.random.default_rng(0)
    benign = rng.normal(0.0, 1.0, size=(2000, 2))
    anomaly = rng.normal(8.0, 0.4, size=(200, 2))
    data = np.vstack([benign, anomaly])

    print("2000 benign points and 200 tightly clustered anomalies, all in training")
    print(f"{'psi':>6} {'benign mean':>12} {'anomaly mean':>13} {'gap':>8}")
    for psi in psi_values:
        forest = IsolationForest(
            n_estimators=trees, max_samples=min(psi, len(data)), random_state=42
        ).fit(data)
        scores = -forest.score_samples(data)
        benign_mean = float(scores[:2000].mean())
        anomaly_mean = float(scores[2000:].mean())
        print(
            f"{min(psi, len(data)):>6} {benign_mean:>12.4f} {anomaly_mean:>13.4f} "
            f"{anomaly_mean - benign_mean:>8.4f}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trees", type=int, default=200)
    args = parser.parse_args()

    print("=" * 72)
    print("SETTING 1: one-class training (what File Defender does)")
    print("=" * 72)
    one_class_sweep([16, 32, 64, 128, 256, 400], args.trees)

    print()
    print("=" * 72)
    print("SETTING 2: contaminated training (the paper's masking experiment)")
    print("=" * 72)
    contaminated_sweep([8, 16, 32, 64, 128, 256, 1024, 2200], args.trees)


if __name__ == "__main__":
    main()
