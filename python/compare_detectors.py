#!/usr/bin/env python3
"""compare_detectors.py

Put the Isolation Forest up against three alternatives on the same data, with
the same false-positive budget.

The project currently asserts that an Isolation Forest is the right model. This
script tries to demonstrate it, which is a different and much stronger claim. It
trains four one-class detectors on one benign baseline, calibrates every one of
them by the identical rule (the 99.5th percentile of its own benign training
scores), and evaluates all four on a held-out benign session plus a ransomware
sweep:

  1. Isolation Forest      - the incumbent, from scikit-learn.
  2. Robust z-score        - six medians and six scales, one-sided.
  3. Mahalanobis distance  - a single Gaussian with Ledoit-Wolf shrinkage.
  4. Extended Isolation Forest - oblique cuts instead of axis-aligned ones.

Reported per detector: false-positive rate out of sample, detection rate,
ROC-AUC, average precision, how many files were encrypted before the first
alert, and serialized model size. The last two columns are the ones a defender
actually cares about.

The final section probes the specific geometric weakness of axis-aligned
splitting, by scoring points that are ordinary in every individual feature but
sit off the correlation ridge the benign data occupies.

Run it with:

  uv run python python/compare_detectors.py
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
from baseline_detectors import MahalanobisDetector, RobustZScoreDetector
from evaluation import (
    build_labeled_features,
    evaluate_detector,
    format_report_table,
    threshold_at_fpr,
)
from extended_isolation_forest import ExtendedIsolationForest
from features import FEATURE_COLUMNS
from simulate_realistic_baseline import (
    generate_baseline_event_log,
    generate_paced_attack,
)
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from train_isolation_forest import export_model_json

# Paces at which to run the whole comparison, in files per minute. One
# smash-and-grab and one deliberately paced attacker, because the ranking of
# detectors is not the same at both speeds.
TEST_PACES: list[float] = [120.0, 30.0]


def json_bytes(payload: dict) -> int:
    """Return the size of a model dict once serialized to JSON."""
    return len(json.dumps(payload).encode("utf-8"))


def isolation_forest_bytes(
    scaler: StandardScaler, forest: IsolationForest, threshold: float
) -> int:
    """
    Measure the exported size of a scikit-learn forest.

    Uses the project's real exporter rather than an estimate, so the number is
    the size the C++ daemon would actually have to load.

    Parameters
    ----------
    scaler : StandardScaler
        The fitted feature scaler.
    forest : IsolationForest
        The fitted forest.
    threshold : float
        Alert threshold to embed in the export.

    Returns
    -------
    int
        Size of the exported model JSON, in bytes.
    """
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "model.json"
        export_model_json(scaler, forest, threshold, path)
        return len(path.read_bytes())


class DetectorSuite:
    """The four detectors, all fitted on one benign training set."""

    def __init__(self, training_features: np.ndarray, trees: int = 200) -> None:
        self.training_features = training_features
        max_samples = min(256, len(training_features))

        # The standard forest and the extended forest both score standardized
        # input. For the standard forest that is cosmetic, because axis-aligned
        # splits are invariant under a monotone per-feature rescaling. For the
        # extended forest it is load-bearing, because an oblique cut mixes
        # features and therefore depends on their relative scales.
        self.scaler = StandardScaler().fit(training_features)
        scaled = self.scaler.transform(training_features)

        self.forest = IsolationForest(
            n_estimators=trees,
            max_samples=max_samples,
            contamination="auto",
            random_state=42,
        ).fit(scaled)

        self.extended = ExtendedIsolationForest(
            n_estimators=trees, max_samples=max_samples, random_state=42
        ).fit(scaled)

        # The two baselines work on raw features. Neither needs a scaler: the
        # z-score divides by a per-feature scale by construction, and the
        # Mahalanobis distance absorbs the covariance.
        self.zscore = RobustZScoreDetector(one_sided=True).fit(training_features)
        self.mahalanobis = MahalanobisDetector().fit(training_features)

    def scores(self, rows: pd.DataFrame) -> dict[str, np.ndarray]:
        """
        Score feature rows with every detector.

        Parameters
        ----------
        rows : pd.DataFrame
            Feature rows carrying at least the columns in FEATURE_COLUMNS.

        Returns
        -------
        dict[str, np.ndarray]
            One score array per detector name; higher means more anomalous.
        """
        x = rows[FEATURE_COLUMNS].to_numpy(dtype=float)
        scaled = self.scaler.transform(x)
        return {
            "isolation_forest": -self.forest.score_samples(scaled),
            "robust_zscore": self.zscore.score(x),
            "mahalanobis": self.mahalanobis.score(x),
            "extended_forest": self.extended.score(scaled),
        }

    def model_sizes(self, thresholds: dict[str, float]) -> dict[str, int]:
        """Return the serialized size of each model, in bytes."""
        return {
            "isolation_forest": isolation_forest_bytes(
                self.scaler, self.forest, thresholds["isolation_forest"]
            ),
            "robust_zscore": json_bytes(
                self.zscore.to_dict(FEATURE_COLUMNS, thresholds["robust_zscore"])
            ),
            "mahalanobis": json_bytes(
                self.mahalanobis.to_dict(FEATURE_COLUMNS, thresholds["mahalanobis"])
            ),
            "extended_forest": json_bytes(
                self.extended.to_dict(
                    FEATURE_COLUMNS,
                    self.scaler.mean_,
                    self.scaler.scale_,
                    thresholds["extended_forest"],
                )
            ),
        }


def blind_spot_probe(
    suite: DetectorSuite, thresholds: dict[str, float], quantile: float = 0.975
) -> pd.DataFrame:
    """
    Score points that are ordinary per feature but absent from the joint data.

    The two most strongly correlated features are found, then a probe is built
    from the median window with one of them pushed high and the other pushed
    low. Every coordinate of that probe is inside the benign range, so a
    detector that looks at features one at a time sees nothing unusual. The
    combination, however, never occurs in training, which is exactly the "ghost
    region" an axis-aligned isolation tree cannot fence off.

    Parameters
    ----------
    suite : DetectorSuite
        The fitted detectors.
    thresholds : dict[str, float]
        Each detector's alert threshold, for the flagged/not-flagged verdict.
    quantile : float
        How far out along each of the two features to push the probe.

    Returns
    -------
    pd.DataFrame
        One row per detector with its score on each probe, its threshold, and
        whether the probe was flagged.
    """
    x = suite.training_features
    correlation = np.corrcoef(x, rowvar=False)
    np.fill_diagonal(correlation, 0.0)
    first, second = np.unravel_index(np.argmax(correlation), correlation.shape)

    high = np.quantile(x, quantile, axis=0)
    low = np.quantile(x, 1.0 - quantile, axis=0)
    median = np.median(x, axis=0)

    probe_a = median.copy()
    probe_a[first] = high[first]
    probe_a[second] = low[second]

    probe_b = median.copy()
    probe_b[first] = low[first]
    probe_b[second] = high[second]

    # Establish that the region really is unobserved, so a high score is
    # correct behavior rather than a false positive.
    band_high = np.quantile(x, 0.90, axis=0)
    band_low = np.quantile(x, 0.10, axis=0)
    occupancy = int(
        ((x[:, first] >= band_high[first]) & (x[:, second] <= band_low[second])).sum()
    )

    print(
        f"\nMost correlated feature pair: {FEATURE_COLUMNS[first]} and "
        f"{FEATURE_COLUMNS[second]} (r = {correlation[first, second]:.3f})"
    )
    print(
        f"Training windows with {FEATURE_COLUMNS[first]} in its top decile and "
        f"{FEATURE_COLUMNS[second]} in its bottom decile: {occupancy} "
        f"of {len(x)}"
    )

    probes = pd.DataFrame([probe_a, probe_b], columns=FEATURE_COLUMNS)
    scores = suite.scores(probes)

    records = []
    for name, values in scores.items():
        records.append(
            {
                "detector": name,
                "threshold": round(thresholds[name], 4),
                "probe_a": round(float(values[0]), 4),
                "probe_b": round(float(values[1]), 4),
                "flags_a": bool(values[0] >= thresholds[name]),
                "flags_b": bool(values[1] >= thresholds[name]),
            }
        )

    return pd.DataFrame(records)


def explain_worst_window(
    suite: DetectorSuite, attack_rows: pd.DataFrame
) -> tuple[str, float]:
    """Return the feature and z-score that most incriminate the worst window."""
    x = attack_rows[FEATURE_COLUMNS].to_numpy(dtype=float)
    z = suite.zscore.per_feature_z(x)
    row = int(z.max(axis=1).argmax())
    column = int(z[row].argmax())
    return FEATURE_COLUMNS[column], float(z[row, column])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--minutes", type=float, default=90.0, help="baseline length")
    parser.add_argument("--trees", type=int, default=200)
    parser.add_argument(
        "--max-fpr",
        type=float,
        default=0.005,
        help="shared target false-positive rate (default 0.5%%)",
    )
    args = parser.parse_args()

    print("Fitting four one-class detectors on one benign baseline ...")
    train_rows = build_labeled_features(
        generate_baseline_event_log(seed=1234, duration_minutes=args.minutes)
    )
    x_train = train_rows[FEATURE_COLUMNS].to_numpy(dtype=float)
    suite = DetectorSuite(x_train, trees=args.trees)
    print(f"  {len(x_train)} benign training windows, {args.trees} trees per forest")

    # Every detector is calibrated by the same rule on the same data, which is
    # the only way the comparison is fair.
    train_scores = suite.scores(train_rows)
    thresholds = {
        name: threshold_at_fpr(values, args.max_fpr)
        for name, values in train_scores.items()
    }
    sizes = suite.model_sizes(thresholds)

    # A second benign session the detectors never saw, so the false-positive
    # column is a prediction rather than a restatement of the calibration.
    benign_rows = build_labeled_features(
        generate_baseline_event_log(seed=555, duration_minutes=args.minutes)
    )

    for pace in TEST_PACES:
        attack_rows = build_labeled_features(generate_paced_attack(pace, seed=5))
        test_rows = pd.concat([benign_rows, attack_rows], ignore_index=True)
        test_scores = suite.scores(test_rows)

        print(f"\n{'=' * 104}")
        print(f"ATTACK PACE: {pace:g} files/minute")
        print(f"{'=' * 104}")

        reports = [
            evaluate_detector(
                name,
                test_scores[name],
                test_rows,
                thresholds[name],
                model_bytes=sizes[name],
            )
            for name in train_scores
        ]
        print(format_report_table(reports))

        print("\nBenign processes that tripped each detector:")
        for report in reports:
            names = report.flagged_benign_processes or ["none"]
            print(f"  {report.name:<22} {', '.join(names)}")

    print(f"\n{'=' * 104}")
    print("AXIS-ALIGNED BLIND SPOT PROBE")
    print(f"{'=' * 104}")
    print(blind_spot_probe(suite, thresholds).to_string(index=False))

    attack_rows = build_labeled_features(generate_paced_attack(120.0, seed=5))
    feature, z = explain_worst_window(suite, attack_rows)
    print(
        f"\nExplainability: the robust z-score attributes the attacker's worst "
        f"window\nto {feature}, at {z:.1f} robust sigmas above the benign median."
    )


if __name__ == "__main__":
    main()
