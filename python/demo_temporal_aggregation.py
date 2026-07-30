#!/usr/bin/env python3
"""demo_temporal_aggregation.py

Measure what temporal aggregation actually buys, as a function of attack pace.

The claim being tested is the one from `docs/WHY_ISOLATION_FOREST.md`: because
the daemon scores every window independently, an attacker who rate-limits their
encryption can keep every single window below the alert threshold and never be
detected. Adding memory to the score stream should recover some of those
attackers.

A single hand-built "slow attack" scenario cannot test that claim, because
whether it is caught depends entirely on the pace that was chosen. So this
experiment sweeps the pace from a smash-and-grab down to a very patient
attacker and reports, for each of the three alarm rules, how many files were
already encrypted when the alarm first fired. Every pace is run with several
attacker seeds and the median is reported, because a single run can get lucky
with one unusually loud window.

Two calibrations are reported, because the result depends heavily on which
benign processes the false-positive budget has to cover:

  1. All benign processes. `git gc` and `restic` genuinely look like ransomware
     in this feature space, so tolerating them consumes the entire budget.
  2. Known applications excluded. What a deployment does after triaging its
     first week of alerts: the two heavy hitters get their own baseline or an
     allowlist entry, and the general threshold tightens.

Run it with:

  uv run python python/demo_temporal_aggregation.py
"""

from __future__ import annotations

import argparse

import numpy as np
import pandas as pd
from evaluation import build_labeled_features, count_files_encrypted_before
from features import FEATURE_COLUMNS
from score_smoother import TemporalConfig, calibrate, run_stream
from simulate_realistic_baseline import (
    generate_baseline_event_log,
    generate_paced_attack,
)
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Encryption paces to sweep, in files per minute. 600 is a smash-and-grab that
# finishes a home directory in seconds; 1 is an attacker willing to spend most
# of a day.
PACES: list[float] = [600.0, 300.0, 120.0, 60.0, 30.0, 12.0, 6.0, 3.0, 1.0]

# Benign processes whose behavior is indistinguishable from ransomware in this
# feature space. Reported separately rather than silently dropped.
KNOWN_APPLICATIONS: tuple[str, ...] = ("git", "restic")

RULES: tuple[str, ...] = ("instant_alarm", "ewma_alarm", "cusum_alarm")


class ScoredModel:
    """An Isolation Forest plus its scaler, scoring labeled feature frames."""

    def __init__(self, training_features: np.ndarray, trees: int = 200) -> None:
        self.scaler = StandardScaler().fit(training_features)
        self.forest = IsolationForest(
            n_estimators=trees,
            max_samples=min(256, len(training_features)),
            contamination="auto",
            random_state=42,
        ).fit(self.scaler.transform(training_features))

    def score(self, rows: pd.DataFrame) -> np.ndarray:
        """Return one anomaly score per row; higher means more anomalous."""
        x = rows[FEATURE_COLUMNS].to_numpy(dtype=float)
        return -self.forest.score_samples(self.scaler.transform(x))


def calibrate_from_baseline(
    rows: pd.DataFrame,
    scores: np.ndarray,
    exclude: tuple[str, ...] = (),
    max_fpr: float = 0.005,
) -> TemporalConfig:
    """
    Calibrate the three alarm rules from a benign baseline.

    Parameters
    ----------
    rows : pd.DataFrame
        Labeled benign feature rows from `build_labeled_features`.
    scores : np.ndarray
        The model's anomaly score for each row.
    exclude : tuple[str, ...]
        Process names to leave out of the calibration, standing in for
        applications a deployment has already triaged and baselined separately.
    max_fpr : float
        Target false-positive rate for the quantile-based rules.

    Returns
    -------
    TemporalConfig
        Thresholds for the instantaneous, EWMA, and CUSUM rules.
    """
    frame = rows.assign(score=scores)
    if exclude:
        frame = frame[~frame["process_name"].isin(exclude)]

    streams = [
        group["score"].to_numpy() for _, group in frame.groupby("process_id", sort=True)
    ]
    return calibrate(streams, max_fpr=max_fpr)


def benign_alarm_counts(
    config: TemporalConfig,
    rows: pd.DataFrame,
    scores: np.ndarray,
) -> pd.DataFrame:
    """
    Count how often each rule fires on each benign process, out of sample.

    Parameters
    ----------
    config : TemporalConfig
        Calibrated thresholds.
    rows : pd.DataFrame
        Labeled benign feature rows from a baseline the model never trained on.
    scores : np.ndarray
        The model's anomaly score for each row.

    Returns
    -------
    pd.DataFrame
        One row per benign process with the window count and the number of
        windows each rule flagged.
    """
    frame = rows.assign(score=scores)
    records: list[dict[str, object]] = []

    for _, group in frame.groupby("process_id", sort=True):
        series = run_stream(config, group["score"].to_numpy())
        records.append(
            {
                "process": group["process_name"].iloc[0],
                "windows": len(group),
                "instant": int(series["instant_alarm"].sum()),
                "ewma": int(series["ewma_alarm"].sum()),
                "cusum": int(series["cusum_alarm"].sum()),
                "peak_cusum": float(series["cusum"].max()),
            }
        )

    return pd.DataFrame(records)


def files_lost_by_rule(
    config: TemporalConfig, attack_rows: pd.DataFrame, scores: np.ndarray
) -> dict[str, int | None]:
    """
    Report how many files each rule let the attacker encrypt before alarming.

    Parameters
    ----------
    config : TemporalConfig
        Calibrated thresholds.
    attack_rows : pd.DataFrame
        Labeled feature rows for the attacker process only, in time order.
    scores : np.ndarray
        The model's anomaly score for each attacker row.

    Returns
    -------
    dict[str, int | None]
        Files encrypted before the first alarm, keyed by rule name. `None`
        means the rule never fired, so every file was lost.
    """
    series = run_stream(config, scores)
    timestamps = attack_rows["timestamp_seconds"].to_numpy()
    result: dict[str, int | None] = {}

    for rule in RULES:
        fired = np.flatnonzero(series[rule])
        if len(fired) == 0:
            result[rule] = None
            continue
        alert_time = float(timestamps[fired[0]])
        result[rule] = count_files_encrypted_before(attack_rows, alert_time)

    return result


def sweep_paces(
    model: ScoredModel,
    config: TemporalConfig,
    paces: list[float],
    seeds: list[int],
) -> pd.DataFrame:
    """
    Run every pace with every seed and summarize the median outcome.

    Parameters
    ----------
    model : ScoredModel
        The trained forest used to score attacker windows.
    config : TemporalConfig
        Calibrated thresholds for the three rules.
    paces : list[float]
        Encryption paces to test, in files per minute.
    seeds : list[int]
        Attacker seeds; the median across seeds is reported per pace.

    Returns
    -------
    pd.DataFrame
        One row per pace with the median files lost and the miss count for
        each rule.
    """
    records: list[dict[str, object]] = []

    for pace in paces:
        losses: dict[str, list[int]] = {rule: [] for rule in RULES}
        misses: dict[str, int] = dict.fromkeys(RULES, 0)
        total_files = 0

        for seed in seeds:
            events = generate_paced_attack(pace, seed=seed)
            rows = build_labeled_features(events)
            scores = model.score(rows)
            total_files = int((rows["operation"] == "write").sum())

            for rule, lost in files_lost_by_rule(config, rows, scores).items():
                if lost is None:
                    misses[rule] += 1
                    losses[rule].append(total_files)
                else:
                    losses[rule].append(lost)

        record: dict[str, object] = {
            "files_per_minute": pace,
            "total_files": total_files,
            "attack_seconds": round(60.0 * total_files / pace, 1),
        }
        for rule in RULES:
            short = rule.replace("_alarm", "")
            record[f"{short}_lost"] = int(np.median(losses[rule]))
            record[f"{short}_missed"] = misses[rule]
        records.append(record)

    return pd.DataFrame(records)


def _format_duration(seconds: float) -> str:
    """Render an attack duration in whichever unit reads more naturally."""
    if seconds < 90.0:
        return f"{seconds:.0f} s"
    return f"{seconds / 60.0:.0f} min"


def format_sweep(sweep: pd.DataFrame, seeds: int) -> str:
    """Render the pace sweep as a fixed-width table."""
    header = (
        f"{'files/min':>10} {'attack len':>11} "
        f"{'instant':>16} {'ewma':>16} {'cusum':>16}"
    )
    lines = [
        header,
        "-" * len(header),
        f"{'':>10} {'':>11} " + " ".join(f"{'lost (missed)':>16}" for _ in RULES),
    ]

    for _, row in sweep.iterrows():
        cells = []
        for rule in RULES:
            short = rule.replace("_alarm", "")
            lost = int(row[f"{short}_lost"])
            missed = int(row[f"{short}_missed"])
            flag = f" ({missed}/{seeds})" if missed else ""
            cells.append(f"{f'{lost}/{int(row["total_files"])}{flag}':>16}")
        lines.append(
            f"{row['files_per_minute']:>10.0f} "
            f"{_format_duration(float(row['attack_seconds'])):>11} " + " ".join(cells)
        )

    return "\n".join(lines)


def report_calibration(
    label: str,
    model: ScoredModel,
    train_rows: pd.DataFrame,
    train_scores: np.ndarray,
    test_rows: pd.DataFrame,
    test_scores: np.ndarray,
    exclude: tuple[str, ...],
    paces: list[float],
    seeds: list[int],
) -> None:
    """Calibrate one configuration, then print its benign and sweep results."""
    print(f"\n{'=' * 78}\n{label}\n{'=' * 78}")
    config = calibrate_from_baseline(train_rows, train_scores, exclude=exclude)
    print(f"calibration: {config.describe()}")
    if exclude:
        print(f"excluded from calibration: {', '.join(exclude)}")

    print("\nBenign false alarms on a baseline the model never saw:")
    benign = benign_alarm_counts(config, test_rows, test_scores)
    if exclude:
        benign = benign[~benign["process"].isin(exclude)]
    print(benign.to_string(index=False))

    sweep = sweep_paces(model, config, paces, seeds)
    print(
        "\nFiles encrypted before the first alarm (median of "
        f"{len(seeds)} attacker seeds, lower is better):"
    )
    print(format_sweep(sweep, len(seeds)))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--minutes", type=float, default=90.0, help="baseline length")
    parser.add_argument("--seeds", type=int, default=5, help="attacker seeds per pace")
    parser.add_argument("--trees", type=int, default=200)
    args = parser.parse_args()

    print("Training the Isolation Forest on a benign baseline ...")
    train_rows = build_labeled_features(
        generate_baseline_event_log(seed=1234, duration_minutes=args.minutes)
    )
    model = ScoredModel(
        train_rows[FEATURE_COLUMNS].to_numpy(dtype=float), trees=args.trees
    )
    train_scores = model.score(train_rows)
    print(f"  {len(train_rows)} benign windows, {args.trees} trees")

    # A second, independent benign session, so the false-alarm numbers are
    # out-of-sample rather than a restatement of the calibration.
    test_rows = build_labeled_features(
        generate_baseline_event_log(seed=555, duration_minutes=args.minutes)
    )
    test_scores = model.score(test_rows)
    print(f"  {len(test_rows)} held-out benign windows")

    seeds = list(range(5, 5 + args.seeds))

    report_calibration(
        "CALIBRATION 1: every benign process included",
        model,
        train_rows,
        train_scores,
        test_rows,
        test_scores,
        exclude=(),
        paces=PACES,
        seeds=seeds,
    )
    report_calibration(
        "CALIBRATION 2: git and restic treated as triaged known applications",
        model,
        train_rows,
        train_scores,
        test_rows,
        test_scores,
        exclude=KNOWN_APPLICATIONS,
        paces=PACES,
        seeds=seeds,
    )

    print(
        "\nRead the tables by column, not by row. A rule earns its keep where it\n"
        "loses fewer files than 'instant' at the same pace. See\n"
        "docs/POTENTIAL_IMPROVEMENTS.md for the interpretation."
    )


if __name__ == "__main__":
    main()
