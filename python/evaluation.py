"""evaluation.py

Shared evaluation machinery for comparing detector designs.

None of the existing scripts measure detection quality. `verify_parity.py`
proves the C++ and Python scoring agree, and `train_isolation_forest.py` reports
the training-score distribution, but nothing answers the question a reviewer
will ask first: *how good is this detector, and compared to what?*

This module supplies the three pieces every such comparison needs:

  1. Labeled feature rows. `features.build_feature_rows` deliberately returns
     only the six feature columns, so the process and label information needed
     for scoring is lost. `build_labeled_features` calls it per process and
     reattaches the identity columns, which is exact because the feature window
     is per-process by construction.
  2. A common threshold rule. Every detector is calibrated the same way the
     Isolation Forest already is: the threshold is the (1 - max_fpr) quantile of
     the scores it assigns to *training* benign data. Comparing detectors at a
     shared target false-positive rate is the only way the comparison is fair.
  3. Operational metrics. Detection rate and ROC-AUC are not enough for a
     ransomware detector. What matters is how many files were already encrypted
     before the first alert fired, so `evaluate_detector` reports that too.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from features import FEATURE_COLUMNS, build_feature_rows
from sklearn.metrics import average_precision_score, roc_auc_score

# Identity columns carried alongside the six features so that alerts can be
# attributed to a process and located in time.
IDENTITY_COLUMNS: list[str] = [
    "timestamp_seconds",
    "process_id",
    "process_name",
    "operation",
    "path",
    "label",
]


def build_labeled_features(
    events: pd.DataFrame,
    attacker_processes: tuple[str, ...] = ("cryptor",),
    window_seconds: float = 10.0,
) -> pd.DataFrame:
    """
    Build feature rows that keep their process, timestamp, and label.

    Parameters
    ----------
    events : pd.DataFrame
        Raw events with the columns in `features.EVENT_COLUMNS`.
    attacker_processes : tuple[str, ...]
        Process names to label "ransomware". Everything else is "normal".
    window_seconds : float
        Rolling window length, matching the daemon's `--window`.

    Returns
    -------
    pd.DataFrame
        One row per event with FEATURE_COLUMNS plus IDENTITY_COLUMNS.
    """
    frames: list[pd.DataFrame] = []

    for process_id, group in events.groupby("process_id", sort=True):
        # Sort exactly the way build_feature_rows does, so that row i of the
        # returned features corresponds to row i of this group.
        group = group.sort_values("timestamp_seconds").reset_index(drop=True)
        rows = build_feature_rows(group, window_seconds=window_seconds)
        rows["timestamp_seconds"] = group["timestamp_seconds"].to_numpy()
        rows["process_id"] = int(process_id)
        rows["process_name"] = group["process_name"].to_numpy()
        rows["operation"] = group["operation"].to_numpy()
        rows["path"] = group["path"].to_numpy()
        rows["label"] = np.where(
            group["process_name"].isin(attacker_processes), "ransomware", "normal"
        )
        frames.append(rows)

    combined = pd.concat(frames, ignore_index=True)
    return combined[FEATURE_COLUMNS + IDENTITY_COLUMNS]


def threshold_at_fpr(benign_scores: np.ndarray, max_fpr: float = 0.005) -> float:
    """Return the score threshold that flags at most `max_fpr` of benign rows.

    This is the same rule `train_isolation_forest.py` uses for the Isolation
    Forest, applied uniformly to every detector so the comparison is fair.
    """
    if not 0.0 < max_fpr < 1.0:
        raise ValueError("max_fpr must be in (0, 1)")
    return float(np.quantile(np.asarray(benign_scores, dtype=float), 1.0 - max_fpr))


@dataclass
class DetectorReport:
    """One row of the comparison table."""

    name: str
    threshold: float
    benign_windows: int
    benign_flagged: int
    attack_windows: int
    attack_flagged: int
    roc_auc: float
    average_precision: float
    files_lost: int | None = None
    detection_seconds: float | None = None
    model_bytes: int | None = None
    flagged_benign_processes: list[str] = field(default_factory=list)

    @property
    def false_positive_rate(self) -> float:
        return self.benign_flagged / max(self.benign_windows, 1)

    @property
    def detection_rate(self) -> float:
        return self.attack_flagged / max(self.attack_windows, 1)


def count_files_encrypted_before(rows: pd.DataFrame, alert_time: float | None) -> int:
    """Count attacker `write` events that completed before the first alert.

    This is the metric that actually matters to a user: how many files were
    already encrypted by the time the detector spoke up. `None` means the
    detector never fired, so every file was lost.
    """
    writes = rows[rows["operation"] == "write"]
    if alert_time is None:
        return int(len(writes))
    return int((writes["timestamp_seconds"] < alert_time).sum())


def evaluate_detector(
    name: str,
    scores: np.ndarray,
    rows: pd.DataFrame,
    threshold: float,
    model_bytes: int | None = None,
) -> DetectorReport:
    """
    Score a detector against labeled feature rows at a fixed threshold.

    Parameters
    ----------
    name : str
        Label for the comparison table.
    scores : np.ndarray
        One anomaly score per row of `rows`; higher means more anomalous.
    rows : pd.DataFrame
        Labeled feature rows from `build_labeled_features`.
    threshold : float
        Alert threshold, normally from `threshold_at_fpr` on training data.
    model_bytes : int | None
        Serialized model size, for the deployment-cost column.

    Returns
    -------
    DetectorReport
        Detection rate, false-positive rate, ranking metrics, and how many
        files were encrypted before the first alert.
    """
    scores = np.asarray(scores, dtype=float)
    is_attack = (rows["label"] == "ransomware").to_numpy()
    flagged = scores >= threshold

    attack_rows = rows[is_attack]
    attack_flagged_times = rows.loc[is_attack & flagged, "timestamp_seconds"]
    alert_time = (
        float(attack_flagged_times.min()) if len(attack_flagged_times) else None
    )

    first_attack_event = (
        float(attack_rows["timestamp_seconds"].min()) if len(attack_rows) else None
    )
    detection_seconds = (
        alert_time - first_attack_event
        if alert_time is not None and first_attack_event is not None
        else None
    )

    benign_flagged_names = sorted(
        set(rows.loc[~is_attack & flagged, "process_name"].tolist())
    )

    # ROC-AUC and average precision need both classes present.
    if is_attack.any() and (~is_attack).any():
        auc = float(roc_auc_score(is_attack, scores))
        ap = float(average_precision_score(is_attack, scores))
    else:
        auc = float("nan")
        ap = float("nan")

    return DetectorReport(
        name=name,
        threshold=threshold,
        benign_windows=int((~is_attack).sum()),
        benign_flagged=int((~is_attack & flagged).sum()),
        attack_windows=int(is_attack.sum()),
        attack_flagged=int((is_attack & flagged).sum()),
        roc_auc=auc,
        average_precision=ap,
        files_lost=count_files_encrypted_before(attack_rows, alert_time),
        detection_seconds=detection_seconds,
        model_bytes=model_bytes,
        flagged_benign_processes=benign_flagged_names,
    )


def format_report_table(reports: list[DetectorReport]) -> str:
    """Render a list of DetectorReport rows as a fixed-width table."""
    header = (
        f"{'detector':<22} {'thresh':>8} {'benign FPR':>11} {'detect':>8} "
        f"{'AUC':>7} {'AP':>7} {'lost':>6} {'latency':>9} {'model KB':>9}"
    )
    lines = [header, "-" * len(header)]

    for r in reports:
        latency = (
            "never" if r.detection_seconds is None else f"{r.detection_seconds:.1f}s"
        )
        lost = "all" if r.detection_seconds is None else str(r.files_lost)
        size = "-" if r.model_bytes is None else f"{r.model_bytes / 1024.0:.1f}"
        lines.append(
            f"{r.name:<22} {r.threshold:>8.4f} "
            f"{r.false_positive_rate:>10.2%} {r.detection_rate:>7.1%} "
            f"{r.roc_auc:>7.4f} {r.average_precision:>7.4f} {lost:>6} "
            f"{latency:>9} {size:>9}"
        )

    return "\n".join(lines)
