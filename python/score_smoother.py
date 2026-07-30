"""score_smoother.py

Temporal aggregation for the anomaly score stream: the layer the current
detector does not have.

The problem
-----------
The daemon scores every 10-second window independently. It keeps a rolling
window of *events*, but it keeps no memory at all of previous *scores*: each
window is judged as though it were the only thing that ever happened. An
attacker who rate-limits their encryption so that no single window crosses the
threshold is therefore invisible, no matter how long they keep it up. That is a
property of the model class, not of its tuning - no choice of threshold, tree
count, or subsample size can recover information the model never receives.

The fix
-------
Wrap the existing score in two classical sequential-change detectors, both of
which are a handful of arithmetic operations per event and need no model:

  1. `EwmaSmoother` - an exponentially weighted moving average. It answers "has
     this process been mildly unusual for a while?" by letting each score decay
     into the next. One multiply-add of state per event.

  2. `CusumDetector` - a one-sided cumulative sum. It accumulates how far the
     score sits above a benign reference level, minus a slack term, and floors
     the total at zero:

         S_i = max(0, S_{i-1} + (x_i - reference - slack))

     A brief benign burst adds a little and then decays back to the floor. A
     sustained mild elevation accumulates without bound, so the alarm fires on
     *persistence* rather than on magnitude. This is the classical CUSUM chart
     from statistical process control, and it is the standard answer to
     "detect a small persistent shift in a noisy stream".

Both are per process, exactly like the feature window, so a flagged process can
still be named and paused.

Calibration follows the rule the project already uses for the forest: every
threshold is a quantile of what the detector produces on *benign* data. See
`demo_temporal_aggregation.py` for the experiment that measures how much this
layer actually buys, at which attack paces, and what it costs in false
positives.

Porting note for the C++ daemon: `TemporalDetector` holds four doubles of state
per process. In `main.cpp` it would live beside the `FeatureWindow` in the
per-pid map, updated with the score that is already being computed after every
event.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


class EwmaSmoother:
    """Exponentially weighted moving average of a score stream.

    The update is

        s_i = alpha * x_i + (1 - alpha) * s_{i-1}

    `alpha` sets the memory: 1.0 is no smoothing at all, and small values
    average over roughly `1 / alpha` recent observations. The default of 0.15
    corresponds to a memory of about seven events, long enough to survive a
    single quiet window without forgetting a sustained trend.
    """

    def __init__(self, alpha: float = 0.15) -> None:
        if not 0.0 < alpha <= 1.0:
            raise ValueError("alpha must be in (0, 1]")
        self.alpha = alpha
        self.value: float | None = None

    def update(self, score: float) -> float:
        """Fold one score into the average and return the new value."""
        if self.value is None:
            self.value = float(score)
        else:
            self.value = self.alpha * float(score) + (1.0 - self.alpha) * self.value
        return self.value


class CusumDetector:
    """
    One-sided cumulative sum of a score stream.

    Parameters
    ----------
    reference : float
        The score level considered normal, normally the mean benign score.
    slack : float
        Dead band subtracted from every observation. Nothing accumulates until
        a score exceeds `reference + slack`, which is what stops ordinary
        benign noise from drifting the statistic upward. Conventionally set to
        half the shift one wants to detect.
    """

    def __init__(self, reference: float, slack: float) -> None:
        self.reference = float(reference)
        self.slack = float(slack)
        self.value = 0.0

    def update(self, score: float) -> float:
        """Accumulate one score and return the new CUSUM statistic."""
        self.value = max(0.0, self.value + (float(score) - self.reference - self.slack))
        return self.value


@dataclass
class TemporalConfig:
    """Thresholds for the three alarm rules, all derived from benign data."""

    instant_threshold: float
    ewma_alpha: float
    ewma_threshold: float
    cusum_reference: float
    cusum_slack: float
    cusum_limit: float

    def describe(self) -> str:
        """Return a short human-readable summary of the calibration."""
        return (
            f"instant >= {self.instant_threshold:.4f} | "
            f"ewma(alpha={self.ewma_alpha:.2f}) >= {self.ewma_threshold:.4f} | "
            f"cusum(ref={self.cusum_reference:.4f}, slack={self.cusum_slack:.4f}) "
            f">= {self.cusum_limit:.3f}"
        )


@dataclass
class TemporalState:
    """What the three rules currently say about one process."""

    score: float
    ewma: float
    cusum: float
    instant_alarm: bool
    ewma_alarm: bool
    cusum_alarm: bool

    @property
    def any_alarm(self) -> bool:
        return self.instant_alarm or self.ewma_alarm or self.cusum_alarm


class TemporalDetector:
    """Per-process wrapper that runs all three alarm rules side by side.

    Keeping the instantaneous rule alongside the temporal ones matters: the
    temporal layer is an addition, not a replacement. A smash-and-grab attack
    is caught fastest by the instantaneous threshold, because a single window is
    already extreme, and waiting for an average to build would cost files.
    """

    def __init__(self, config: TemporalConfig) -> None:
        self.config = config
        self.ewma = EwmaSmoother(config.ewma_alpha)
        self.cusum = CusumDetector(config.cusum_reference, config.cusum_slack)

    def update(self, score: float) -> TemporalState:
        """Fold one anomaly score in and report which rules are alarming."""
        ewma_value = self.ewma.update(score)
        cusum_value = self.cusum.update(score)
        return TemporalState(
            score=float(score),
            ewma=ewma_value,
            cusum=cusum_value,
            instant_alarm=score >= self.config.instant_threshold,
            ewma_alarm=ewma_value >= self.config.ewma_threshold,
            cusum_alarm=cusum_value >= self.config.cusum_limit,
        )


def run_stream(config: TemporalConfig, scores: np.ndarray) -> dict[str, np.ndarray]:
    """
    Replay one process's score stream and return every intermediate series.

    Parameters
    ----------
    config : TemporalConfig
        Calibrated thresholds.
    scores : np.ndarray
        The anomaly scores for one process, in time order.

    Returns
    -------
    dict[str, np.ndarray]
        Arrays "score", "ewma", "cusum" and the three boolean alarm series,
        all the same length as `scores`.
    """
    detector = TemporalDetector(config)
    states = [detector.update(float(s)) for s in np.asarray(scores, dtype=float)]
    return {
        "score": np.array([s.score for s in states]),
        "ewma": np.array([s.ewma for s in states]),
        "cusum": np.array([s.cusum for s in states]),
        "instant_alarm": np.array([s.instant_alarm for s in states]),
        "ewma_alarm": np.array([s.ewma_alarm for s in states]),
        "cusum_alarm": np.array([s.cusum_alarm for s in states]),
    }


def calibrate(
    benign_streams: list[np.ndarray],
    max_fpr: float = 0.005,
    ewma_alpha: float = 0.15,
    slack_sigmas: float = 0.5,
    limit_safety_factor: float = 1.05,
) -> TemporalConfig:
    """
    Derive all three thresholds from benign score streams.

    The instantaneous and EWMA thresholds are quantiles, the same rule
    `train_isolation_forest.py` uses. The CUSUM limit cannot be a quantile of
    per-observation values, because the statistic is serially dependent by
    design: what matters is the largest excursion any benign process ever
    reaches. So the limit is set just above the worst benign excursion
    observed, which means zero alarms on the calibration data by construction.

    Parameters
    ----------
    benign_streams : list[np.ndarray]
        One array of scores per benign process, in time order. Per-process
        streams are required rather than one pooled array, because the CUSUM
        state is per process and pooling would concatenate unrelated histories.
    max_fpr : float
        Target false-positive rate for the two quantile-based rules.
    ewma_alpha : float
        Smoothing factor handed to `EwmaSmoother`.
    slack_sigmas : float
        CUSUM dead band, in benign standard deviations.
    limit_safety_factor : float
        Multiplier applied to the worst benign CUSUM excursion. Above 1.0 it
        buys margin against benign behavior slightly worse than what was
        recorded, at the cost of detection latency.

    Returns
    -------
    TemporalConfig
        Thresholds ready to hand to `TemporalDetector`.
    """
    streams = [np.asarray(s, dtype=float) for s in benign_streams if len(s)]
    if not streams:
        raise ValueError("at least one non-empty benign stream is required")

    pooled = np.concatenate(streams)
    reference = float(pooled.mean())
    slack = float(slack_sigmas * pooled.std())
    instant_threshold = float(np.quantile(pooled, 1.0 - max_fpr))

    # Replay every benign stream to see what the two temporal statistics
    # actually reach on normal activity.
    ewma_values: list[np.ndarray] = []
    worst_cusum = 0.0
    for stream in streams:
        smoother = EwmaSmoother(ewma_alpha)
        cusum = CusumDetector(reference, slack)
        ewma_values.append(np.array([smoother.update(float(s)) for s in stream]))
        for value in stream:
            worst_cusum = max(worst_cusum, cusum.update(float(value)))

    ewma_threshold = float(np.quantile(np.concatenate(ewma_values), 1.0 - max_fpr))

    return TemporalConfig(
        instant_threshold=instant_threshold,
        ewma_alpha=ewma_alpha,
        ewma_threshold=ewma_threshold,
        cusum_reference=reference,
        cusum_slack=slack,
        cusum_limit=float(worst_cusum * limit_safety_factor),
    )
