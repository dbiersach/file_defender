"""baseline_detectors.py

Two simple one-class detectors that serve as baselines for the Isolation
Forest.

Why bother? Because the project currently *asserts* that an Isolation Forest is
the right model rather than *demonstrating* it. A detector is only as good as
the simplest thing it beats, and in six dimensions the simplest things are
genuinely competitive:

  1. `RobustZScoreDetector` - per-feature median and MAD, score is the largest
     number of robust standard deviations any single feature is above its
     benign median. Six medians and six scales, and the alert names the feature
     that tripped it.
  2. `MahalanobisDetector` - a single multivariate Gaussian fitted to the
     benign cloud, score is the Mahalanobis distance from its center. Unlike the
     z-score rule it accounts for *correlations* between features, which is the
     specific thing an axis-aligned Isolation Forest cannot see.

Both are one-class: they are fitted on benign data only, exactly like the
Isolation Forest, so the project's central research claim is preserved.

Both also address the Isolation Forest's direction-blindness. The forest's
random cuts make its score symmetric in every feature, so an unusually *quiet*
process is as anomalous as an unusually loud one. Here, `one_sided=True` (the
default) encodes what we actually know: for all six features, high is
suspicious and low is not.

Neither detector needs a StandardScaler. The z-score rule divides by a
per-feature scale by construction, and the Mahalanobis distance absorbs the
covariance, which includes the variances.

See `compare_detectors.py` for the evaluation harness that puts these up
against the forest.
"""

from __future__ import annotations

import numpy as np
from sklearn.covariance import LedoitWolf

# Guard against dividing by a scale of zero, matching the convention already
# used for the exported scaler in train_isolation_forest.py.
_MIN_SCALE = 1.0e-9


class RobustZScoreDetector:
    """Flag a window when any single feature is far above its benign median.

    The score is

        s(x) = max_j  (x_j - median_j) / (1.4826 * MAD_j)

    with the maximum taken over the six features and, when `one_sided` is True,
    negative terms clamped to zero.

    The median and the median absolute deviation (MAD) are used instead of the
    mean and standard deviation because the benign training data contains real
    bursts - a `git gc` repack, a backup sweep - and a single such burst would
    inflate a standard deviation enough to hide a genuine attack. The constant
    1.4826 rescales the MAD so that it estimates the standard deviation of a
    normal distribution, which keeps the score readable as "sigmas above
    normal".
    """

    def __init__(self, one_sided: bool = True) -> None:
        self.one_sided = one_sided
        self.median_: np.ndarray | None = None
        self.scale_: np.ndarray | None = None

    def fit(self, x: np.ndarray) -> RobustZScoreDetector:
        """Fit per-feature medians and robust scales on benign data."""
        x = np.asarray(x, dtype=float)
        self.median_ = np.median(x, axis=0)

        mad = np.median(np.abs(x - self.median_), axis=0)
        scale = 1.4826 * mad

        # A feature can have MAD = 0 when more than half the benign windows
        # share one value (rename_delete_rate is 0 in most windows). Fall back
        # to the standard deviation, then to 1.0, so the feature stays usable
        # instead of producing an infinite z-score.
        fallback = np.std(x, axis=0)
        scale = np.where(scale > _MIN_SCALE, scale, fallback)
        self.scale_ = np.maximum(scale, _MIN_SCALE)
        return self

    def per_feature_z(self, x: np.ndarray) -> np.ndarray:
        """Return the (n_samples, n_features) matrix of robust z-scores."""
        if self.median_ is None or self.scale_ is None:
            raise RuntimeError("fit() must be called before scoring")
        z = (np.asarray(x, dtype=float) - self.median_) / self.scale_
        return np.maximum(z, 0.0) if self.one_sided else np.abs(z)

    def score(self, x: np.ndarray) -> np.ndarray:
        """Anomaly score per row; higher means more anomalous."""
        return self.per_feature_z(x).max(axis=1)

    def dominant_feature(self, x: np.ndarray, feature_columns: list[str]) -> list[str]:
        """Name the feature responsible for each row's score.

        This is the explainability advantage of the baseline: an alert can say
        "writes_per_second was 9.4 sigma high" instead of "the average path
        length across 200 random trees was short".
        """
        indices = self.per_feature_z(x).argmax(axis=1)
        return [feature_columns[i] for i in indices]

    def to_dict(
        self, feature_columns: list[str], recommended_threshold: float
    ) -> dict[str, object]:
        """Serialize to a JSON-ready dict in the style of models/model.json."""
        if self.median_ is None or self.scale_ is None:
            raise RuntimeError("fit() must be called before exporting")
        return {
            "detector": "robust_zscore",
            "feature_columns": list(feature_columns),
            "one_sided": bool(self.one_sided),
            "median": self.median_.tolist(),
            "scale": self.scale_.tolist(),
            "recommended_threshold": float(recommended_threshold),
        }


class MahalanobisDetector:
    """Flag a window by its Mahalanobis distance from the benign center.

    The score is

        d(x) = sqrt( (x - mu)^T  S^-1  (x - mu) )

    where `mu` is the benign mean and `S` the benign covariance. Because the
    inverse covariance appears in the middle, the distance is measured in units
    that account for how features vary *together*: a window with a high write
    rate is unremarkable if its event rate is high too, because benign windows
    always show those two rising together, but a high write rate with a low
    event rate is far away even though neither value is individually extreme.
    That is exactly the correlation structure that axis-aligned isolation trees
    cannot represent.

    The covariance is estimated with Ledoit-Wolf shrinkage rather than the
    plain sample covariance. Shrinkage pulls the estimate toward a scaled
    identity matrix, which keeps it invertible when a feature is nearly
    constant, and is what makes this method usable on a short baseline.

    The cost of the method is its assumption: one Gaussian blob. Real benign
    activity is multi-modal (idle, editing, compiling, backing up), so a single
    center is a genuine simplification. A Gaussian mixture is the natural next
    step if the single-center version proves too coarse.
    """

    def __init__(self) -> None:
        self.mean_: np.ndarray | None = None
        self.precision_: np.ndarray | None = None

    def fit(self, x: np.ndarray) -> MahalanobisDetector:
        """Fit the benign mean and shrunk inverse covariance."""
        x = np.asarray(x, dtype=float)
        estimator = LedoitWolf().fit(x)
        self.mean_ = np.asarray(estimator.location_, dtype=float)
        self.precision_ = np.asarray(estimator.precision_, dtype=float)
        return self

    def score(self, x: np.ndarray) -> np.ndarray:
        """Mahalanobis distance per row; higher means more anomalous."""
        if self.mean_ is None or self.precision_ is None:
            raise RuntimeError("fit() must be called before scoring")
        centered = np.asarray(x, dtype=float) - self.mean_
        # einsum computes the quadratic form row by row without building an
        # n-by-n intermediate matrix.
        squared = np.einsum("ij,jk,ik->i", centered, self.precision_, centered)
        return np.sqrt(np.maximum(squared, 0.0))

    def to_dict(
        self, feature_columns: list[str], recommended_threshold: float
    ) -> dict[str, object]:
        """Serialize to a JSON-ready dict in the style of models/model.json."""
        if self.mean_ is None or self.precision_ is None:
            raise RuntimeError("fit() must be called before exporting")
        return {
            "detector": "mahalanobis",
            "feature_columns": list(feature_columns),
            "mean": self.mean_.tolist(),
            "precision": self.precision_.tolist(),
            "recommended_threshold": float(recommended_threshold),
        }
