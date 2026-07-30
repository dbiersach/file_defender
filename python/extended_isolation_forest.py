#!/usr/bin/env python3
"""extended_isolation_forest.py

An Extended Isolation Forest (Hariri, Kind and Brunner, 2018), written from
scratch in NumPy, as a drop-in alternative to scikit-learn's IsolationForest.

The problem it fixes
--------------------
A standard isolation tree splits on one feature at a time: "is
`writes_per_second` above 3.1?". Every cut is therefore perpendicular to an
axis, and the region assigned to each leaf is an axis-aligned box. When the
benign data is *correlated* - and these six features are strongly correlated,
because a process with a high event rate also has a high write rate - the union
of those boxes covers rectangular regions that contain no training data at all.
A point landing in such a region takes a long path down the tree and receives a
*normal* score even though nothing like it was ever observed. These are the
well-known "ghost" or blind-spot regions of the standard algorithm.

The fix is to let each cut be an arbitrary hyperplane rather than an
axis-aligned one. At every node the tree draws a random unit normal vector `w`
and a random intercept point `p` inside the node's data range, then splits on

    w . x + b <= 0,      where b = -(w . p)

Nothing else about the algorithm changes: the anomaly score is still

    s(x) = 2 ^ ( -E[h(x)] / c(psi) )

where `E[h(x)]` is the mean path length over the forest and `c(psi)` is the
expected path length of an unsuccessful search in a random binary tree of
`psi` points.

Why this stays deployable
-------------------------
The exported model is the same shape as the existing `models/model.json`. Each
node stores a vector and a scalar instead of a feature index and a threshold,
so the C++ port replaces one comparison

    scaled[feature[node]] <= threshold[node]

with one dot product

    dot(normal[node], scaled) + bias[node] <= 0

That is six multiply-adds instead of one array lookup, on a tree walk that is
already memory-bound. No new dependency and no ML runtime, so the design
constraint that motivated Isolation Forest in the first place is preserved.

One real difference: standardization now matters. A monotone per-feature
rescaling cannot change an axis-aligned split, which is why StandardScaler is
mathematically a no-op for the standard forest. An oblique cut mixes features,
so the scale of each feature changes which hyperplanes are reachable. Here the
scaler is load-bearing, not decorative.

Run this file directly for a self-check that also proves the JSON export scores
identically to the in-memory model, in the spirit of `verify_parity.py`:

  python3 extended_isolation_forest.py
"""

from __future__ import annotations

import argparse
import json
import math

import numpy as np
from features import FEATURE_COLUMNS, build_feature_rows
from simulate_realistic_baseline import (
    generate_baseline_event_log,
    generate_paced_attack,
)
from sklearn.preprocessing import StandardScaler

_EULER_MASCHERONI = 0.5772156649015329


def average_path_length(n: float | np.ndarray) -> float | np.ndarray:
    """
    Expected path length c(n) of an unsuccessful search in a random BST.

    This is the same normalizing function scikit-learn uses and that
    `verify_parity.py` re-implements, generalized to accept an array so that
    whole batches of leaf sizes can be corrected at once.

    Parameters
    ----------
    n : float | np.ndarray
        Number of training samples that reached a node.

    Returns
    -------
    float | np.ndarray
        The expected additional path length attributable to those samples.
    """
    n_array = np.asarray(n, dtype=float)
    result = np.zeros_like(n_array)

    two = n_array == 2.0
    many = n_array > 2.0
    result[two] = 1.0
    result[many] = (
        2.0 * (np.log(n_array[many] - 1.0) + _EULER_MASCHERONI)
        - 2.0 * (n_array[many] - 1.0) / n_array[many]
    )

    return float(result) if np.isscalar(n) or result.ndim == 0 else result


class _Tree:
    """One extended isolation tree, stored as flat arrays indexed by node id."""

    def __init__(self, n_features: int) -> None:
        self.n_features = n_features
        self.normal: list[np.ndarray] = []
        self.bias: list[float] = []
        self.children_left: list[int] = []
        self.children_right: list[int] = []
        self.n_node_samples: list[int] = []

    def add_node(self, n_samples: int) -> int:
        """Append a placeholder leaf node and return its id."""
        self.normal.append(np.zeros(self.n_features))
        self.bias.append(0.0)
        self.children_left.append(-1)
        self.children_right.append(-1)
        self.n_node_samples.append(int(n_samples))
        return len(self.children_left) - 1

    def freeze(self) -> _FrozenTree:
        """Convert the growing lists into contiguous arrays for fast scoring."""
        return _FrozenTree(
            normal=np.asarray(self.normal, dtype=float),
            bias=np.asarray(self.bias, dtype=float),
            children_left=np.asarray(self.children_left, dtype=int),
            children_right=np.asarray(self.children_right, dtype=int),
            n_node_samples=np.asarray(self.n_node_samples, dtype=float),
        )


class _FrozenTree:
    """A finished tree in array form, ready to be walked by whole batches."""

    def __init__(
        self,
        normal: np.ndarray,
        bias: np.ndarray,
        children_left: np.ndarray,
        children_right: np.ndarray,
        n_node_samples: np.ndarray,
    ) -> None:
        self.normal = normal
        self.bias = bias
        self.children_left = children_left
        self.children_right = children_right
        self.n_node_samples = n_node_samples

    def path_lengths(self, x: np.ndarray) -> np.ndarray:
        """Return the corrected path length of every row of `x`.

        All samples descend the tree together, one level per iteration, so the
        cost is proportional to the tree height rather than to the number of
        samples times the height.
        """
        node = np.zeros(len(x), dtype=int)
        depth = np.zeros(len(x), dtype=float)

        while True:
            internal = self.children_left[node] != -1
            if not internal.any():
                break
            moving = np.flatnonzero(internal)
            here = node[moving]
            # One dot product per sample against its own node's normal vector.
            projection = np.einsum("ij,ij->i", x[moving], self.normal[here])
            projection += self.bias[here]
            node[moving] = np.where(
                projection <= 0.0, self.children_left[here], self.children_right[here]
            )
            depth[moving] += 1.0

        # Samples that stop at a leaf holding several training points would have
        # needed more cuts to be isolated; c(n) estimates how many.
        return depth + average_path_length(self.n_node_samples[node])


class ExtendedIsolationForest:
    """
    Isolation Forest with oblique (hyperplane) cuts instead of axis cuts.

    Parameters
    ----------
    n_estimators : int
        Number of trees, matching the project's default of 200.
    max_samples : int
        Subsample size `psi` used to grow each tree, matching the default 256.
    extension_level : int | None
        How many features a cut may mix. `None` means fully extended
        (`n_features - 1`), which is the usual choice. Setting it to 0 makes
        every cut use a single feature, reproducing the standard algorithm, so
        this parameter interpolates between the two designs.
    random_state : int
        Seed, so results are reproducible in the way the rest of the project
        expects.
    """

    def __init__(
        self,
        n_estimators: int = 200,
        max_samples: int = 256,
        extension_level: int | None = None,
        random_state: int = 42,
    ) -> None:
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.extension_level = extension_level
        self.random_state = random_state
        self.trees_: list[_FrozenTree] = []
        self.max_samples_ = max_samples
        self.extension_level_ = 0
        self.n_features_ = 0

    def fit(self, x: np.ndarray) -> ExtendedIsolationForest:
        """Grow the forest on benign data."""
        x = np.asarray(x, dtype=float)
        n_samples, n_features = x.shape
        self.n_features_ = n_features
        self.max_samples_ = int(min(self.max_samples, n_samples))
        self.extension_level_ = (
            n_features - 1
            if self.extension_level is None
            else int(self.extension_level)
        )
        if not 0 <= self.extension_level_ <= n_features - 1:
            raise ValueError(f"extension_level must be in [0, {n_features - 1}]")

        # A tree stops at the depth where a balanced tree would have isolated
        # every one of its psi points, the same limit scikit-learn uses.
        height_limit = max(1, int(math.ceil(math.log2(max(self.max_samples_, 2)))))
        rng = np.random.default_rng(self.random_state)

        self.trees_ = []
        for _ in range(self.n_estimators):
            sample_rows = rng.choice(n_samples, size=self.max_samples_, replace=False)
            tree = _Tree(n_features)
            self._grow(
                tree, x[sample_rows], depth=0, height_limit=height_limit, rng=rng
            )
            self.trees_.append(tree.freeze())

        return self

    def _grow(
        self,
        tree: _Tree,
        x: np.ndarray,
        depth: int,
        height_limit: int,
        rng: np.random.Generator,
    ) -> int:
        """Recursively split `x` with random hyperplanes; return the node id."""
        node_id = tree.add_node(len(x))
        if depth >= height_limit or len(x) <= 1:
            return node_id

        low = x.min(axis=0)
        high = x.max(axis=0)
        if np.all(high - low <= 0.0):
            return node_id  # every point here is identical; nothing to cut

        # A random intercept can occasionally leave all points on one side. Try
        # a few times before giving up and leaving this node as a leaf.
        for _ in range(10):
            normal = self._random_normal(rng)
            if normal is None:
                continue
            point = rng.uniform(low, high)
            bias = -float(normal @ point)
            goes_left = (x @ normal + bias) <= 0.0
            if goes_left.any() and not goes_left.all():
                tree.normal[node_id] = normal
                tree.bias[node_id] = bias
                tree.children_left[node_id] = self._grow(
                    tree, x[goes_left], depth + 1, height_limit, rng
                )
                tree.children_right[node_id] = self._grow(
                    tree, x[~goes_left], depth + 1, height_limit, rng
                )
                return node_id

        return node_id

    def _random_normal(self, rng: np.random.Generator) -> np.ndarray | None:
        """Draw a random unit normal vector honoring the extension level."""
        normal = rng.normal(size=self.n_features_)

        # Zeroing coordinates restricts the cut to a subspace. With
        # extension_level = 0 exactly one coordinate survives, which is an
        # axis-aligned cut.
        zeroed = self.n_features_ - 1 - self.extension_level_
        if zeroed > 0:
            indices = rng.choice(self.n_features_, size=zeroed, replace=False)
            normal[indices] = 0.0

        length = float(np.linalg.norm(normal))
        return normal / length if length > 0.0 else None

    def path_length(self, x: np.ndarray) -> np.ndarray:
        """Mean corrected path length of each row across the whole forest."""
        if not self.trees_:
            raise RuntimeError("fit() must be called before scoring")
        x = np.asarray(x, dtype=float)
        total = np.zeros(len(x), dtype=float)
        for tree in self.trees_:
            total += tree.path_lengths(x)
        return total / len(self.trees_)

    def score(self, x: np.ndarray) -> np.ndarray:
        """Anomaly score in (0, 1); higher means more anomalous.

        Identical in form and interpretation to the score the C++ AnomalyModel
        already returns, so the daemon's threshold logic is unchanged.
        """
        normalizer = float(average_path_length(float(self.max_samples_)))
        if normalizer <= 0.0:
            return np.full(len(x), 0.5)
        return 2.0 ** (-self.path_length(x) / normalizer)

    def to_dict(
        self,
        feature_columns: list[str],
        scaler_mean: np.ndarray,
        scaler_scale: np.ndarray,
        recommended_threshold: float,
    ) -> dict[str, object]:
        """Serialize to a JSON-ready dict mirroring models/model.json.

        The only structural change from the existing format is that each node
        carries a `normal` vector and a `bias` scalar in place of `feature` and
        `threshold`.
        """
        trees = [
            {
                "normal": tree.normal.tolist(),
                "bias": tree.bias.tolist(),
                "children_left": tree.children_left.tolist(),
                "children_right": tree.children_right.tolist(),
                "n_node_samples": tree.n_node_samples.astype(int).tolist(),
            }
            for tree in self.trees_
        ]
        return {
            "model": "extended_isolation_forest",
            "feature_columns": list(feature_columns),
            "scaler_mean": np.asarray(scaler_mean, dtype=float).tolist(),
            "scaler_scale": np.maximum(
                np.asarray(scaler_scale, dtype=float), 1.0e-9
            ).tolist(),
            "max_samples": int(self.max_samples_),
            "extension_level": int(self.extension_level_),
            "recommended_threshold": float(recommended_threshold),
            "trees": trees,
        }


def score_from_dict(model: dict, x_raw: np.ndarray) -> np.ndarray:
    """Score raw feature rows straight from an exported model dict.

    This function is the reference implementation for a future C++ port, in the
    same role `verify_parity.score_from_json` plays for the standard forest. It
    deliberately reads only what the JSON contains, so if it agrees with the
    in-memory model then the export is complete.
    """
    mean = np.asarray(model["scaler_mean"], dtype=float)
    scale = np.asarray(model["scaler_scale"], dtype=float)
    max_samples = float(model["max_samples"])
    x = (np.asarray(x_raw, dtype=float) - mean) / scale

    normalizer = float(average_path_length(max_samples))
    total_depth = np.zeros(len(x), dtype=float)

    for tree in model["trees"]:
        normal = np.asarray(tree["normal"], dtype=float)
        bias = np.asarray(tree["bias"], dtype=float)
        left = np.asarray(tree["children_left"], dtype=int)
        right = np.asarray(tree["children_right"], dtype=int)
        n_node = np.asarray(tree["n_node_samples"], dtype=float)

        for i, sample in enumerate(x):
            node = 0
            depth = 0
            while left[node] != -1:
                if float(normal[node] @ sample) + bias[node] <= 0.0:
                    node = left[node]
                else:
                    node = right[node]
                depth += 1
            total_depth[i] += depth + float(average_path_length(float(n_node[node])))

    return 2.0 ** (-(total_depth / len(model["trees"])) / normalizer)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tolerance", type=float, default=1.0e-9)
    parser.add_argument("--trees", type=int, default=100)
    args = parser.parse_args()

    benign = build_feature_rows(generate_baseline_event_log(seed=1234), 10.0)
    attack = build_feature_rows(generate_paced_attack(30.0, seed=5), 10.0)

    x_benign = benign[FEATURE_COLUMNS].to_numpy(dtype=float)
    x_attack = attack[FEATURE_COLUMNS].to_numpy(dtype=float)

    scaler = StandardScaler().fit(x_benign)
    forest = ExtendedIsolationForest(n_estimators=args.trees, max_samples=256).fit(
        scaler.transform(x_benign)
    )

    benign_scores = forest.score(scaler.transform(x_benign))
    attack_scores = forest.score(scaler.transform(x_attack))
    threshold = float(np.quantile(benign_scores, 0.995))

    print(f"Trained on {len(x_benign)} benign windows, {args.trees} oblique trees.")
    print(f"  benign  mean score : {benign_scores.mean():.4f}")
    print(f"  attack  mean score : {attack_scores.mean():.4f}")
    print(f"  threshold  (99.5%) : {threshold:.4f}")
    print(f"  attack windows over threshold: {(attack_scores >= threshold).mean():.1%}")

    # Prove the export is complete: re-score from the serialized dict alone.
    exported = forest.to_dict(FEATURE_COLUMNS, scaler.mean_, scaler.scale_, threshold)
    round_trip = json.loads(json.dumps(exported))
    sample = x_attack[:40]
    difference = float(
        np.max(
            np.abs(
                score_from_dict(round_trip, sample)
                - forest.score(scaler.transform(sample))
            )
        )
    )
    print(f"\nJSON round-trip max difference: {difference:.3e}")
    if difference > args.tolerance:
        raise SystemExit("EXPORT FAILED: the JSON does not reproduce the model")
    print("EXPORT OK: the JSON alone reproduces the model, so a C++ port is possible.")


if __name__ == "__main__":
    main()
