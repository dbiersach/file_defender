#!/usr/bin/env python3
"""inspect_model.py

Look inside an exported Isolation Forest and report what it actually contains.

Why this exists
---------------
It is easy to assume that a model trained on six features uses all six. The
model shipped with this project did not. Two of its features never varied in
the training data, so no tree ever split on them, and the finished forest
could not react to them at all. Nothing in the training output said so.

This script reads a `model.json`, walks every tree, and prints the facts that
docs/ABOUT_THE_TREE.md quotes: how many trees, how deep they go, how many
training points end up in the biggest leaf, and which features the forest
really splits on. It then proves the "never used" claim the direct way, by
changing each feature by a huge amount and showing that the score does not
move.

Run it with:

  uv run python python/inspect_model.py
  uv run python python/inspect_model.py --model models/model.json \\
      --events testdata/sample_events.csv
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from features import FEATURE_COLUMNS, build_feature_rows
from verify_parity import score_from_json


def tree_depth(tree: dict, node: int = 0) -> int:
    """Return the number of splits on the longest root-to-leaf path."""
    if tree["children_left"][node] == -1:
        return 0
    return 1 + max(
        tree_depth(tree, tree["children_left"][node]),
        tree_depth(tree, tree["children_right"][node]),
    )


def describe_forest(model: dict) -> dict[str, object]:
    """
    Summarize the structure of every tree in an exported forest.

    Parameters
    ----------
    model : dict
        The parsed model JSON, holding every tree as flat arrays.

    Returns
    -------
    dict[str, object]
        Tree count, subsample size, depth range, leaf-size range, the set of
        feature indices any tree splits on, and how often each feature is the
        root split.
    """
    trees = model["trees"]
    depths = [tree_depth(t) for t in trees]
    leaf_sizes = [
        n
        for t in trees
        for n, left in zip(t["n_node_samples"], t["children_left"])
        if left == -1
    ]
    used: set[int] = set()
    root_counts = np.zeros(len(FEATURE_COLUMNS), dtype=int)
    for t in trees:
        for feature, left in zip(t["feature"], t["children_left"]):
            if left != -1:
                used.add(int(feature))
        # A tree that never split (a "stump") stores -2 as its root feature.
        # Skip it rather than letting -2 index the array from the end.
        if t["children_left"][0] != -1:
            root_counts[int(t["feature"][0])] += 1

    return {
        "trees": len(trees),
        "max_samples": int(model["max_samples"]),
        "depth_min": min(depths),
        "depth_max": max(depths),
        "leaf_min": min(leaf_sizes),
        "leaf_max": max(leaf_sizes),
        "features_used": sorted(used),
        "root_counts": root_counts,
    }


def sensitivity_check(model: dict, x_raw: np.ndarray) -> list[float]:
    """
    Push each feature to an absurd value and report how much scores move.

    This is an illustration, not a proof. A change of 0.0 means the chosen
    rows followed the same branches before and after the push. That always
    happens for a feature no tree splits on, but it can also happen for a
    used feature if the rows were already outside every split threshold.
    The structural scan in `describe_forest` is the real evidence about which
    features the forest uses; this check just makes it visible on real rows.

    Parameters
    ----------
    model : dict
        The parsed model JSON.
    x_raw : np.ndarray
        Unscaled feature rows to perturb, shape (n_rows, 6).

    Returns
    -------
    list[float]
        For each feature, the largest absolute change in any row's score
        after setting that feature to one million.
    """
    base = score_from_json(model, x_raw)
    changes = []
    for column in range(x_raw.shape[1]):
        perturbed = x_raw.copy()
        perturbed[:, column] = 1.0e6
        changes.append(float(np.max(np.abs(score_from_json(model, perturbed) - base))))
    return changes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="models/model.json")
    parser.add_argument(
        "--events",
        default="testdata/sample_events.csv",
        help="event CSV whose windows are used for the sensitivity check",
    )
    parser.add_argument("--window", type=float, default=10.0)
    args = parser.parse_args()

    model = json.loads(Path(args.model).read_text(encoding="utf-8"))
    summary = describe_forest(model)

    print(f"Model: {args.model}")
    print(f"  trees                : {summary['trees']}")
    print(f"  samples per tree     : {summary['max_samples']}")
    print(f"  tree depth           : {summary['depth_min']} to {summary['depth_max']}")
    print(f"  training points/leaf : {summary['leaf_min']} to {summary['leaf_max']}")
    print(f"  threshold            : {model['recommended_threshold']:.4f}")

    print("\nWhich features the forest splits on:")
    root_counts = summary["root_counts"]
    for index, name in enumerate(FEATURE_COLUMNS):
        status = "used" if index in summary["features_used"] else "NEVER USED"
        print(
            f"  [{index}] {name:<24} {status:<11} "
            f"(root split in {root_counts[index]} of {summary['trees']} trees)"
        )

    events = pd.read_csv(args.events)
    x_raw = build_feature_rows(events, window_seconds=args.window)[
        FEATURE_COLUMNS
    ].to_numpy(dtype=float)
    changes = sensitivity_check(model, x_raw)

    print(f"\nSensitivity check on {len(x_raw)} windows from {args.events}:")
    print("  (largest score change after setting one feature to 1,000,000;")
    print("   an illustration of the split scan above, not separate proof)")
    for index, (name, change) in enumerate(zip(FEATURE_COLUMNS, changes)):
        if index not in summary["features_used"]:
            note = "  <- no tree splits on this feature, so it can never move"
        elif change == 0.0:
            note = "  <- used by the forest, but these rows did not cross a split"
        else:
            note = ""
        print(f"  {name:<24} {change:.4f}{note}")


if __name__ == "__main__":
    main()
