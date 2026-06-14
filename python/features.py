"""features.py

Canonical definition of the behavioral feature vector used everywhere in this
project. The same six features are computed in three places, and they MUST stay
in sync:

  1. Here, in Python, to build training data from recorded events.
  2. In the C++ daemon (src/daemon/feature_window.cpp) for live scoring.
  3. Implicitly in the simulator (python/simulate_activity.py).

The features summarize a short rolling time window of one process's file
activity. Ransomware tends to show up as a spike in write rate, byte entropy,
and the breadth of directories and file extensions touched.
"""

from __future__ import annotations

from pathlib import PurePosixPath

import pandas as pd

# The exact feature order. The C++ daemon relies on this order.
FEATURE_COLUMNS: list[str] = [
    "events_per_second",
    "writes_per_second",
    "rename_delete_rate",
    "average_byte_entropy",
    "unique_directory_count",
    "unique_extension_count",
]

# Columns expected in a raw event CSV (matches the collector output and
# testdata/sample_events.csv).
EVENT_COLUMNS: list[str] = [
    "timestamp_seconds",
    "user_name",
    "process_name",
    "process_id",
    "operation",
    "path",
    "bytes",
    "byte_entropy",
]


def build_feature_rows(
    events: pd.DataFrame, window_seconds: float = 10.0
) -> pd.DataFrame:
    """Turn a raw event log into one feature row per event, per process.

    This mirrors the C++ daemon exactly: each process has its own rolling
    window, and after every event we recompute the window's features. Rates are
    divided by the fixed window length, so they are comparable across windows.

    Parameters
    ----------
    events : pd.DataFrame
        Raw events with the columns in EVENT_COLUMNS.
    window_seconds : float
        Length of the rolling window, in seconds.

    Returns
    -------
    pd.DataFrame
        One row per event with the columns in FEATURE_COLUMNS.
    """
    events = events.sort_values("timestamp_seconds").reset_index(drop=True)
    rows: list[dict[str, float]] = []

    for _, group in events.groupby("process_id"):
        records = group.to_dict("records")
        for i, current in enumerate(records):
            now = float(current["timestamp_seconds"])

            # Keep events within the window, matching the daemon's expiry rule:
            # an event is kept while (now - its_time) <= window_seconds.
            window = [
                r
                for r in records[: i + 1]
                if now - float(r["timestamp_seconds"]) <= window_seconds
            ]
            n = len(window)

            writes = sum(1 for r in window if r["operation"] == "write")
            renames_deletes = sum(
                1 for r in window if r["operation"] in ("rename", "delete")
            )
            mean_entropy = (
                sum(float(r["byte_entropy"]) for r in window) / n if n else 0.0
            )
            directories = {str(PurePosixPath(str(r["path"])).parent) for r in window}
            extensions = {PurePosixPath(str(r["path"])).suffix for r in window}

            rows.append(
                {
                    "events_per_second": n / window_seconds,
                    "writes_per_second": writes / window_seconds,
                    "rename_delete_rate": renames_deletes / window_seconds,
                    "average_byte_entropy": mean_entropy,
                    "unique_directory_count": float(len(directories)),
                    "unique_extension_count": float(len(extensions)),
                }
            )

    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)
