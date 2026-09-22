#!/usr/bin/env python3
"""verify_cpp_parity.py

Run the real C++ daemon and check its features AND scores against Python.

`verify_parity.py` shows that the exported JSON scores the same way
scikit-learn does, but it never runs a line of C++. This script closes that
gap. It launches the compiled daemon with `--dump-features`, which makes the
daemon print one CSV row per event holding the six features it computed and
the score it produced. The same events are then pushed through
`python/features.py` and the JSON scorer, and the two tables are compared
number for number.

If this passes, three things are true at once, on the fixture files it was
given:

  1. `src/daemon/feature_window.cpp` computed the same six numbers as
     `python/features.py` for every event in those files.
  2. `src/daemon/anomaly_model.cpp` walked the trees the same way the Python
     reference does for every one of those windows.
  3. The model file the daemon loaded is the one Python expects.

A pass on two fixture files is evidence, not a proof for every possible
input. It is the strongest check this project has, and it must run on Linux,
where the daemon builds. Run it after any change to a feature definition, in
either language:

  uv run python python/verify_cpp_parity.py --daemon build/file_defender_daemon

A checker that cannot fail is worthless, so this script can also test
itself. `--self-test` skips the daemon, corrupts the Python table in several
ways, and confirms that each corruption is rejected:

  uv run python python/verify_cpp_parity.py --self-test
"""

from __future__ import annotations

import argparse
import io
import json
import subprocess
from pathlib import Path

import numpy as np
import pandas as pd
from evaluation import build_labeled_features
from features import FEATURE_COLUMNS
from verify_parity import score_from_json

IDENTITY = ["process_id", "timestamp_seconds"]
NUMERIC = [*FEATURE_COLUMNS, "score"]


class ParityMismatch(Exception):
    """Raised when the daemon's table does not match the Python table."""


def run_daemon_dump(
    daemon: Path, model: Path, events: Path, window: float
) -> pd.DataFrame:
    """
    Run the daemon in `--dump-features` mode and parse its CSV output.

    Parameters
    ----------
    daemon : Path
        Path to the compiled `file_defender_daemon` binary.
    model : Path
        Path to the exported model JSON.
    events : Path
        Event CSV to feed the daemon.
    window : float
        Rolling window length in seconds, passed as `--window`.

    Returns
    -------
    pd.DataFrame
        The daemon's rows: timestamp, pid, six features, and score.
    """
    command = [
        str(daemon),
        "--events",
        str(events),
        "--model",
        str(model),
        "--window",
        str(window),
        "--dump-features",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=True)
    return pd.read_csv(io.StringIO(completed.stdout))


def python_reference(model: dict, events: Path, window: float) -> pd.DataFrame:
    """
    Compute the same table in Python, from the same events.

    Parameters
    ----------
    model : dict
        The parsed model JSON.
    events : Path
        Event CSV.
    window : float
        Rolling window length in seconds.

    Returns
    -------
    pd.DataFrame
        Timestamp, pid, six features, and score, one row per event.
    """
    frame = pd.read_csv(events)
    rows = build_labeled_features(frame, window_seconds=window)
    x_raw = rows[FEATURE_COLUMNS].to_numpy(dtype=float)
    rows = rows.assign(score=score_from_json(model, x_raw))
    return rows[[*IDENTITY[::-1], *NUMERIC]]


def compare_tables(cpp: pd.DataFrame, py: pd.DataFrame) -> tuple[float, float]:
    """
    Line the two tables up by process and time, then report the worst gaps.

    The function refuses to report a gap at all when the tables cannot be
    compared honestly: different row counts, missing columns, non-finite
    numbers, or rows whose process id and timestamp do not match after
    sorting. Each of those raises `ParityMismatch` instead of returning a
    number, so a broken daemon output can never look like a pass.

    Parameters
    ----------
    cpp : pd.DataFrame
        Rows printed by the daemon.
    py : pd.DataFrame
        Rows computed by Python.

    Returns
    -------
    tuple[float, float]
        Largest absolute difference over the six features, and over the score.
    """
    if len(cpp) == 0 or len(py) == 0:
        raise ParityMismatch("one of the tables is empty")
    if len(cpp) != len(py):
        raise ParityMismatch(
            f"row count mismatch: daemon printed {len(cpp)} rows, Python built {len(py)}"
        )
    missing = [c for c in IDENTITY + NUMERIC if c not in cpp.columns]
    if missing:
        raise ParityMismatch(f"daemon output lacks columns: {missing}")

    cpp = cpp.sort_values(IDENTITY, kind="stable").reset_index(drop=True)
    py = py.sort_values(IDENTITY, kind="stable").reset_index(drop=True)

    # Identity first: the rows must describe the same events.
    if not np.array_equal(
        cpp["process_id"].to_numpy(dtype=int), py["process_id"].to_numpy(dtype=int)
    ):
        raise ParityMismatch("process ids differ after alignment")
    if not np.allclose(
        cpp["timestamp_seconds"].to_numpy(dtype=float),
        py["timestamp_seconds"].to_numpy(dtype=float),
        rtol=0.0,
        atol=1.0e-6,
    ):
        raise ParityMismatch("timestamps differ after alignment")

    cpp_numeric = cpp[NUMERIC].to_numpy(dtype=float)
    py_numeric = py[NUMERIC].to_numpy(dtype=float)
    if not np.isfinite(cpp_numeric).all():
        raise ParityMismatch("daemon output contains NaN or infinite values")
    if not np.isfinite(py_numeric).all():
        raise ParityMismatch("Python reference contains NaN or infinite values")

    diff = np.abs(cpp_numeric - py_numeric)
    feature_gap = float(diff[:, : len(FEATURE_COLUMNS)].max())
    score_gap = float(diff[:, -1].max())
    return feature_gap, score_gap


def self_test(model: dict, events: Path, window: float) -> None:
    """
    Corrupt the Python table in several ways and confirm each one is caught.

    Parameters
    ----------
    model : dict
        The parsed model JSON.
    events : Path
        Event CSV used to build the reference table.
    window : float
        Rolling window length in seconds.

    Returns
    -------
    None
        Prints one line per case. Exits non-zero if any corruption passes.
    """
    reference = python_reference(model, events, window)

    def corrupt(name: str, table: pd.DataFrame) -> tuple[str, pd.DataFrame]:
        return name, table

    cases = []

    bad = reference.copy()
    bad[NUMERIC] = float("nan")
    cases.append(corrupt("all numbers NaN", bad))

    bad = reference.copy()
    bad["process_id"] += 1000
    cases.append(corrupt("process ids shifted", bad))

    bad = reference.copy()
    bad["timestamp_seconds"] += 5.0
    cases.append(corrupt("timestamps shifted", bad))

    bad = reference.copy()
    bad.loc[0, "score"] += 1.0e-3
    cases.append(corrupt("one score off by 1e-3", bad))

    bad = reference.copy()
    bad.loc[0, "average_byte_entropy"] += 1.0e-3
    cases.append(corrupt("one feature off by 1e-3", bad))

    cases.append(corrupt("half the rows missing", reference.iloc[::2].copy()))
    cases.append(corrupt("empty table", reference.iloc[0:0].copy()))

    failures = 0
    for name, table in cases:
        try:
            feature_gap, score_gap = compare_tables(table, reference)
            caught = max(feature_gap, score_gap) > 1.0e-9
            detail = f"gaps {feature_gap:.1e} / {score_gap:.1e}"
        except ParityMismatch as error:
            caught = True
            detail = str(error)
        status = "caught" if caught else "PASSED (BUG)"
        print(f"  {name:<26} {status:<13} {detail}")
        failures += 0 if caught else 1

    # And the unchanged table must pass, or the checker is useless the other way.
    feature_gap, score_gap = compare_tables(reference.copy(), reference)
    print(
        f"  {'identical table':<26} {'passes':<13} gaps {feature_gap:.1e} / {score_gap:.1e}"
    )

    if failures:
        raise SystemExit(
            f"\nSELF-TEST FAILED: {failures} corruption(s) were not caught"
        )
    print("\nSELF-TEST OK: every corrupted table was rejected.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", default="build/file_defender_daemon")
    parser.add_argument("--model", default="models/model.json")
    parser.add_argument(
        "--events",
        nargs="+",
        default=["testdata/sample_events.csv", "testdata/attack_scenario.csv"],
    )
    parser.add_argument("--window", type=float, default=10.0)
    parser.add_argument("--tolerance", type=float, default=1.0e-9)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="do not run the daemon; prove the checker rejects bad tables",
    )
    args = parser.parse_args()

    model_path = Path(args.model)
    model = json.loads(model_path.read_text(encoding="utf-8"))

    if args.self_test:
        print("Checker self-test (no daemon involved):")
        self_test(model, Path(args.events[0]), args.window)
        return

    daemon = Path(args.daemon)
    if not daemon.exists():
        raise SystemExit(
            f"Daemon not found at {daemon}. Build it first on Linux:\n"
            "  cmake --preset default && cmake --build build"
        )

    worst_feature = 0.0
    worst_score = 0.0
    for events in args.events:
        events_path = Path(events)
        cpp = run_daemon_dump(daemon, model_path, events_path, args.window)
        py = python_reference(model, events_path, args.window)
        try:
            feature_gap, score_gap = compare_tables(cpp, py)
        except ParityMismatch as error:
            raise SystemExit(f"\nC++ PARITY FAILED on {events}: {error}") from error
        worst_feature = max(worst_feature, feature_gap)
        worst_score = max(worst_score, score_gap)
        print(
            f"{events}: {len(cpp)} rows, feature gap {feature_gap:.3e}, "
            f"score gap {score_gap:.3e}"
        )

    if max(worst_feature, worst_score) <= args.tolerance:
        print(
            "\nC++ PARITY OK: on these fixture files the daemon's features and\n"
            "scores agree with the Python reference."
        )
    else:
        raise SystemExit(
            f"\nC++ PARITY FAILED: feature gap {worst_feature:.3e}, "
            f"score gap {worst_score:.3e} (tolerance {args.tolerance})"
        )


if __name__ == "__main__":
    main()
