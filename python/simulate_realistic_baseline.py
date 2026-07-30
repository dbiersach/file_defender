"""simulate_realistic_baseline.py

A harder, more realistic synthetic dataset for evaluating detector designs.

This module exists alongside `simulate_activity.py` and does not replace it.
`simulate_activity.py` produces a deliberately easy dataset: its benign
processes never delete a file and never write high-entropy content, so the
ransomware cluster is separable on almost any single feature. That is the right
choice for teaching the pipeline, but it makes every detector look perfect and
therefore cannot be used to compare detector designs.

The baseline here adds the three benign behaviors that actually cause false
positives in the field:

  1. Deletes and renames. An editor removes swap files, LibreOffice creates and
     removes lock files, a browser discards partial downloads. Without these,
     `rename_delete_rate` is identically zero in training, and then *any*
     delete at all looks infinitely anomalous.
  2. High-entropy writes. Already-compressed content (`.zip`, `.jpg`) measures
     ~7.6 bits/byte, which is ransomware territory. `average_byte_entropy`
     alone therefore cannot separate the classes.
  3. Fast, broad, high-entropy sweeps. `git gc` repacking and a `restic` backup
     run touch many directories and extensions at a high rate with
     near-random bytes. These are the hardest benign cases in the whole
     problem, and a detector that has never seen them will flag them.

It also provides a *rate-parameterized* attacker, so an experiment can ask the
question that a fixed scenario cannot: at what encryption pace does per-window
detection stop working?

Usage:
  python3 simulate_realistic_baseline.py                       # print a summary
  python3 simulate_realistic_baseline.py --write-baseline b.csv
  python3 simulate_realistic_baseline.py --write-scenario s.csv --files-per-minute 2
"""

from __future__ import annotations

import argparse

import numpy as np
import pandas as pd
from features import EVENT_COLUMNS

# Ordinary desktop applications. Each stays in its own directory and writes
# content at its own characteristic entropy.
#
# fields: (process_name, pid, mean_gap_seconds, directory, extensions, entropy)
_DESKTOP_PROFILES: list[tuple[str, int, float, str, list[str], float]] = [
    ("code", 2001, 2.0, "/home/student/Projects/app", [".py", ".md", ".txt"], 4.3),
    ("libreoffice", 2002, 15.0, "/home/student/Documents", [".odt", ".ods"], 4.8),
    ("thunderbird", 2004, 20.0, "/home/student/Mail", [".eml"], 4.6),
]

# The browser is listed separately because it is the one desktop process that
# routinely writes already-compressed, high-entropy files.
_BROWSER_MIX: list[tuple[str, float]] = [
    (".html", 5.2),
    (".pdf", 5.4),
    (".zip", 7.6),  # compressed: entropy in ransomware territory, but benign
    (".jpg", 7.4),
]

# Directories and extensions a backup run sweeps through. Deliberately broad,
# because breadth is exactly what the detector treats as suspicious.
_BACKUP_SOURCES: list[tuple[str, str, float]] = [
    ("/home/student/Documents", ".odt", 4.8),
    ("/home/student/Documents/tax", ".pdf", 5.4),
    ("/home/student/Pictures", ".jpg", 7.4),
    ("/home/student/Pictures/trip", ".png", 7.2),
    ("/home/student/Videos", ".mp4", 7.8),
    ("/home/student/Music", ".flac", 7.7),
    ("/home/student/Projects/app", ".py", 4.3),
    ("/home/student/Projects/thesis", ".tex", 4.4),
    ("/home/student/Desktop", ".txt", 4.1),
    ("/home/student/Mail", ".eml", 4.6),
]

# Files a ransomware sweep works through, spread across many directories and
# file types the way a real home-directory sweep would be.
_RANSOMWARE_TARGETS: list[str] = [
    "/home/student/Documents/resume.docx",
    "/home/student/Documents/budget.ods",
    "/home/student/Documents/letter.odt",
    "/home/student/Documents/tax/return_2025.xlsx",
    "/home/student/Documents/tax/w2.pdf",
    "/home/student/Documents/tax/receipts.csv",
    "/home/student/Pictures/wedding.jpg",
    "/home/student/Pictures/graduation.png",
    "/home/student/Pictures/trip/beach.jpg",
    "/home/student/Pictures/trip/mountain.jpg",
    "/home/student/Desktop/passwords.txt",
    "/home/student/Desktop/todo.md",
    "/home/student/Videos/birthday.mp4",
    "/home/student/Videos/recital.mp4",
    "/home/student/Music/playlist.m3u",
    "/home/student/Music/mixtape.flac",
    "/home/student/Projects/thesis/chapter1.tex",
    "/home/student/Projects/thesis/chapter2.tex",
    "/home/student/Projects/thesis/data.csv",
    "/home/student/Projects/app/main.py",
    "/home/student/Mail/archive.eml",
    "/home/student/.config/app/settings.json",
    "/home/student/Downloads/manual.pdf",
    "/home/student/Downloads/photos.zip",
]


def _event(
    t: float,
    name: str,
    pid: int,
    operation: str,
    path: str,
    size_bytes: int = 0,
    entropy: float = 0.0,
) -> dict[str, object]:
    """Build one raw-event row in the collector's CSV schema."""
    return {
        "timestamp_seconds": round(float(t), 3),
        "user_name": "student",
        "process_name": name,
        "process_id": int(pid),
        "operation": operation,
        "path": path,
        "bytes": int(size_bytes),
        "byte_entropy": round(float(entropy), 2),
    }


def _desktop_events(
    rng: np.random.Generator, duration_seconds: float
) -> list[dict[str, object]]:
    """Ordinary editor / office / mail activity, including temp-file deletes."""
    rows: list[dict[str, object]] = []

    for name, pid, mean_gap, directory, extensions, entropy_mean in _DESKTOP_PROFILES:
        t = 0.0
        while t < duration_seconds:
            t += float(rng.exponential(mean_gap))
            extension = extensions[rng.integers(len(extensions))]
            path = f"{directory}/file{int(rng.integers(0, 12))}{extension}"
            operation = str(
                rng.choice(["open", "read", "write", "close"], p=[0.3, 0.4, 0.2, 0.1])
            )
            if operation in ("open", "close"):
                rows.append(_event(t, name, pid, operation, path))
                continue

            entropy = float(np.clip(rng.normal(entropy_mean, 0.4), 0.0, 8.0))
            rows.append(
                _event(
                    t,
                    name,
                    pid,
                    operation,
                    path,
                    int(rng.integers(512, 200_000)),
                    entropy,
                )
            )

            # Editors and office suites clean up after themselves. This is the
            # benign source of rename/delete activity that the easy dataset
            # lacks entirely.
            if operation == "write" and rng.random() < 0.25:
                temp_path = (
                    f"{path}.swp"
                    if name == "code"
                    else f"{directory}/.~lock.{extension}#"
                )
                rows.append(_event(t + 0.05, name, pid, "write", temp_path, 4096, 3.0))
                rows.append(_event(t + 0.10, name, pid, "delete", temp_path))

    return rows


def _browser_events(
    rng: np.random.Generator, duration_seconds: float
) -> list[dict[str, object]]:
    """Browser downloads, including benign high-entropy compressed files."""
    rows: list[dict[str, object]] = []
    name, pid, directory = "firefox", 2003, "/home/student/Downloads"
    t = 0.0

    while t < duration_seconds:
        t += float(rng.exponential(8.0))
        extension, entropy_mean = _BROWSER_MIX[rng.integers(len(_BROWSER_MIX))]
        path = f"{directory}/download{int(rng.integers(0, 30))}{extension}"

        rows.append(_event(t, name, pid, "open", path))
        # A download arrives as a ".part" file that is renamed into place.
        rows.append(
            _event(
                t + 0.2,
                name,
                pid,
                "write",
                path + ".part",
                int(rng.integers(10_000, 5_000_000)),
                float(np.clip(rng.normal(entropy_mean, 0.3), 0.0, 8.0)),
            )
        )
        rows.append(_event(t + 0.4, name, pid, "rename", path + ".part"))
        if rng.random() < 0.15:  # an abandoned download is deleted
            rows.append(_event(t + 0.6, name, pid, "delete", path))

    return rows


def _git_gc_events(
    rng: np.random.Generator, duration_seconds: float
) -> list[dict[str, object]]:
    """Periodic `git gc`: bursts of high-entropy packfile writes plus deletes.

    This is a hard benign case. Repacking writes compressed objects (entropy
    ~7.9), renames temporary packs into place, and deletes the loose objects it
    replaced - three of the six features spike at once.
    """
    rows: list[dict[str, object]] = []
    name, pid = "git", 2005
    objects_dir = "/home/student/Projects/app/.git/objects"
    t = float(rng.uniform(60.0, 240.0))

    while t < duration_seconds:
        burst_size = int(rng.integers(10, 26))
        burst_time = t
        for i in range(burst_size):
            burst_time += float(rng.uniform(0.05, 0.25))
            pack = f"{objects_dir}/pack/tmp_pack_{i}.pack"
            rows.append(
                _event(
                    burst_time,
                    name,
                    pid,
                    "write",
                    pack,
                    int(rng.integers(50_000, 4_000_000)),
                    float(np.clip(rng.normal(7.9, 0.06), 0.0, 8.0)),
                )
            )
            burst_time += 0.02
            rows.append(_event(burst_time, name, pid, "rename", pack))
            burst_time += 0.02
            rows.append(
                _event(
                    burst_time,
                    name,
                    pid,
                    "delete",
                    f"{objects_dir}/{i:02x}/loose_object_{i}",
                )
            )
        t += float(rng.uniform(600.0, 1200.0))

    return rows


def _backup_events(
    rng: np.random.Generator, duration_seconds: float
) -> list[dict[str, object]]:
    """A `restic`-style backup sweep: broad, fast, and high-entropy.

    The single most ransomware-like benign workload there is. It reads every
    directory and extension in the home tree and writes encrypted blobs into
    its own cache, so it spikes every feature the detector watches except that
    it never deletes the originals.
    """
    rows: list[dict[str, object]] = []
    name, pid = "restic", 2006
    cache_dir = "/home/student/.cache/restic/data"
    t = float(rng.uniform(300.0, 900.0))

    while t < duration_seconds:
        sweep_time = t
        for directory, extension, entropy_mean in _BACKUP_SOURCES:
            for index in range(int(rng.integers(2, 5))):
                sweep_time += float(rng.uniform(0.1, 0.4))
                source = f"{directory}/item{index}{extension}"
                rows.append(_event(sweep_time, name, pid, "open", source))
                sweep_time += 0.05
                rows.append(
                    _event(
                        sweep_time,
                        name,
                        pid,
                        "read",
                        source,
                        int(rng.integers(20_000, 3_000_000)),
                        float(np.clip(rng.normal(entropy_mean, 0.3), 0.0, 8.0)),
                    )
                )
                sweep_time += 0.05
                # Backup blobs are encrypted, so they look exactly like
                # ransomware output on the entropy axis.
                rows.append(
                    _event(
                        sweep_time,
                        name,
                        pid,
                        "write",
                        f"{cache_dir}/blob_{int(rng.integers(0, 9999)):04x}.bin",
                        int(rng.integers(20_000, 3_000_000)),
                        float(np.clip(rng.normal(7.92, 0.05), 0.0, 8.0)),
                    )
                )
        t += float(rng.uniform(1800.0, 3600.0))

    return rows


def generate_baseline_event_log(
    seed: int = 1234, duration_minutes: float = 90.0
) -> pd.DataFrame:
    """
    Generate a benign-only raw-event log with realistic hard cases.

    Parameters
    ----------
    seed : int
        Seed for the random generator, so datasets are reproducible.
    duration_minutes : float
        Length of the simulated session, in minutes.

    Returns
    -------
    pd.DataFrame
        Raw events with the columns in EVENT_COLUMNS, sorted by timestamp.
    """
    rng = np.random.default_rng(seed)
    duration_seconds = duration_minutes * 60.0

    rows: list[dict[str, object]] = []
    rows += _desktop_events(rng, duration_seconds)
    rows += _browser_events(rng, duration_seconds)
    rows += _git_gc_events(rng, duration_seconds)
    rows += _backup_events(rng, duration_seconds)

    return (
        pd.DataFrame(rows, columns=EVENT_COLUMNS)
        .sort_values("timestamp_seconds")
        .reset_index(drop=True)
    )


def generate_paced_attack(
    files_per_minute: float,
    seed: int = 99,
    start_seconds: float = 600.0,
    n_targets: int | None = None,
) -> pd.DataFrame:
    """
    Generate a ransomware sweep that encrypts at a controlled pace.

    The per-file behavior is always the same - open the original, read it,
    write a high-entropy `.locked` copy, delete the original - so the only
    thing that changes across runs is *how fast* files are processed. That is
    what makes it possible to find the pace at which per-window detection
    fails.

    Parameters
    ----------
    files_per_minute : float
        Encryption pace. 60 is a fast smash-and-grab; 1 is a patient attacker.
    seed : int
        Seed for the random generator.
    start_seconds : float
        Timestamp at which the attack begins.
    n_targets : int | None
        How many files to encrypt. Defaults to the full target list.

    Returns
    -------
    pd.DataFrame
        Raw events with the columns in EVENT_COLUMNS, sorted by timestamp.
    """
    if files_per_minute <= 0.0:
        raise ValueError("files_per_minute must be positive")

    rng = np.random.default_rng(seed)
    targets = _RANSOMWARE_TARGETS[: n_targets or len(_RANSOMWARE_TARGETS)]
    gap_seconds = 60.0 / files_per_minute

    rows: list[dict[str, object]] = []
    name, pid = "cryptor", 6666
    t = start_seconds

    for target in targets:
        size_bytes = int(rng.integers(50_000, 2_000_000))
        rows.append(_event(t, name, pid, "open", target))
        rows.append(
            _event(
                t + 0.06,
                name,
                pid,
                "read",
                target,
                size_bytes,
                float(np.clip(rng.normal(5.2, 0.8), 0.0, 8.0)),
            )
        )
        rows.append(
            _event(
                t + 0.14,
                name,
                pid,
                "write",
                target + ".locked",
                size_bytes,
                float(np.clip(rng.normal(7.93, 0.05), 0.0, 8.0)),
            )
        )
        rows.append(_event(t + 0.19, name, pid, "delete", target))
        # Jitter the pace so the attacker is not perfectly periodic.
        t += gap_seconds * float(rng.uniform(0.85, 1.15))

    return (
        pd.DataFrame(rows, columns=EVENT_COLUMNS)
        .sort_values("timestamp_seconds")
        .reset_index(drop=True)
    )


def generate_scenario(
    files_per_minute: float = 20.0,
    seed: int = 7,
    duration_minutes: float | None = None,
) -> pd.DataFrame:
    """Merge a benign baseline with a paced ransomware sweep.

    The benign session is made long enough to cover the whole attack, so a slow
    attacker is not simply running off the end of the recording.
    """
    n_targets = len(_RANSOMWARE_TARGETS)
    attack_minutes = n_targets / files_per_minute
    if duration_minutes is None:
        duration_minutes = max(90.0, 10.0 + attack_minutes * 1.25)

    baseline = generate_baseline_event_log(seed=seed, duration_minutes=duration_minutes)
    attack = generate_paced_attack(
        files_per_minute, seed=seed + 1, start_seconds=duration_minutes * 60.0 * 0.15
    )

    return (
        pd.concat([baseline, attack], ignore_index=True)
        .sort_values("timestamp_seconds")
        .reset_index(drop=True)
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-baseline", metavar="PATH", help="benign-only CSV")
    parser.add_argument(
        "--write-scenario", metavar="PATH", help="benign + ransomware CSV"
    )
    parser.add_argument(
        "--files-per-minute",
        type=float,
        default=20.0,
        help="encryption pace for --write-scenario (default 20)",
    )
    parser.add_argument("--minutes", type=float, default=90.0, help="session length")
    parser.add_argument("--seed", type=int, default=1234)
    args = parser.parse_args()

    if args.write_scenario:
        events = generate_scenario(args.files_per_minute, seed=args.seed)
        events.to_csv(args.write_scenario, index=False)
        attack_rows = int((events["process_name"] == "cryptor").sum())
        print(f"Wrote {len(events)} events ({attack_rows} from the attacker)")
        print(f"  pace : {args.files_per_minute} files/minute")
        print(f"  path : {args.write_scenario}")
        return

    events = generate_baseline_event_log(seed=args.seed, duration_minutes=args.minutes)
    if args.write_baseline:
        events.to_csv(args.write_baseline, index=False)
        print(f"Wrote {len(events)} benign events to {args.write_baseline}")
        return

    print(f"Benign baseline: {len(events)} events over {args.minutes:g} minutes")
    print("\nEvents per process:")
    print(events["process_name"].value_counts().to_string())
    print("\nOperations:")
    print(events["operation"].value_counts().to_string())
    writes = events[events["operation"] == "write"]
    print("\nMean write entropy per process (bits/byte):")
    print(writes.groupby("process_name")["byte_entropy"].mean().round(2).to_string())


if __name__ == "__main__":
    main()
