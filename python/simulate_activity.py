"""simulate_activity.py

Generate synthetic behavioral feature vectors so the machine-learning pipeline
can be developed and tested on any machine, even without Linux or root access.

It produces two clusters:
  - "normal": ordinary desktop usage (editing a few documents).
  - "ransomware": rapid, high-entropy writes across many directories and file
    extensions, the signature this project aims to catch.

The model is trained ONLY on the normal cluster (unsupervised anomaly
detection). The ransomware cluster is used to check that the trained model
actually flags it. A fixed seed makes the dataset reproducible, so the training
and verification scripts see identical data.
"""

from __future__ import annotations

import argparse

import numpy as np
import pandas as pd
from features import EVENT_COLUMNS, FEATURE_COLUMNS


def generate_feature_dataset(
    n_normal: int = 400, n_ransomware: int = 25, seed: int = 42
) -> pd.DataFrame:
    """Return a DataFrame of feature rows with an extra 'label' column."""
    rng = np.random.default_rng(seed)

    normal = pd.DataFrame(
        {
            "events_per_second": rng.normal(0.8, 0.3, n_normal).clip(0.05, None),
            "writes_per_second": rng.normal(0.20, 0.10, n_normal).clip(0.0, None),
            "rename_delete_rate": rng.normal(0.02, 0.02, n_normal).clip(0.0, None),
            "average_byte_entropy": rng.normal(4.5, 0.5, n_normal).clip(0.0, 8.0),
            "unique_directory_count": rng.integers(1, 4, n_normal).astype(float),
            "unique_extension_count": rng.integers(1, 4, n_normal).astype(float),
        }
    )
    normal["label"] = "normal"

    ransomware = pd.DataFrame(
        {
            "events_per_second": rng.normal(12.0, 3.0, n_ransomware).clip(1.0, None),
            "writes_per_second": rng.normal(8.0, 2.0, n_ransomware).clip(0.5, None),
            "rename_delete_rate": rng.normal(3.0, 1.0, n_ransomware).clip(0.0, None),
            "average_byte_entropy": rng.normal(7.8, 0.15, n_ransomware).clip(0.0, 8.0),
            "unique_directory_count": rng.integers(5, 20, n_ransomware).astype(float),
            "unique_extension_count": rng.integers(5, 15, n_ransomware).astype(float),
        }
    )
    ransomware["label"] = "ransomware"

    dataset = pd.concat([normal, ransomware], ignore_index=True)
    return dataset[FEATURE_COLUMNS + ["label"]]


# A few benign desktop applications, each working mostly in one directory with
# normal-entropy content. Real ransomware differs by touching many directories
# and many file extensions with near-random (high-entropy) content.
_BENIGN_PROFILES = [
    # (process_name, pid, directory, [extensions], entropy_mean)
    ("code", 1001, "/home/student/Projects/app", [".py", ".txt", ".md"], 4.3),
    ("libreoffice", 1002, "/home/student/Documents", [".odt", ".ods"], 4.8),
    ("firefox", 1003, "/home/student/Downloads", [".pdf", ".html"], 5.2),
    ("thunderbird", 1004, "/home/student/Mail", [".eml"], 4.6),
]


def generate_benign_event_log(seed: int = 123, n_events: int = 1200) -> pd.DataFrame:
    """Create a realistic benign raw-event log (columns = EVENT_COLUMNS).

    Used to train a model the way it will really be used: on a baseline of
    ordinary activity recorded from the collector. Each process stays in its own
    directory with normal-entropy content, so a later ransomware burst (many
    directories, many extensions, high entropy) stands out.
    """
    rng = np.random.default_rng(seed)
    rows: list[dict[str, object]] = []
    t = 0.0

    for _ in range(n_events):
        t += float(rng.exponential(3.0))  # seconds between events
        name, pid, directory, extensions, entropy_mean = _BENIGN_PROFILES[
            rng.integers(len(_BENIGN_PROFILES))
        ]
        operation = str(
            rng.choice(["open", "read", "write", "close"], p=[0.3, 0.4, 0.2, 0.1])
        )
        extension = extensions[rng.integers(len(extensions))]
        path = f"{directory}/file{int(rng.integers(0, 12))}{extension}"

        if operation in ("open", "close"):
            entropy = 0.0
            size_bytes = 0
        else:
            entropy = float(np.clip(rng.normal(entropy_mean, 0.4), 0.0, 8.0))
            size_bytes = int(rng.integers(512, 200_000))

        rows.append(
            {
                "timestamp_seconds": round(t, 3),
                "user_name": "student",
                "process_name": name,
                "process_id": pid,
                "operation": operation,
                "path": path,
                "bytes": size_bytes,
                "byte_entropy": round(entropy, 2),
            }
        )

    return pd.DataFrame(rows, columns=EVENT_COLUMNS)


# Files the simulated ransomware sweeps through, spread across many directories
# and file types (a realistic target set for a home directory).
_RANSOMWARE_TARGETS = [
    "/home/student/Documents/resume.docx",
    "/home/student/Documents/budget.ods",
    "/home/student/Documents/tax/return_2025.xlsx",
    "/home/student/Documents/tax/w2.pdf",
    "/home/student/Documents/tax/receipts.csv",
    "/home/student/Pictures/wedding.jpg",
    "/home/student/Pictures/graduation.png",
    "/home/student/Pictures/trip/beach.jpg",
    "/home/student/Desktop/passwords.txt",
    "/home/student/Desktop/todo.md",
    "/home/student/Videos/birthday.mp4",
    "/home/student/Music/playlist.m3u",
    "/home/student/Projects/thesis/chapter1.tex",
    "/home/student/Projects/thesis/data.csv",
    "/home/student/.config/app/settings.json",
]


def generate_attack_scenario(seed: int = 7) -> pd.DataFrame:
    """Build a realistic mixed event log: several benign processes plus one
    ransomware process, for an end-to-end detection demo.

    Benign processes (code, libreoffice, firefox) work quietly in their own
    directories at normal entropy. Partway through, a 'cryptor' process sweeps
    the home directory: for each file it reads the original, writes a
    high-entropy '.locked' copy, then deletes the original - across many
    directories and file types in a few seconds.
    """
    rng = np.random.default_rng(seed)
    rows: list[dict[str, object]] = []

    def add(t, name, pid, op, path, size_bytes=0, entropy=0.0):
        rows.append(
            {
                "timestamp_seconds": round(float(t), 3),
                "user_name": "student",
                "process_name": name,
                "process_id": pid,
                "operation": op,
                "path": path,
                "bytes": int(size_bytes),
                "byte_entropy": round(float(entropy), 2),
            }
        )

    # Benign background activity (same cadence as the training baseline).
    benign = [
        ("code", 2001, "/home/student/Projects/app", [".py", ".md"], 4.3),
        ("libreoffice", 2002, "/home/student/Documents", [".odt", ".ods"], 4.8),
        ("firefox", 2003, "/home/student/Downloads", [".pdf", ".html"], 5.2),
    ]
    t = 0.0
    for _ in range(90):
        t += float(rng.exponential(3.0))
        name, pid, directory, exts, entropy_mean = benign[rng.integers(len(benign))]
        op = str(rng.choice(["open", "read", "write", "close"], p=[0.3, 0.4, 0.2, 0.1]))
        path = (
            f"{directory}/file{int(rng.integers(0, 10))}{exts[rng.integers(len(exts))]}"
        )
        if op in ("open", "close"):
            add(t, name, pid, op, path)
        else:
            add(
                t,
                name,
                pid,
                op,
                path,
                rng.integers(512, 150_000),
                float(np.clip(rng.normal(entropy_mean, 0.3), 0.0, 8.0)),
            )

    # The ransomware burst, starting halfway through the benign timeline.
    cryptor_time = t * 0.5
    for target in _RANSOMWARE_TARGETS:
        cryptor_time += float(rng.uniform(0.2, 0.6))
        add(cryptor_time, "cryptor", 6666, "open", target)
        cryptor_time += float(rng.uniform(0.1, 0.3))
        add(
            cryptor_time,
            "cryptor",
            6666,
            "read",
            target,
            rng.integers(50_000, 2_000_000),
            float(np.clip(rng.normal(5.0, 0.6), 0.0, 8.0)),
        )
        cryptor_time += float(rng.uniform(0.1, 0.3))
        add(
            cryptor_time,
            "cryptor",
            6666,
            "write",
            target + ".locked",
            rng.integers(50_000, 2_000_000),
            float(np.clip(rng.normal(7.9, 0.08), 0.0, 8.0)),
        )
        cryptor_time += float(rng.uniform(0.05, 0.15))
        add(cryptor_time, "cryptor", 6666, "delete", target)

    return (
        pd.DataFrame(rows, columns=EVENT_COLUMNS)
        .sort_values("timestamp_seconds")
        .reset_index(drop=True)
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate synthetic activity for testing."
    )
    parser.add_argument(
        "--write-events",
        metavar="PATH",
        help="write a benign baseline raw-event CSV to PATH",
    )
    parser.add_argument(
        "--write-scenario",
        metavar="PATH",
        help="write a mixed benign + ransomware attack scenario CSV to PATH",
    )
    args = parser.parse_args()

    if args.write_scenario:
        events = generate_attack_scenario()
        events.to_csv(args.write_scenario, index=False)
        ransom = int((events["process_name"] == "cryptor").sum())
        print(
            f"Wrote {len(events)} events ({ransom} from the ransomware) to {args.write_scenario}"
        )
    elif args.write_events:
        events = generate_benign_event_log()
        events.to_csv(args.write_events, index=False)
        print(f"Wrote {len(events)} benign events to {args.write_events}")
    else:
        data = generate_feature_dataset()
        print("Synthetic feature dataset:")
        print(data["label"].value_counts().to_string())
        print("\nNormal cluster means:")
        print(
            data[data["label"] == "normal"][FEATURE_COLUMNS].mean().round(3).to_string()
        )
        print("\nRansomware cluster means:")
        print(
            data[data["label"] == "ransomware"][FEATURE_COLUMNS]
            .mean()
            .round(3)
            .to_string()
        )
