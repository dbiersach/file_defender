# File Defender

File Defender is a defensive cybersecurity research project. It uses a
machine-learning method called Isolation Forest to detect ransomware by
looking for unusual patterns in file activity.

**This project is defensive.** It observes file activity and raises alerts. It contains no ransomware and never encrypts, corrupts, or mass-modifies files. See [`docs/SAFETY_AND_SCOPE.md`](docs/SAFETY_AND_SCOPE.md).

## What File Defender Does

Ransomware typically behaves very differently from normal user activity:

- **Rapid, high-volume file writes** across many directories
- **High-entropy encrypted data** (looks random to statistical analysis)
- **Repeated rename/delete cycles** (e.g., renaming files to `.locked`)
- **Sweeping across file extensions** and directories (trying to encrypt everything)

File Defender watches for these patterns in each running process. It learns
from *benign* activity, meaning ordinary use rather than attacks, and raises
an alert when a process behaves differently. It does not need ransomware
samples for training.

This is a research prototype for learning and experimentation, not a finished
security product. The offline demos run from start to finish, but the
detection results come from simulated activity rather than real recordings.
The two collectors also remain separate rather than feeding one combined
event stream.

## What the Experiments Found

The detector summarizes recent activity as six measurements, called
*features*, and gives that activity an anomaly score. A score above the alert
threshold triggers a warning. If the activity was benign, the warning is a
*false positive*, or false alarm.

The experiments test both detection and false alarms. Several results differ
from the initial expectations; the full methods and tables are in
[`docs/EXPERIMENTS_AND_FINDINGS.md`](docs/EXPERIMENTS_AND_FINDINGS.md).

- **The shipped model uses four of its six input features.**
  `rename_delete_rate` and `unique_directory_count` never vary in
  `testdata/benign_baseline.csv`. No tree splits on them, so changing those
  inputs cannot change the score. `python/inspect_model.py` shows this.
- **The tested rules miss patient attackers.** Below about 6 files per
  minute, the attacker's average score matches a benign process's average.
  Averaging scores over time with EWMA cannot help when the average is not
  elevated. The CUSUM rule, with the calibration used here, does not help
  either. A test of something other than the average has not been tried.
- **Two benign programs account for the false alarms.** `git gc` and
  `restic` backups resemble ransomware in these measurements. Setting the
  threshold high enough to tolerate them makes detection much slower.
- **A target false-positive rate is not a future guarantee.** With `git`
  and `restic` excluded from calibration, a threshold aimed at 0.5% on one
  benign session flags 1.15% of a second session. Including every process
  raises the threshold, giving 0.34% on the second session, but the detector
  then misses most attacks.
- **A simpler detector performs better in this comparison.** On the
  synthetic data, a 1.1 KB Mahalanobis model beats the 562 KB forest on files
  lost, time to detection, and average precision at the same target
  false-alarm rate.
- **Training and live data share an entropy convention.** The collector and
  simulators assign 0.0 to `open` and `close` events. For reads and writes,
  the value represents entropy in the file's first 4096 bytes.

## Documentation

| Document | What it covers |
| --- | --- |
| [`docs/SAFETY_AND_SCOPE.md`](docs/SAFETY_AND_SCOPE.md) | What this project will and will not do, and the ethics of automatic response. Read this first. |
| [`docs/ENTROPY_AND_ML_EXPLAINED.md`](docs/ENTROPY_AND_ML_EXPLAINED.md) | Step-by-step walkthrough of Shannon entropy and the full pipeline, from raw bytes to an alert. Written for a student meeting information theory for the first time. |
| [`docs/WHY_ISOLATION_FOREST.md`](docs/WHY_ISOLATION_FOREST.md) | Why Isolation Forest was chosen, where it is genuinely weak, and what the alternatives would cost. |
| [`docs/ABOUT_THE_TREE.md`](docs/ABOUT_THE_TREE.md) | How one isolation tree is built and scored: the three random choices during training, the stopping rules, the leaf correction, what subsampling does in this project's setting, and what is actually inside the shipped model. Optional deeper reading after the entropy guide. |
| [`docs/EXPERIMENTS_AND_FINDINGS.md`](docs/EXPERIMENTS_AND_FINDINGS.md) | Three proposed improvements, built as standalone modules and measured against the current detector. Includes the results that did not support the proposal, which turned out to be the important ones. |

## How It Works

The collector records file events. The daemon reads those events and scores
recent activity. Before the daemon can do that, the Python trainer learns
a model from benign activity and saves it to a file. These three programs
form the pipeline:

```text
  +---------------------+        CSV events         +-----------------------+
  |  collector (C)      |  ---------------------->  |  daemon (C++)         |
  |  fanotify           |   pid, path, entropy...   |  rolling features per |
  |  watches the FS     |                           |  process + Isolation  |
  +---------------------+                           |  Forest scoring       |
                                                    +-----------------------+
                                                              |
  +---------------------+   trees + scaler (JSON)             v
  |  trainer (Python)   |  ------------------------>   alert / notify /
  |  Isolation Forest   |        models/model.json     (optional) SIGSTOP
  +---------------------+
```

### Component 1: Collector (C)

**Location:** `src/collector/fanotify_collector.c`

- Watches filesystem using `fanotify` (Linux kernel API)
- Captures file events: **opens, reads, writes, and close-after-write**
- For each event, records:
  - Timestamp, user, process name/PID
  - File operation (`open`, `read`, `write`, `close`)
  - File path and size
  - **Shannon byte entropy** of the file's first 4096 bytes (0 = very structured, 8 = evenly spread byte values, which is what encrypted and compressed data look like)
- Outputs one CSV line per event to stdout

The collector follows the same entropy convention as the simulators in
`python/`: `open` and `close` carry 0.0, while `read` and `write` carry the
entropy of the file's current first 4096 bytes. Rename and delete events
come from the second collector below. It has no file content to sample and
reports 0.0.

Measuring only the start of a file keeps the work small, but has limits. That
prefix is not necessarily the data the process just wrote. A partly encrypted
file may also keep an ordinary-looking prefix.

**Why fanotify (not inotify or eBPF)?**

The detector needs the process ID that caused an event, so it can identify
and optionally pause the process. It also needs access to file contents for
entropy measurements. Ordinary `inotify` does not provide both; `fanotify`
does, without requiring this project to write a kernel module.

There are two fanotify collectors:

- **`fanotify_collector`** (primary) - classic mode: opens, reads, and writes with content for entropy, plus the pid.
- **`fanotify_fid_collector`** (worked example) uses FID mode
  (`FAN_REPORT_DFID_NAME`) for rename, delete, and create events that classic
  mode misses. Examples include renaming a file to `.locked` and deleting
  the original. It reports the PID but has no file content for entropy.
  A complete deployment runs both collectors and merges their streams; the
  daemon already counts rename/delete events.

### Component 2: Daemon (C++)

**Location:** `src/daemon/main.cpp`

- Reads the CSV event stream from the collector
- Maintains a **rolling behavioral window** for each process (default: 10 seconds)
- Computes six behavioral features per window
- Scores each window using the trained **Isolation Forest** model
- Alerts when a window is anomalous (unlike benign data)
- Optionally pauses suspicious processes with `SIGSTOP` (requires opt-in)

### Component 3: Trainer (Python)

**Location:** `python/train_isolation_forest.py`

- Reads a CSV of **benign baseline** activity (normal user workflow)
- Trains a scikit-learn **Isolation Forest** on behavioral features
- Exports the model to **JSON** (so the C++ daemon can score without Python)
- Also exports a joblib file for debugging in Python

The Isolation Forest is trained **only on benign data**, so it needs no ransomware samples.

## The Behavioral Features

A *window* is the recent activity kept for one process, covering 10 seconds
by default. The program summarizes it with these six numbers:

| Feature | Why It Matters | Ransomware Looks Like |
| --- | --- | --- |
| **events per second** | Activity bursts | Spikes (50+ events/sec) |
| **writes per second** | Encryption requires writes | High write rate (10+ writes/sec) |
| **rename/delete rate** | The `.locked` rename pattern | Rapid cycles |
| **average byte entropy** | Encrypted data is random | Approaches 8.0 (max) |
| **unique directory count** | Attack sweeps filesystem | Hundreds of dirs in seconds |
| **unique extension count** | Attack touches all file types | Dozens of extensions |

An Isolation Forest learns what benign windows look like. It flags windows
that are easy to separate, or *isolate*, from the training examples. The
ordinary editor and browser activity in the baseline has low, steady feature
values, while the ransomware activity produces spikes.

The table describes the six inputs, but a trained tree can split only on
features that vary in its training data. In the supplied
`testdata/benign_baseline.csv`, no process renames or deletes a file, and
each process stays in one directory. The shipped `models/model.json`
therefore never splits on `rename_delete_rate` or `unique_directory_count`.
Run `uv run python python/inspect_model.py` to inspect feature usage; the
trainer also warns about unused features after each run.

## Platform

- Linux Mint 22.3 (Ubuntu 24.04 base, kernel 6.x), Intel x64
- clang / clangd, CMake, LLDB
- Python 3.12, managed with [uv](https://docs.astral.sh/uv/)
- VS Code

## Setup (Step-by-Step)

### Prerequisites

- Linux (tested on Ubuntu 24.04 / Mint 22.3)
- `uv` (Python package manager)
- CMake, clang, and standard build tools

### Step 1: Install System Dependencies

```bash
bash scripts/setup_system_deps.sh
```

This installs:

- Build tools (clang, CMake, git)
- Python dev headers
- uv package manager

### Step 2: Install VS Code Extensions

```bash
bash install_vscode_extensions.sh
```

Sets up:

- C/C++ extensions (clangd, lldb for debugging)
- Python extensions
- CMake support

### Step 3: Build the C/C++ Programs

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j"$(nproc)"
```

This compiles:

- `fanotify_collector` - filesystem watcher
- `fanotify_fid_collector` - rename/delete/create watcher
- `file_defender_daemon` - anomaly detector
- `inotify_demo` - teaching comparison

### Step 4: Open in VS Code

```bash
code file_defender.code-workspace
```

This loads the workspace with all settings, debugging, and linting configured.

## Running File Defender

### Mode 1: Quick Offline Demo (No Root Needed)

Start with the supplied event files to try training and scoring without
monitoring a live system:

```bash
# Train on a benign baseline (ordinary activity)
uv run python python/train_isolation_forest.py \
    --events testdata/benign_baseline.csv \
    --out models/model.json --joblib models/model.joblib

# Score a scenario where one process behaves like ransomware
./build/file_defender_daemon \
    --events testdata/sample_events.csv --model models/model.json
```

**Expected:** only `unknown_process` (pid 4242) is flagged; `code`, `libreoffice`, and `firefox` are not.

The first command trains on `benign_baseline.csv`, which represents ordinary
file activity, and writes `model.json`. The second command loads that model
into the C++ daemon and scores `sample_events.csv`. This file includes benign
activity and one process behaving like ransomware. Training happens in
Python; the daemon only loads the result and scores events.

### Mode 2: Larger Multi-Process Attack Scenario

This scenario mixes events from three benign processes with a `cryptor`
process. The latter visits 15 files across several directories. For each
file it reads the original, writes a high-entropy `.locked` copy, and deletes
the original:

```bash
./build/file_defender_daemon \
    --events testdata/attack_scenario.csv --model models/model.json
```

Regenerate it with:

```bash
uv run python python/simulate_activity.py --write-scenario testdata/attack_scenario.csv
```

**Expected:** only `cryptor` (pid 6666) is flagged.

### Mode 3: Live Monitoring (Requires Root)

For live monitoring, the collector needs root privileges (`CAP_SYS_ADMIN`),
but the daemon runs as your regular user. The pipe sends the collector's
event records directly to the daemon, keeping the privileged part of the
system small:

```bash
sudo ./build/fanotify_collector "$HOME" \
    | ./build/file_defender_daemon --model models/model.json --notify
```

**Flags:**

- `--notify` - send desktop notifications when anomalies are detected
- `--stop` - pause flagged processes with `SIGSTOP` (can resume with `kill -CONT <pid>`)
- `--threshold N` - override the alert score (default: the `recommended_threshold` stored in the model file; lower = more alerts)
- `--window N` - seconds per rolling window (default 10)
- `--dump-features` - print one CSV row per event with the six features and the score, instead of alerts (used by `verify_cpp_parity.py`)

The trainer's `--max-fpr` option sets the target false-positive rate used
to choose `recommended_threshold`. It is not a daemon option: the daemon
reads the saved threshold or uses the `--threshold` override.

Add `--stop` to pause a flagged process with `SIGSTOP` (opt-in). A paused process is never killed; resume it with `kill -CONT <pid>`.

## Understanding the Data

### Event CSV Format

Each line is one file operation:

```text
timestamp_seconds,user_name,process_name,process_id,operation,path,bytes,byte_entropy
1623456000.000,alice,code,1234,write,/home/alice/file.txt,1024,4.50
```

**Fields** (these exact column names are what `python/features.py` and the daemon expect):

- `timestamp_seconds` - Unix time, as a decimal number of seconds
- `user_name` - username
- `process_name` - process name (from `/proc/[pid]/comm`, which any program can set)
- `process_id` - process ID
- `operation` - `open`, `read`, `write`, `close` from the classic collector; `create`, `delete`, `rename` from the FID collector
- `path` - full file path
- `bytes` - file size in bytes
- `byte_entropy` - Shannon entropy of the file's first 4096 bytes (0.00 to 8.00); 0.00 for `open`, `close`, and every FID event

### Feature Window

The daemon keeps a rolling time window for each process. As a new event
arrives, events older than the window are removed and the six features are
recalculated. With the default 10-second window, the score describes that
process's recent 10 seconds of activity.

## Development Workflow

### Phase 1: Understand Offline

1. Run the offline demo above
2. Read `python/features.py` to understand the feature definitions
3. Look at `src/daemon/feature_window.cpp` to see how features are computed
4. Examine sample data in `testdata/` with `cat` or a spreadsheet app

### Phase 2: Record Your Own Baseline

1. Run the collector on your home directory:

   ```bash
   sudo ./build/fanotify_collector "$HOME" > my_baseline.csv
   ```

   (Let it run for 5-10 minutes during normal use)

2. Retrain the model:

   ```bash
   uv run python python/train_isolation_forest.py \
       --events my_baseline.csv \
       --out models/model_personalized.json
   ```

3. Test with live data:

   ```bash
   sudo ./build/fanotify_collector "$HOME" \
       | ./build/file_defender_daemon \
           --model models/model_personalized.json --notify
   ```

### Phase 3: Tune Detection

Tuning involves a tradeoff: how quickly should the detector respond, and how
many benign windows will it flag? The time before an alert is called
*detection latency*. These settings affect that tradeoff:

- Daemon: `--window N` - seconds per window (default 10, lower = faster detection, more noise)
- Daemon: `--threshold N` - alert score (lower = more alerts)
- Trainer: `--max-fpr N` - where the model's `recommended_threshold` is aimed (higher = more alerts)

Compare the effects as you change the settings:

- **Fast detection** needs small windows and low thresholds (but more false alerts)
- **Few false alerts** needs large windows and high thresholds (but slower detection)

### Phase 4: Live Defense

1. Set up the collector and daemon to run at startup
2. Configure `--notify` for desktop alerts
3. Decide on the `--stop` flag (pause vs. alert-only)

### Phase 5: Ethics Review

Read `docs/SAFETY_AND_SCOPE.md` for important guidance on:

- When software should alert vs. act
- Consent and privacy considerations
- Scope and limits of this approach

### Stretch Goals

- Merge the classic and FID collectors into one event stream (study `fanotify_fid_collector.c`)
- Add a minimal eBPF collector for comparison
- Integrate with SIEM systems for enterprise deployment

## Testing and Verification

### Verify the Scorer (two checks)

The C++ daemon implements the scoring used by scikit-learn's Isolation
Forest. The two parity checks compare implementations, but cover different
parts of the pipeline:

```bash
# 1. Any machine. Does the exported JSON score the same way scikit-learn does?
#    Runs a Python copy of the tree walk. Does NOT run any C++.
uv run python python/verify_parity.py

# 2. Linux, after building. Does the real daemon compute the same six features
#    and the same score as Python, event by event?
uv run python python/verify_cpp_parity.py --daemon build/file_defender_daemon
```

Run both after changing a feature definition. Only the second one can catch a mismatch between `feature_window.cpp` and `features.py`.

### Look Inside a Model

```bash
uv run python python/inspect_model.py
```

This prints the number and depth of the trees and the features used in their
splits. It also changes one input feature at a time to show how the scores
respond.

## Repository Layout

```text
src/collector/   fanotify_collector.c     (primary: reads/writes + content)
                 fanotify_fid_collector.c (worked example: rename/delete/create)
                 inotify_demo.c           (teaching comparison)
src/daemon/      main.cpp, feature_window.*, anomaly_model.* (Isolation Forest)
src/common/      file_event.hpp (shared event schema)
python/          features, simulator, trainer, two parity checks
                 (verify_parity.py, verify_cpp_parity.py), inspect_model.py
                 (see "Detector Experiments" below for the research modules)
testdata/        sample_events.csv, attack_scenario.csv (demos),
                 benign_baseline.csv (training)
models/          trained model output (model.json, model.joblib)
docs/            SAFETY_AND_SCOPE.md, ENTROPY_AND_ML_EXPLAINED.md,
                 WHY_ISOLATION_FOREST.md, ABOUT_THE_TREE.md,
                 EXPERIMENTS_AND_FINDINGS.md
```

### Detector Experiments

These modules run separately from the monitoring pipeline. They test the
current design against alternatives without modifying it. See
[`docs/EXPERIMENTS_AND_FINDINGS.md`](docs/EXPERIMENTS_AND_FINDINGS.md) for the
measured results.

```text
score_smoother.py               EWMA and CUSUM aggregation over the score stream
demo_temporal_aggregation.py    attack-pace sweep: what does that aggregation buy?
baseline_detectors.py           robust z-score and Mahalanobis detectors
extended_isolation_forest.py    Isolation Forest with oblique cuts
compare_detectors.py            four-way comparison at one false-positive budget
evaluation.py                   labeled features, shared thresholds, metrics
simulate_realistic_baseline.py  a benign baseline hard enough to tell detectors apart
subsample_sweep.py              what the subsample size does, in two settings
```

Every table in the docs comes from one of these commands:

```bash
uv run python python/demo_temporal_aggregation.py
uv run python python/compare_detectors.py --paces 600 300 120 60 30 --seeds 5
uv run python python/extended_isolation_forest.py
uv run python python/subsample_sweep.py
uv run python python/inspect_model.py
```

## Common Questions

### Can this detect my specific ransomware?

File Defender learns from benign activity and looks for windows that differ
from it. It is not trained on particular ransomware samples. The aim is to
recognize new attacks that show the file-access patterns described above.

### Does it require root?

- **Collector:** Yes, needs `CAP_SYS_ADMIN` to use `fanotify`
- **Daemon:** No, runs as a regular user
- **Training:** No

### What if a legitimate process has high entropy?

It may cause a false alarm. Image and video processing, database work,
compression, and saving a `.docx` file can all produce high entropy; a
`.docx` is itself a ZIP archive. The forest considers its usable features
together, so high entropy alone may not be enough to trigger an alert.

The harder cases in
[`docs/EXPERIMENTS_AND_FINDINGS.md`](docs/EXPERIMENTS_AND_FINDINGS.md) are
`git gc` and a `restic` backup run. In the simulated data, `restic` triggers
all four detectors. `git` triggers three; the robust z-score rule does not
flag it.

### Can I use this for live protection?

Not yet. Live mode works, and `--stop` can pause a flagged process, but this
is not a system to rely on for protecting important files. The results are
from simulations. The collectors are not merged, leaving
`rename_delete_rate` at zero in the live setup above, and the shipped model
ignores two of its six inputs.

Use live mode to observe the detector and collect a baseline in alert-only
mode, on a machine with backups. Read `docs/SAFETY_AND_SCOPE.md` before
enabling `--stop`.

### How do I deploy this?

This project is intended for research and teaching. Work toward production
use would need to consider:

- Integrating with existing security monitoring (SIEM)
- Tuning on your organization's specific baseline
- Combining with other detection methods
- Regular model retraining as normal operations evolve

## Key Insights

1. **Isolation Forest learns from benign data only** - no ransomware samples needed
2. **Behavioral features are language-agnostic** - works regardless of file type or OS language
3. **Process ID enables defense** - can pause the attacker, not just alert
4. **Entropy detection is fast** - Shannon entropy is O(n) in file size
5. **Lightweight C++ daemon** - no Python runtime or ML libraries needed at runtime
6. **Teaching-first design** - code is written for clarity and learning, not maximum compression

## Next Steps

1. **Run the offline demo** - familiarize yourself with the pipeline
2. **Read the code** - start with `python/features.py` and `src/daemon/feature_window.cpp`
3. **Understand the entropy math** - [`docs/ENTROPY_AND_ML_EXPLAINED.md`](docs/ENTROPY_AND_ML_EXPLAINED.md) works it through by hand
4. **Examine the model choice** - read the reasons in
   [`docs/WHY_ISOLATION_FOREST.md`](docs/WHY_ISOLATION_FOREST.md), follow one
   tree in [`docs/ABOUT_THE_TREE.md`](docs/ABOUT_THE_TREE.md), then compare
   the results in
   [`docs/EXPERIMENTS_AND_FINDINGS.md`](docs/EXPERIMENTS_AND_FINDINGS.md)
5. **Modify and experiment** - change thresholds, add features, tune parameters
6. **Collect your own data** - train on your real workflow
7. **Deploy cautiously** - understand what it detects before enabling auto-pause
