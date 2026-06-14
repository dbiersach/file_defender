# File Defender

**Utilizing AI in Ransomware Detection via Filesystem Behavior Anomaly Detection**

A defensive cybersecurity research project that detects ransomware by analyzing filesystem behavior anomalies using machine learning (Isolation Forest).

**This project is defensive.** It observes file activity and raises alerts. It contains no ransomware and never encrypts, corrupts, or mass-modifies files. See [`docs/SAFETY_AND_SCOPE.md`](docs/SAFETY_AND_SCOPE.md).

## What File Defender Does

Ransomware typically behaves very differently from normal user activity:
- **Rapid, high-volume file writes** across many directories
- **High-entropy encrypted data** (looks random to statistical analysis)
- **Repeated rename/delete cycles** (e.g., renaming files to `.locked`)
- **Sweeping across file extensions** and directories (trying to encrypt everything)

File Defender watches these behavioral patterns and alerts when a process deviates from normal user behavior. It learns what "normal" looks like from benign activity, so it needs no ransomware samples to detect attacks.

## How It Works

Three pieces, connected by a simple text stream of events:

```
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
- Captures file events: **opens, reads, writes** with actual file content
- For each event, records:
  - Timestamp, user, process name/PID
  - File operation (read, write, create, delete, etc.)
  - File path and size
  - **Shannon byte entropy** of the content (0 = very structured, 8 = random/encrypted)
- Outputs one CSV line per event to stdout

**Why fanotify (not inotify or eBPF)?**

The detector needs two things ordinary `inotify` cannot give: the **process id** that caused each event (to name and pause the attacker) and the **file content** (to measure entropy). `fanotify` provides both from userspace, with no kernel module to write or crash.

There are two fanotify collectors:

- **`fanotify_collector`** (primary) - classic mode: opens, reads, and writes with content for entropy, plus the pid.
- **`fanotify_fid_collector`** (worked example) - FID mode (`FAN_REPORT_DFID_NAME`): the rename, delete, and create events that classic mode misses (for example the `.locked` rename and the deletion of the original). It reports the pid but not content. A complete deployment runs both and merges their streams; the daemon already counts rename/delete events.

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

Each rolling window of one process becomes six numbers that characterize its behavior:

| Feature | Why It Matters | Ransomware Looks Like |
| --- | --- | --- |
| **events per second** | Activity bursts | Spikes (50+ events/sec) |
| **writes per second** | Encryption requires writes | High write rate (10+ writes/sec) |
| **rename/delete rate** | The `.locked` rename pattern | Rapid cycles |
| **average byte entropy** | Encrypted data is random | Approaches 8.0 (max) |
| **unique directory count** | Attack sweeps filesystem | Hundreds of dirs in seconds |
| **unique extension count** | Attack touches all file types | Dozens of extensions |

An **Isolation Forest** learns what benign windows look like and flags windows that are easy to "isolate" (unusual). Benign processes (code editor, browser, etc.) have low, stable values for all of these. Ransomware spikes.

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

Use pre-recorded sample data to test the full pipeline:

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

**What's happening:**
- `benign_baseline.csv` contains typical file activity from normal use
- `sample_events.csv` contains mostly normal activity, plus one process behaving like ransomware
- The daemon trains on benign baseline, then scores the sample data

### Mode 2: Larger Multi-Process Attack Scenario

A scenario that interleaves three benign processes with a `cryptor` process that sweeps 15 files across many directories (read original, write a high-entropy `.locked` copy, delete the original):

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

Watch real filesystem activity on your system. The collector needs root (`CAP_SYS_ADMIN`); the daemon runs as you. Piping them keeps the privileged part small:

```bash
sudo ./build/fanotify_collector "$HOME" \
    | ./build/file_defender_daemon --model models/model.json --notify
```

**Flags:**
- `--notify` - send desktop notifications when anomalies are detected
- `--stop` - pause flagged processes with `SIGSTOP` (can resume with `kill -CONT <pid>`)
- `--max-fpr N` - tune false positive rate (higher = more alerts, lower = fewer alerts)

Add `--stop` to pause a flagged process with `SIGSTOP` (opt-in). A paused process is never killed; resume it with `kill -CONT <pid>`.

## Understanding the Data

### Event CSV Format

Each line is one file operation:

```
timestamp,user,process,pid,operation,path,size,entropy
1623456000,alice,code,1234,write,/home/alice/file.txt,1024,4.5
```

**Fields:**
- `timestamp` - Unix time
- `user` - username
- `process` - process name (from `/proc/[pid]/comm`)
- `pid` - process ID
- `operation` - `open`, `write`, `read`, `create`, `delete`, `rename`
- `path` - full file path
- `size` - file size in bytes
- `entropy` - Shannon entropy (0.0 to 8.0)

### Feature Window

The daemon groups events into **rolling time windows** per process. For a 10-second window, it computes the six features. Older windows slide out; new events slide in.

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

Adjust these parameters to balance **detection latency** vs. **false positives**:
- `--window-size N` - seconds per window (default 10, lower = faster detection, more noise)
- `--max-fpr N` - false positive rate threshold (higher = more alerts)

Study the tradeoff:
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

### Verify the C++ Scorer

The C++ daemon re-implements scikit-learn's Isolation Forest scoring. To ensure they match:

```bash
uv run python python/verify_parity.py
```

This runs the same scoring algorithm in Python and C++, comparing results to within floating-point epsilon. Use this after changing the feature definitions.

## Repository Layout

```
src/collector/   fanotify_collector.c     (primary: reads/writes + content)
                 fanotify_fid_collector.c (worked example: rename/delete/create)
                 inotify_demo.c           (teaching comparison)
src/daemon/      main.cpp, feature_window.*, anomaly_model.* (Isolation Forest)
src/common/      file_event.hpp (shared event schema)
python/          features, simulator, trainer, parity verifier
testdata/        sample_events.csv, attack_scenario.csv (demos),
                 benign_baseline.csv (training)
models/          trained model output (model.json, model.joblib)
docs/            SAFETY_AND_SCOPE.md
```

## Common Questions

### Can this detect my specific ransomware?

File Defender learns what "normal" looks like for your system and flags anomalies. It isn't trained on specific ransomware samples, so it's designed to catch new, unseen attacks with similar behavioral patterns.

### Does it require root?

- **Collector:** Yes, needs `CAP_SYS_ADMIN` to use `fanotify`
- **Daemon:** No, runs as a regular user
- **Training:** No

### What if a legitimate process has high entropy?

This is a potential false positive. Media processing (images, videos), database operations, or compression can produce high entropy. The Isolation Forest learns what's normal in *all six dimensions*—a single high-entropy spike may not be anomalous if other features are typical.

### Can I use this for live protection?

Yes, with the `--stop` flag it can pause suspicious processes. Review `docs/SAFETY_AND_SCOPE.md` for ethical and legal considerations before enabling automatic actions.

### How do I deploy this?

This is a research project with a teaching focus. For production use, consider:
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
3. **Modify and experiment** - change thresholds, add features, tune parameters
4. **Collect your own data** - train on your real workflow
5. **Deploy cautiously** - understand what it detects before enabling auto-pause
