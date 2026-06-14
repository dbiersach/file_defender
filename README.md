# File Defender

**Utilizing AI in Ransomware Detection via Filesystem Behavior Anomaly Detection**

A defensive cybersecurity research project. It detects file-system activity that
does not match a user's normal routine, the behavioral fingerprint of
ransomware: rapid, high-entropy writes across many directories.

This project is **defensive**. It observes file activity and raises alerts. It
contains no ransomware and never encrypts, corrupts, or mass-modifies files.
See [`docs/SAFETY_AND_SCOPE.md`](docs/SAFETY_AND_SCOPE.md).

## How it works

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

1. **Collector (C, `src/collector/`)** - watches the filesystem and prints one
   CSV line per event: timestamp, user, process name, **pid**, operation, path,
   size, and the **Shannon byte entropy** of the content.
2. **Daemon (C++, `src/daemon/`)** - keeps a rolling behavioral feature window
   **per process**, scores each window with the trained model, and alerts when a
   process looks anomalous. It can optionally pause the process with `SIGSTOP`.
3. **Trainer (Python, `python/`)** - trains a scikit-learn Isolation Forest on
   benign activity and exports it to JSON so the daemon can score without Python.

### Why fanotify (not inotify or eBPF)?

The detector needs two things ordinary `inotify` cannot give: the **process id**
that caused each event (to name and pause the attacker) and the **file content**
(to measure entropy). `fanotify` provides both from userspace, with no kernel
module to write or crash. `inotify` is included as a small teaching comparison
(`inotify_demo`), and `eBPF` is noted as an advanced stretch goal. See the
header comment in `src/collector/fanotify_collector.c` for details.

There are two fanotify collectors:

- **`fanotify_collector`** (primary) - classic mode: opens, reads, and writes
  with content for entropy, plus the pid.
- **`fanotify_fid_collector`** (worked example) - FID mode
  (`FAN_REPORT_DFID_NAME`): the rename, delete, and create events that classic
  mode misses (for example the `.locked` rename and the deletion of the
  original). It reports the pid but not content. A complete deployment runs both
  and merges their streams; the daemon already counts rename/delete events.

### The behavioral features

Each rolling window of one process becomes six numbers (defined once in
`python/features.py` and mirrored in `src/daemon/feature_window.cpp`):

| Feature | Ransomware tends to... |
| --- | --- |
| events per second | spike |
| writes per second | spike |
| rename/delete rate | spike (the `.locked` rename) |
| average byte entropy | approach 8.0 (encrypted data) |
| unique directory count | sweep many directories |
| unique extension count | touch many file types |

An **Isolation Forest** learns what benign windows look like and flags windows
that are easy to "isolate" (unusual). It is trained only on benign data, so it
needs no ransomware samples to work.

## Platform

- Linux Mint 22.3 (Ubuntu 24.04 base, kernel 6.x), Intel x64
- clang / clangd, CMake, LLDB
- Python 3.12, managed with [uv](https://docs.astral.sh/uv/)
- VS Code

## Setup

```bash
# 1. System packages, uv, and the Python environment
bash scripts/setup_system_deps.sh

# 2. VS Code extensions
bash install_vscode_extensions.sh

# 3. Build the C/C++ programs (the preset pins the clang toolchain)
cmake --preset default
cmake --build --preset default -j"$(nproc)"
```

The `default` preset (see `CMakePresets.json`) pins `clang`/`clang++` and a
Debug build into `build/`, so the compiler matches the rest of the LLVM
toolchain (clangd, clang-tidy, clang-format, LLDB) and a contributor's default
`cc` cannot silently swap it. To build with a different compiler, override it
explicitly, e.g. `cmake -S . -B build -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++`.

Open `file_defender.code-workspace` in VS Code (or open the folder; the
`.vscode/` settings apply either way).

## Quick offline demo (no root needed)

This uses recorded sample data, so it runs anywhere.

```bash
# Train on a benign baseline (ordinary activity)
uv run python python/train_isolation_forest.py \
    --events testdata/benign_baseline.csv \
    --out models/model.json --joblib models/model.joblib

# Score a scenario where one process behaves like ransomware
./build/file_defender_daemon \
    --events testdata/sample_events.csv --model models/model.json
```

Expected: only `unknown_process` (pid 4242) is flagged; `code`, `libreoffice`,
and `firefox` are not.

### A larger, multi-process scenario

`testdata/attack_scenario.csv` interleaves three benign processes with a
`cryptor` process that sweeps 15 files across many directories (read original,
write a high-entropy `.locked` copy, delete the original). Regenerate it with
`uv run python python/simulate_activity.py --write-scenario testdata/attack_scenario.csv`.

```bash
./build/file_defender_daemon \
    --events testdata/attack_scenario.csv --model models/model.json
```

Expected: only `cryptor` (pid 6666) is flagged.

## Live monitoring

The collector needs root (`CAP_SYS_ADMIN`); the daemon runs as you. Piping them
keeps the privileged part small:

```bash
sudo ./build/fanotify_collector "$HOME" \
    | ./build/file_defender_daemon --model models/model.json --notify
```

Add `--stop` to pause a flagged process with `SIGSTOP` (opt-in). A paused
process is never killed; resume it with `kill -CONT <pid>`.

## Verifying the C++ scorer

The C++ daemon re-implements scikit-learn's Isolation Forest scoring. Because it
cannot be compiled on every machine, `python/verify_parity.py` re-implements the
exact same algorithm the C++ uses and checks it matches scikit-learn to within
floating-point epsilon:

```bash
uv run python python/verify_parity.py
```

## Suggested development phases

1. **Offline first** - run the demo above; read and modify the feature code.
2. **Record a baseline** - run the collector during ordinary use to gather your
   own benign data, then retrain.
3. **Tune detection** - adjust the window length and `--max-fpr`; study the
   trade-off between false positives and detection latency.
4. **Live defense** - run the collector and daemon together; test `--notify`.
5. **Ethics review** - decide when software should alert vs. act. See
   `docs/SAFETY_AND_SCOPE.md`.
6. **Stretch goals** - merge the classic and FID collectors into one event
   stream (study `fanotify_fid_collector.c`), or add a minimal eBPF collector.

## Repository layout

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
