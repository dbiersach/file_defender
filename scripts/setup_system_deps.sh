#!/usr/bin/env bash
#
# One-time system setup for the file_defender project on Linux Mint 22.3
# (Ubuntu 24.04 base). Installs the compilers, libraries, and tools needed to
# build the C/C++ collector and daemon and to run the Python ML pipeline.
#
# Usage:
#   bash scripts/setup_system_deps.sh
#
set -euo pipefail

echo "==> Installing build tools and libraries (sudo required)"
sudo apt update
sudo apt install -y \
    build-essential \
    clang \
    clangd \
    lldb \
    cmake \
    git \
    nlohmann-json3-dev \
    libnotify-bin \
    python3 \
    python3-venv

echo "==> Installing uv (Python package manager) if missing"
if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # shellcheck disable=SC1090
    [ -f "$HOME/.local/bin/env" ] && source "$HOME/.local/bin/env"
fi

echo "==> Creating the Python environment from uv.lock"
uv sync

cat <<'EOF'

System setup complete.

Next steps:
  1. Build the C/C++ programs:
       cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
       cmake --build build -j"$(nproc)"

  2. Train a model on the included benign baseline:
       uv run python python/train_isolation_forest.py \
           --events testdata/benign_baseline.csv \
           --out models/model.json --joblib models/model.joblib

  3. Run the offline demo (should flag only the "unknown_process" ransomware):
       ./build/file_defender_daemon \
           --events testdata/sample_events.csv --model models/model.json

  4. Try live monitoring (collector needs root; daemon runs as you):
       sudo ./build/fanotify_collector "$HOME" | \
           ./build/file_defender_daemon --model models/model.json --notify
EOF
