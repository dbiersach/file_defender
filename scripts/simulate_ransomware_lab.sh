#!/usr/bin/env bash
#
# simulate_ransomware_lab.sh
#
# A SAFE test-workload generator for File Defender. It is NOT ransomware.
#
# It mimics the file-access PATTERN of ransomware - read a file, write a
# high-entropy ".locked" copy, delete the original, rapidly across several
# directories - so the detector has a realistic process to flag. It is boxed
# in so that it can only ever touch files it made itself:
#
#   - It works ONLY inside one lab directory (default ~/ransomware_lab), and
#     refuses to run if that path is your home directory or the disk root.
#   - It marks the directory it creates with a hidden marker file. Every mode,
#     including --clean, refuses to touch a directory that lacks the marker.
#   - It refuses to run if any decoy it is about to write already exists, or
#     if any directory on the way is a symbolic link. So a file you placed in
#     the lab folder is never read, overwritten, or deleted by a normal run.
#   - --clean deletes the whole lab directory, but only if the marker is
#     present. Do not store anything you care about in a marked lab folder.
#   - No persistence, no spreading, no network, no privilege changes.
#
# This script is the one place in the project that writes random-looking
# bytes and deletes files. docs/SAFETY_AND_SCOPE.md explains why that is
# allowed here and nowhere else.
#
# Usage:
#   ./scripts/simulate_ransomware_lab.sh           # run the simulation
#   ./scripts/simulate_ransomware_lab.sh --clean   # delete the lab directory
#
# Typical test (two terminals):
#   terminal 1:  sudo ./build/fanotify_collector "$HOME" \
#                    | ./build/file_defender_daemon --model models/model.json --notify
#   terminal 2:  ./scripts/simulate_ransomware_lab.sh
#
set -euo pipefail

# Resolve the lab path once, following symlinks, so the guards below compare
# real locations rather than strings.
LAB_DIR="$(realpath -m "${LAB_DIR:-$HOME/ransomware_lab}")"
HOME_REAL="$(realpath -m "$HOME")"
MARKER="$LAB_DIR/.file_defender_lab"

subdirs=(documents pictures music desktop projects)
decoys_per_dir=5

# --- Guard 1: never operate on a real location -----------------------------
if [[ -z "$LAB_DIR" || "$LAB_DIR" == "/" || "$LAB_DIR" == "$HOME_REAL" ]]; then
    echo "Refusing to run: lab directory resolves to a real location ($LAB_DIR)." >&2
    exit 1
fi

# --- Guard 2: only ever work in a directory this script created -------------
# The marker proves the folder belongs to this script. Every mode checks it.
if [[ -e "$LAB_DIR" && ! -f "$MARKER" ]]; then
    echo "Refusing to run: $LAB_DIR exists but was not created by this script." >&2
    echo "Move it aside or set LAB_DIR to an empty location." >&2
    exit 1
fi

# --- Optional cleanup mode --------------------------------------------------
if [[ "${1:-}" == "--clean" ]]; then
    if [[ -f "$MARKER" ]]; then
        rm -rf "$LAB_DIR"
        echo "Removed $LAB_DIR"
    else
        echo "Nothing to clean ($LAB_DIR does not exist)"
    fi
    exit 0
fi

echo "File Defender - SAFE ransomware-behavior simulator"
echo "Lab directory: $LAB_DIR"
echo "This only ever touches decoy files it creates inside that directory."
echo

# --- Guard 3: refuse to overwrite anything, and refuse to follow symlinks ---
# Check every path this run will write BEFORE writing any of them, so a
# collision stops the script with nothing changed.
if [[ -L "$LAB_DIR" ]]; then
    echo "Refusing to run: $LAB_DIR is a symbolic link." >&2
    exit 1
fi
for d in "${subdirs[@]}"; do
    if [[ -L "$LAB_DIR/$d" ]]; then
        echo "Refusing to run: $LAB_DIR/$d is a symbolic link." >&2
        exit 1
    fi
    for i in $(seq 1 "$decoys_per_dir"); do
        for candidate in "$LAB_DIR/$d/file_$i.txt" "$LAB_DIR/$d/file_$i.txt.locked"; do
            if [[ -e "$candidate" || -L "$candidate" ]]; then
                echo "Refusing to run: $candidate already exists." >&2
                echo "Run with --clean first, or set LAB_DIR to an empty location." >&2
                exit 1
            fi
        done
    done
done

mkdir -p "$LAB_DIR"
touch "$MARKER"

# --- 1) Create decoy files with ordinary (low-entropy) text content ---------
# A bounded loop, not `yes | head`: with `pipefail` a `yes` process killed by
# a broken pipe makes the whole pipeline fail and `set -e` stops the script.
write_decoy() {
    local target="$1"
    local line
    for line in $(seq 1 200); do
        echo "The quick brown fox jumps over the lazy dog. "
    done > "$target"
}

echo "Creating decoy files across ${#subdirs[@]} directories..."
for d in "${subdirs[@]}"; do
    mkdir -p "$LAB_DIR/$d"
    for i in $(seq 1 "$decoys_per_dir"); do
        write_decoy "$LAB_DIR/$d/file_$i.txt"
    done
done

# --- 2) Mimic the encryption sweep: read -> high-entropy write -> delete ----
# Only the decoys created above are named here. Nothing else is touched.
echo "Simulating an encryption sweep (the detector should alert on this)..."
count=0
for d in "${subdirs[@]}"; do
    for i in $(seq 1 "$decoys_per_dir"); do
        original="$LAB_DIR/$d/file_$i.txt"
        cat "$original" > /dev/null                        # read the original
        head -c 65536 /dev/urandom > "$original.locked"    # high-entropy "encrypted" copy
        rm -f "$original"                                   # delete the original
        count=$((count + 1))
        sleep 0.05                                          # rapid, but observable
    done
done

echo
echo "Done. Encrypted-and-deleted $count decoy files."
echo "Clean up afterwards with: $0 --clean"
