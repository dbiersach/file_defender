#!/usr/bin/env bash
#
# simulate_ransomware_lab.sh
#
# A SAFE test-workload generator for File Defender. It is NOT ransomware.
#
# It mimics the file-access PATTERN of ransomware - read a file, write a
# high-entropy ".locked" copy, delete the original, rapidly across several
# directories - so the detector has a realistic process to flag. But it is
# completely harmless:
#
#   - It works ONLY inside a dedicated lab directory (default ~/ransomware_lab).
#   - It creates its own throwaway decoy files first; it never reads, encrypts,
#     or deletes any of your real data.
#   - No persistence, no spreading, no network, no privilege changes.
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

LAB_DIR="$HOME/ransomware_lab"

# --- Optional cleanup mode ---
if [[ "${1:-}" == "--clean" ]]; then
    if [[ -d "$LAB_DIR" ]]; then
        rm -rf "$LAB_DIR"
        echo "Removed $LAB_DIR"
    else
        echo "Nothing to clean ($LAB_DIR does not exist)"
    fi
    exit 0
fi

# --- Safety guards: never operate anywhere except the dedicated lab folder ---
if [[ "$LAB_DIR" == "$HOME" || "$LAB_DIR" == "/" ]]; then
    echo "Refusing to run: lab directory resolves to a real location ($LAB_DIR)." >&2
    exit 1
fi

echo "File Defender - SAFE ransomware-behavior simulator"
echo "Lab directory: $LAB_DIR"
echo "This only ever touches files inside that directory."
echo

# --- 1) Create decoy files with ordinary (low-entropy) text content ---
subdirs=(documents pictures music desktop projects)
echo "Creating decoy files across ${#subdirs[@]} directories..."
for d in "${subdirs[@]}"; do
    mkdir -p "$LAB_DIR/$d"
    for i in $(seq 1 5); do
        target="$LAB_DIR/$d/file_$i.txt"
        yes "The quick brown fox jumps over the lazy dog. " | head -n 200 > "$target"
    done
done

# --- 2) Mimic the encryption sweep: read -> high-entropy write -> delete ---
echo "Simulating an encryption sweep (the detector should alert on this)..."
count=0
for original in "$LAB_DIR"/*/*.txt; do
    cat "$original" > /dev/null                        # read the original
    head -c 65536 /dev/urandom > "$original.locked"    # high-entropy "encrypted" copy
    rm -f "$original"                                   # delete the original
    count=$((count + 1))
    sleep 0.05                                          # rapid, but observable
done

echo
echo "Done. Encrypted-and-deleted $count decoy files."
echo "Clean up afterwards with: $0 --clean"
