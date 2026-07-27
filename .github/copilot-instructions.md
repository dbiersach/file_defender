# File Defender - Copilot Instructions

`AGENTS.md` in the repository root is the full style guide and the source of
truth. Copilot cannot follow file references, so the rules that matter most are
repeated here. When the two disagree, `AGENTS.md` wins.

## What this project is

File Defender is a **defensive** ransomware-detection teaching project. A Linux
collector (`fanotify`/`inotify`/eBPF, in C) feeds file-activity events to a C++
daemon that scores them against an Isolation Forest trained offline in Python.

Never write code that creates, encrypts, corrupts, or mass-modifies files. Never
add evasion, persistence, or payload-delivery behavior. See
`docs/SAFETY_AND_SCOPE.md`.

## General principles

- Code should be clear, explicit, and readable.
- Prefer teaching-oriented explanations over compact or clever code.
- Write as if the reader is a student learning the concept for the first time.
- Avoid unnecessary abstraction unless it improves understanding.

## Naming

- Files: lowercase `snake_case` (`fanotify_collector.c`, `feature_window.cpp`).
- C/C++: `snake_case` for functions and variables, `PascalCase` for C++ types
  (`FeatureWindow`, `AnomalyModel`), `UPPER_CASE` for constants and macros.
- Python: PEP 8 `snake_case`, with type hints on reusable functions.

## C and C++

- C targets C17, C++ targets C++17. Build with clang via CMake
  (`cmake --preset default`).
- Compile cleanly under `-Wall -Wextra`; the daemon also uses `-Wpedantic`.
- Every source file opens with a comment explaining what it does and why.
- Check the return value of every system call and print a helpful error.
- Free what you allocate; close what you open, file descriptors especially.
- Formatting is handled by clang-format through the clangd extension.

## Python

- Target Python 3.12. Use type hints and modern syntax (`float | np.ndarray`,
  `list[str]`).
- NumPy-style docstrings for reusable functions; one-liners for short helpers.
- Imports: standard library, then third-party, then local. Use `np`, `pd`.
- Ruff owns formatting and import order. Code must pass `ruff check` clean.

## The feature parity rule

The six behavioral features are defined in three places that MUST agree:

1. `python/features.py` (training)
2. `src/daemon/feature_window.cpp` (live scoring)
3. `python/simulate_activity.py` (synthetic data)

Change one, change all three, then re-run `python/verify_parity.py`.

## Comments and prose

- Comments explain purpose, math, and intent - never restate the code.
- Use normal hyphens `-`, not em dashes.
- Markdown in `docs/` uses GitHub-flavored `$...$` and `$$...$$` math.
