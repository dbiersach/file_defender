# File Defender - Coding Style Guide

These instructions define the expected coding and documentation style for this
project (C, C++, and Python). The goal is clarity, consistency, and strong
teaching value for a student learning systems programming and machine learning.

---

## General principles

- Code should be **clear, explicit, and readable**.
- Prefer **teaching-oriented explanations** over compact or clever code.
- Write as if the reader is a **student learning the concept for the first time**.
- This is a **defensive** project. Never add code that creates, encrypts,
  corrupts, or mass-modifies files. See `docs/SAFETY_AND_SCOPE.md`.

---

## File and identifier naming

- Files: lowercase `snake_case` (`fanotify_collector.c`, `feature_window.cpp`).
- C/C++: `snake_case` for functions and variables, `PascalCase` for C++ types
  (`FeatureWindow`, `AnomalyModel`), `UPPER_CASE` for constants and macros.
- Python: follow PEP 8 (`snake_case`), with type hints on reusable functions.

---

## C and C++

- C targets **C17**, C++ targets **C++17**. Build with clang via CMake.
- Compile cleanly under `-Wall -Wextra` (the daemon also uses `-Wpedantic`).
- Every source file starts with a comment explaining what it does and why.
- Check the return value of every system call; print a helpful message on error.
- Free what you allocate and close what you open (file descriptors especially).
- Keep functions short and single-purpose. Prefer clear names over comments that
  restate the code; use comments to explain intent and the "why".
- Formatting is handled by clang-format via the clangd extension.

## Python

- Target **Python 3.12**. Use type hints on reusable functions.
- Use NumPy-style or short one-line docstrings.
- Imports: standard library, then third-party, then local.
- Formatting and import order are handled by **Ruff** (`ruff format`,
  `ruff check`). Code must pass `ruff check` with no errors.

---

## Keeping the feature definition in sync

The six behavioral features are defined in **three** places that MUST agree:

1. `python/features.py` (training)
2. `src/daemon/feature_window.cpp` (live scoring)
3. `python/simulate_activity.py` (synthetic data)

If you change a feature, change it in all three and re-run
`python/verify_parity.py`.

---

## Comments and writing style

- Comments must be **functional and explanatory** (purpose, math, intent).
- Avoid decorative comments and comments that restate obvious code.
- Use normal hyphens `-`, not em dashes.

---

## Summary

All code in this repository should be easy to read, easy to teach from, clearly
explain both **how** and **why**, and stay strictly within the project's
defensive scope.
