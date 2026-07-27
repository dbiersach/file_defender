# File Defender - Coding Style Guide

These instructions define the expected coding and documentation style for this
project (C, C++, and Python). The goal is clarity, consistency, and strong
teaching value for a student learning systems programming and machine learning.

---

## General principles

- Code should be **clear, explicit, and readable**.
- Prefer **teaching-oriented explanations** over compact or clever code.
- Write as if the reader is a **student learning the concept for the first time**.
- Avoid unnecessary abstraction unless it improves understanding.
- This is a **defensive** project. Never add code that creates, encrypts,
  corrupts, or mass-modifies files. See `docs/SAFETY_AND_SCOPE.md`.

---

## File and identifier naming

- Files: lowercase `snake_case` (`fanotify_collector.c`, `feature_window.cpp`).
- File names should be descriptive and topic-based.
- C/C++: `snake_case` for functions and variables, `PascalCase` for C++ types
  (`FeatureWindow`, `AnomalyModel`), `UPPER_CASE` for constants and macros.
- Python: follow PEP 8 (`snake_case`), with type hints on reusable functions.

---

## C and C++

- C targets **C17**, C++ targets **C++17**. Build with clang via CMake; the
  `default` CMake preset pins `clang`/`clang++` (`cmake --preset default`).
- Compile cleanly under `-Wall -Wextra` (the daemon also uses `-Wpedantic`).
- Every source file starts with a comment explaining what it does and why.
- Check the return value of every system call; print a helpful message on error.
- Free what you allocate and close what you open (file descriptors especially).
- Keep functions short and single-purpose. Prefer clear names over comments that
  restate the code; use comments to explain intent and the "why".
- Formatting is handled by clang-format via the clangd extension.

---

## Python

- Target **Python 3.12**. Use type hints on reusable functions.
- Prefer modern typing syntax: `float | np.ndarray`, `list[str]`,
  `tuple[np.ndarray, ...]`.
- Use NumPy-style docstrings for reusable functions:

```python
def compute_energy(x: np.ndarray) -> float:
    """
    Compute the total energy of the system.

    Parameters
    ----------
    x : np.ndarray
        Input state vector.

    Returns
    -------
    float
        Computed energy value.
    """
```

- Short helper functions may use a one-line docstring:

```python
def square(x: float) -> float:
    """Return x squared."""
```

- Imports: standard library, then third-party, then local. Use the standard
  aliases (`import numpy as np`, `import pandas as pd`).
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
- Use normal hyphens `-`, not em dashes or long dashes. If a sentence needs an
  em dash to work, rewrite the sentence.

---

## Math in Markdown documents

The docs in `docs/` use GitHub-flavored math, which renders on GitHub and in the
VS Code Markdown preview:

```markdown
$$H = -\sum_{i=0}^{255} p_i \, \log_2(p_i)$$
```

Keep using `$...$` and `$$...$$` in `.md` files. See `CLAUDE.md` for why chat
replies are the one place that must not use LaTeX.

---

## LaTeX for PowerPoint / Word Equation Editor

When asked for LaTeX to paste into the **Microsoft 365 Equation Editor**
(Insert -> Equation -> type LaTeX -> Convert to Math), produce
**Office-compatible** LaTeX, not general LaTeX. The Office build-up engine
supports no packages and has stricter delimiter rules, so expressions that
compile fine in real LaTeX can fail here.

- **Delimiters must balance by count.** An unmatched opener escapes its group
  and swallows surrounding content. `\frac{\lvert 1}{2}` breaks;
  `\frac{|1|}{2}` works.
- **Use `\left ... \right`, never `\lvert`/`\rvert`.** The fixed pairs only
  mate with their own partner, so `\lvert\psi\rangle` fails. Any bracket whose
  two sides differ in shape needs `\left`/`\right`.
- **No package-dependent macros.** `\ket{}`, `\bra{}`, and `\braket{}` do not
  exist in Office. Write brackets out longhand.
- Ket: `\left|\psi\right\rangle`. Bra: `\left\langle\psi\right|`.
  Inner product: `\left\langle\phi\middle|\psi\right\rangle`.
- Use lowercase `\middle|` for a bar inside a bracket pair. Capital `\Middle`,
  `\eqarray`, `\ldiv`, and `\dsmash` are unsupported.

Return the raw source in a fenced `latex` code block so it can be pasted
directly, and use explicit parentheses for grouping even where they are not
mathematically required.

---

## Environment notes

These are properties of the development machine, not style rules. They are
recorded here so that time is not lost rediscovering them.

### Reload VS Code after a `uv sync` that changes packages

After any `uv sync` that adds, removes, or upgrades a package, the VS Code
Python extension can keep a handle on the pre-sync environment. Runs then hang
or fail with a stale import, with no useful error message.

- Fix: Command Palette -> **Developer: Reload Window**.
- The cause is the running extension host being pinned to the old environment
  while the contents of `.venv` are swapped underneath it.
- To tell a real hang from this one, run the script outside VS Code with
  `uv run python python/train_isolation_forest.py`. If that succeeds, the
  problem is the extension host, not the code.

### The daemon and collectors are Linux-only

`fanotify`, `inotify`, and the eBPF program require a Linux kernel. They do not
build or run on Windows. The Python side (`python/`) is cross-platform and can
be developed and tested on Windows; the C/C++ side must be built on Linux Mint
or an equivalent distribution.

---

## Summary

All code in this repository should be easy to read, easy to teach from, clearly
explain both **how** and **why**, and stay strictly within the project's
defensive scope.
