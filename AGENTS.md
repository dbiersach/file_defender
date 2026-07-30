# File Defender C, C++, and Python Style Guide

These instructions define the expected coding and documentation style for all C
(`.c`), C++ (`.cpp`, `.hpp`), and Python (`.py`) sources in this repository.

The goal is clarity, consistency, and strong pedagogical value.

---

## General Principles

- Code should be **clear, explicit, and readable**.
- Prefer **teaching-oriented explanations** over compact or clever code.
- Write as if the reader is a **student learning the concept for the first time**.
- Avoid unnecessary abstraction unless it improves understanding.
- This is a **defensive** project. Never add code that creates, encrypts,
  corrupts, or mass-modifies files. See `docs/SAFETY_AND_SCOPE.md`.

---

## File Naming

- Use lowercase `snake_case` for all files.
- File names should be **descriptive and topic-based**.

Examples:

- `fanotify_collector.c`
- `feature_window.cpp`
- `train_isolation_forest.py`

---

## Python Code Style

### Type Hints

- Use type hints for all reusable functions and classes
- Prefer modern Python 3.12 syntax:

```python
float | np.ndarray
list[str]
tuple[np.ndarray, ...]
```

Python 3.12 rather than a later release because Linux Mint 22.3 ships 3.12, and
`pyproject.toml` pins `requires-python = ">=3.12,<3.13"` to match the machine
the daemon is built on.

---

### Docstrings

- Use **NumPy-style docstrings** for reusable functions in `.py` files

Example:

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

- Short helper functions may use one-line docstrings:

```python
def square(x: float) -> float:
    """Return x squared."""
```

---

## C and C++ Code Style

- C targets **C17**, C++ targets **C++17**. Build with clang via CMake; the
  `default` CMake preset pins `clang`/`clang++` (`cmake --preset default`).
- Compile cleanly under `-Wall -Wextra` (the daemon also uses `-Wpedantic`).
- Every source file starts with a comment explaining what it does and why.
- Check the return value of every system call; print a helpful message on error.
- Free what you allocate and close what you open (file descriptors especially).
- Keep functions short and single-purpose.

### Identifier Naming

- `snake_case` for functions and variables
- `PascalCase` for C++ types (`FeatureWindow`, `AnomalyModel`)
- `UPPER_CASE` for constants and macros

---

## Imports

Follow this order:

1. Standard library
2. Third-party packages
3. Local modules

Use standard aliases:

```python
import numpy as np
import pandas as pd
```

---

## Comments and Writing Style

- Comments must be **functional and explanatory**
- Focus on:
  - Purpose of the code
  - Mathematical meaning
  - Instructions to the reader/student

### Avoid

- Decorative or stylistic comments
- Redundant comments that restate obvious code
- Em dashes or long dashes

Instead:

- Use normal hyphens `-`
- Or rewrite the sentence for clarity

---

## Variable Naming

- Use **clear, descriptive names**
- Avoid overly short or cryptic variables unless standard (e.g., `x`, `t`)
- Prefer readability over brevity

---

## Formatting

- Python code must be compatible with:
  - Ruff
  - Black

- C and C++ formatting is handled by clang-format via the clangd extension
- Follow consistent spacing and formatting
- Avoid overly dense code blocks

Python formatting and import order are handled by `ruff format` and
`ruff check`. Code must pass `ruff check` with no errors.

---

## Keeping the Feature Definition in Sync

The six behavioral features are defined in **three** places that MUST agree:

1. `python/features.py` (training)
2. `src/daemon/feature_window.cpp` (live scoring)
3. `python/simulate_activity.py` (synthetic data)

If you change a feature, change it in all three and re-run
`python/verify_parity.py`.

---

## Math in Markdown Documents

The docs in `docs/` use GitHub-flavored math, which renders on GitHub and in the
VS Code Markdown preview:

```markdown
$$H = -\sum_{i=0}^{255} p_i \, \log_2(p_i)$$
```

Keep using `$...$` and `$$...$$` in `.md` files. See `CLAUDE.md` for why chat
replies are the one place that must not use LaTeX.

---

## Jupyter Notebooks

This repository has no notebooks today. The rules below apply if one is added,
so that a notebook here matches the ones in the companion courseware
repositories.

### First Code Cell

The first code cell must begin with a short docstring containing the notebook
filename:

```python
"""example_notebook.ipynb"""
```

---

### Cell Labeling

Each code cell should be labeled with a structured comment:

```python
# Cell 01 - Import packages
# Cell 02 - Define helper functions
# Cell 03 - Run simulation
```

Guidelines:

- Use two-digit numbering (`01`, `02`, etc.)
- Keep descriptions short and meaningful

---

### Markdown Cell Structure

Every markdown cell after the first one in a notebook must begin with a
horizontal rule on its own line, followed by a `###` header:

```markdown
---
### Setup: simulation parameters

The simulation runs from ...
```

The rule draws a visible line between the cell and the output of the code cell
above it, which otherwise run together in the notebook view.

Header rules:

- Start at `###`. Never use `#` or `##`, which render so large that a short
  heading eats a disproportionate amount of vertical space.
- `###` is the only level used for section headers. Sub-points inside a section
  are made with bold lead-ins or lists, not `####`.
- The very first cell of the notebook is the only exception to the rule: it
  opens directly with its `###` title, since there is no output above it to
  separate.
- A markdown cell that follows another markdown cell still takes the rule. The
  separator doubles as a section break, so it stays even where there is no code
  output above it.

Do not open a markdown cell with a bolded run-in sentence such as
`**Simulation parameters.**`. Write a real `###` header instead.

---

### Every Code Cell Must Display Output

Never write a code cell that produces no visible output. A cell containing
only imports, constants, or function definitions gives the student no feedback
that they ran it. It is easy to skip a silent cell and then hit a `NameError`
in the next one.

When a cell exists mainly to define things, end it with a short check that
exercises what was just defined. Call the new functions on a simple case and
`print()` or `display()` the result next to the expected answer:

```python
# Quick check that the entropy helper works as expected
h = shannon_entropy(bytes(4096))
print(f"shannon_entropy(all zeros) = {h:.2f}  (expected 0.00)")
```

This doubles as a worked example and as proof the cell ran.

Stale saved output is the related hazard. A cell whose code was edited but
never rerun still shows its old result, which reads as if it passed. Rerun
the notebook after editing it.

---

### Markdown + Code Balance

- Use markdown cells to explain:
  - What the code does
  - Why the method is used
  - What the results mean
- Keep explanations **plain, direct, and instructional**
- Avoid overly formal or verbose writing

---

### Notebook Teaching Style

When writing notebooks:

- Break work into logical steps
- Explain transitions between steps
- Clearly interpret results

Good pattern:

1. Introduce concept
2. Show implementation
3. Run code
4. Interpret output

---

## LaTeX for PowerPoint / Word Equation Editor

When I ask for LaTeX to paste into the **Microsoft 365 Equation Editor**
(PowerPoint or Word: Insert -> Equation -> type LaTeX -> Convert to Math /
"build up"), produce **Office-compatible** LaTeX, not general LaTeX. The
Office build-up engine has stricter delimiter rules than a normal LaTeX
compiler and supports no packages at all, so expressions that render fine in
a real LaTeX compiler can "fail miserably" here.

Assume the equation is going into the Equation Editor in **LaTeX input
mode**, and return the raw source in a code block so it can be copied
directly.

### Core rule: delimiters must be balanced by count

Office pairs every opening delimiter (`(`, `[`, `|`, `\langle`, `\lfloor`, ...)
with a matching closer, then builds one auto-sizing bracket object between them.
An **unmatched opener escapes its group** and swallows surrounding content
(e.g. it eats across a fraction bar), producing a mangled result.

- Bad: `\frac{\lvert 1}{2}` - lone `\lvert` has no closer; the bar escapes the
  numerator and wraps the whole fraction.
- Good: `\frac{|1|}{2}` or `\frac{\left|1\right|}{2}` - balanced.

Office does **not** require the two sides to be the *same glyph* - only that
they form one matched `\left ... \right` pair. That is what makes
mixed-delimiter brackets (kets, bras, floors) possible.

### Use `\left ... \right`, not the fixed `\lvert/\rvert` pairs

`\lvert`/`\rvert` (and `\lfloor/\rfloor`, etc.) are **dedicated fixed pairs**:
`\lvert` is hard-wired to seek a matching `\rvert` and will *not* mate with a
different closer. So `\lvert\psi\rangle` fails - `\lvert` wants `\rvert`,
`\rangle` wants `\langle`, and neither finds its partner.

Any bracket whose two sides differ in shape **must** use the generic
`\left ... \right` mechanism, where `\left`/`\right` open/close with whatever
glyph follows and only the count has to balance.

### Never use package-dependent macros

Office has no package system. Anything that a normal LaTeX document would
pull in from `amsmath`, `braket`, or `physics` simply does not exist in the
build-up engine, and the equation fails.

Never emit these:

```latex
\ket{\psi}
\bra{\psi}
\braket{\phi|\psi}
\lvert\psi\rangle
\langle\psi\rvert
```

Write every bracket out longhand with `\left` and `\right` instead.

### Dirac (bra-ket) notation

| Notation | Office-compatible LaTeX |
| --- | --- |
| Ket | `\left\|\psi\right\rangle` |
| Bra | `\left\langle\psi\right\|` |
| Inner product | `\left\langle\phi\middle\|\psi\right\rangle` |
| Matrix element | `\left\langle\phi\middle\|\hat{A}\middle\|\psi\right\rangle` |
| Ket in a fraction | `\frac{\left\|\psi\right\rangle}{\sqrt{2}}` |

Never write a ket with `\lvert` - always `\left|`.

Use `\middle|` for a bar that sits *inside* a bracket pair, as in an inner
product or a matrix element. Splitting the same expression into two separate
pairs, `\left\langle\phi\right|\hat{A}\left|\psi\right\rangle`, also builds
correctly, but `\middle|` keeps it as one group so every glyph grows to the
same height.

Keep the delimiters explicit inside fractions, where a lone bar does the most
damage:

```latex
\frac{\left\langle\psi\middle|\hat{H}\middle|\psi\right\rangle}
{\left\langle\psi\middle|\psi\right\rangle}
```

### Composite states, outer products, and operators

Write a composite ket as one bracket pair:

```latex
\left|00\right\rangle
```

Keep both pairs when the product structure is what matters:

```latex
\left|0\right\rangle\left|1\right\rangle
```

Write outer products out in full, and wrap the whole outer product in
parentheses when it acts on a ket. Add the parentheses even where they are
not mathematically required - they make the operator-action structure
unambiguous to a reader:

```latex
(\left|0\right\rangle\left\langle1\right|)\left|0\right\rangle
```

Preserve that grouping when expanding the operation:

```latex
(\left|0\right\rangle\left\langle1\right|)\left|0\right\rangle
=
\left|0\right\rangle
\left(\left\langle1\middle|0\right\rangle\right)
=
0
```

Parenthesize a compound operator whenever adjacency could be misread:

```latex
(\hat{A}+\hat{B})\left|\psi\right\rangle
```

A single named operator needs no parentheses:

```latex
\hat{U}\left|\psi\right\rangle
```

### Tensor products

Use `\otimes` when the tensor product should be explicit:

```latex
\left|\psi\right\rangle\otimes\left|\phi\right\rangle
```

Do not silently collapse an explicit tensor product into juxtaposition
unless a shorter form was requested.

### Other Office gotchas

- Absolute value: `\left|x\right|` (stretchy) or `|x|` (fixed size, fine for
  short contents).
- Unsupported LaTeX keywords in Office: `\eqarray`, `\Middle`, `\ldiv`,
  `\dsmash`. Capital `\Middle` is unsupported; lowercase `\middle` is the one
  to use. In the rare case it misbehaves, the fallback is all fixed-size
  brackets with a plain separator, `\langle\phi|\psi\rangle`, which keeps the
  delimiter count balanced.
- Recommended reference: Microsoft's "Linear format equations using UnicodeMath
  and LaTeX in Word" support page.

### Output conventions

When asked for "PowerPoint LaTeX", "Microsoft LaTeX", or "Equation Editor
LaTeX":

1. Put the copyable source in a fenced `latex` code block, raw and
   unrendered, so it can be pasted straight into the equation field.
2. Use explicit `\left ... \right` delimiters and explicit parentheses.
3. Use no package-dependent commands.
4. Do not convert the expression to UnicodeMath unless UnicodeMath was
   specifically requested.
5. Where practical, also show the equation rendered normally so the result
   can be checked by eye.

---

## Environment Notes

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

All code in this repository should:

- Be easy to read
- Be easy to teach from
- Clearly explain both **how** and **why**
- Stay strictly within the project's defensive scope
