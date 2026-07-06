# Entropy and the Machine-Learning Pipeline, Explained

*A step-by-step companion to the File Defender research project.*

This document answers four questions, in order:

1. **What does "entropy" actually mean?** (the concept)
2. **How is entropy calculated?** (the math, worked by hand)
3. **How does entropy get into `sample_events.csv`?** (the data path)
4. **How does the whole machine-learning protocol work?** (training → export → scoring → alert)

It is written to be read top to bottom by a student who has seen some C++ and AP Calculus but has not studied information theory or machine learning before. Every claim points back to a real file in this repository so you can check it yourself.

---

## Part 1 — What "Entropy" Means

### The one-sentence version

**Entropy measures how unpredictable a chunk of data is.** Low entropy = predictable and structured (like English text or a spreadsheet). High entropy = looks completely random (like encrypted or compressed data).

### Why a ransomware detector cares

When ransomware attacks, it reads your normal files and writes back **encrypted** versions. Encryption is *designed* to make output look like random noise — that is the whole point of good encryption, because any visible pattern would be a weakness an attacker could exploit. So the encrypted file has **very high entropy**.

This gives us a physical fingerprint we can measure without ever knowing which ransomware family is attacking:

| Kind of data | Typical entropy (bits/byte) | Why |
| --- | --- | --- |
| A file of all zeros | 0.0 | Perfectly predictable — every byte is the same |
| Plain English text | ~4.0 – 4.5 | Only ~26 letters + spaces are common; `e` and `t` dominate |
| An office document / PDF | ~4.5 – 6.0 | Structured, with headers and repeated tokens |
| A JPEG or MP4 (already compressed) | ~7.0 – 7.9 | Compression already removed most redundancy |
| **Encrypted / ransomware output** | **~7.9 – 8.0** | Statistically indistinguishable from random |

The `README.md` states the rule the project relies on: *"0 = very structured, 8 = random/encrypted... A sudden jump toward 8.0 on many files is a hallmark of ransomware."*

### Why the scale stops at 8

Entropy here is measured in **bits per byte**. A byte can hold one of 256 different values (0–255). The most unpredictable a single byte can possibly be is when all 256 values are equally likely. It takes exactly **log₂(256) = 8 bits** to describe one of 256 equally likely outcomes. So **8.0 is the mathematical maximum** for byte entropy, and encrypted data pushes right up against that ceiling.

Think of entropy as answering: *"On average, how many yes/no questions would I need to ask to guess the next byte?"* For a file of all zeros, zero questions — you already know it's zero. For truly random bytes, a full 8 questions every time.

---

## Part 2 — How Entropy Is Calculated

The project uses **Shannon entropy**, named after Claude Shannon, who founded information theory in 1948. The real implementation lives in [`src/collector/fanotify_collector.c`](../src/collector/fanotify_collector.c#L63-L82) in the function `shannon_entropy`. Here is that exact function:

```c
static double shannon_entropy(const unsigned char *data, size_t length) {
    if (length == 0) {
        return 0.0;
    }

    size_t counts[256] = {0};              // how many times each byte value appears
    for (size_t i = 0; i < length; i++) {
        counts[data[i]]++;
    }

    double entropy = 0.0;
    for (int symbol = 0; symbol < 256; symbol++) {
        if (counts[symbol] == 0) {
            continue;                       // a value that never appears adds nothing
        }
        double p = (double)counts[symbol] / (double)length;   // probability of this byte
        entropy -= p * log2(p);             // Shannon's formula, one term per byte value
    }
    return entropy;
}
```

### The formula

$$H = -\sum_{i=0}^{255} p_i \, \log_2(p_i)$$

Read it in plain English:

- For each possible byte value `i` (there are 256 of them, 0 through 255)…
- `p_i` is the **fraction of the file that is that byte value** (its probability).
- `log₂(p_i)` is negative (because probabilities are ≤ 1), so `-p_i · log₂(p_i)` is a positive contribution.
- **Add up all 256 contributions.** That sum is the entropy.

### The three-step recipe the code follows

1. **Count.** Walk through the bytes and tally how many times each of the 256 possible values appears (`counts[256]`).
2. **Convert counts to probabilities.** For each value, `p = count / length`.
3. **Sum `-p · log₂(p)`** over every value that actually appears. (Values that never appear contribute nothing, which is why the code `continue`s when `counts[symbol] == 0` — this also avoids `log₂(0)`, which is undefined.)

### Worked example #1: a boring, structured file

Suppose a tiny 8-byte file contains: `A A A A A A A B`

- The byte `A` appears 7 times → p(A) = 7/8 = 0.875
- The byte `B` appears 1 time → p(B) = 1/8 = 0.125

$$H = -\big(0.875 \cdot \log_2 0.875\big) - \big(0.125 \cdot \log_2 0.125\big)$$
$$H = -(0.875 \cdot -0.1926) - (0.125 \cdot -3.0)$$
$$H = 0.1685 + 0.375 = \mathbf{0.544 \text{ bits/byte}}$$

Very low — almost all bytes are the same, so the file is highly predictable.

### Worked example #2: a maximally random file

Suppose an 8-byte file contains 8 **different** byte values, each appearing once:

- Each of the 8 values has p = 1/8 = 0.125
- `log₂(0.125) = -3`, so each term is `-(0.125)(-3) = 0.375`
- There are 8 such terms: `H = 8 × 0.375 = 3.0 bits/byte`

With only 8 bytes the ceiling is log₂(8) = 3.0, and we hit it exactly. Scale this up: a 4096-byte file in which all 256 byte values appear about equally often approaches the true ceiling of **8.0 bits/byte** — that is what encrypted output looks like.

### One practical detail: sampling

Reading an entire 2 GB video just to measure entropy would be slow. The collector reads only the **first 4096 bytes** of each file and measures the entropy of that sample:

```c
#define ENTROPY_SAMPLE_BYTES 4096
...
unsigned char sample[ENTROPY_SAMPLE_BYTES];
ssize_t sampled = pread(meta->fd, sample, sizeof(sample), 0);   // read up to 4096 bytes
double entropy = (sampled > 0) ? shannon_entropy(sample, (size_t)sampled) : 0.0;
```

4096 bytes is plenty to estimate randomness reliably, and it keeps the detector fast — the README lists *"Entropy detection is fast — Shannon entropy is O(n) in file size"* as a key design win. (The cost is linear in the number of bytes examined, and we cap that at 4096.)

---

## Part 3 — How Entropy Gets Into `sample_events.csv`

There are **two different paths** by which an entropy number ends up in a CSV, and it is important to understand that the demo file was made by the second path, not the first.

### Path A — the real, live collector (production path)

On a real Linux machine, the flow is:

```
A process touches a file
      ↓
fanotify (Linux kernel) notifies the collector, handing it:
   • the process id (pid) that did it
   • an open file descriptor to the file
      ↓
fanotify_collector.c:
   • reads the first 4096 bytes of the file  (pread)
   • runs shannon_entropy() on those bytes
   • looks up the process name  (/proc/<pid>/comm)
   • looks up the owning user     (owner of /proc/<pid>)
   • resolves the file path        (/proc/self/fd/<fd>)
      ↓
prints ONE CSV line to stdout
```

The exact `printf` that produces each row is in [`fanotify_collector.c`](../src/collector/fanotify_collector.c#L248-L250):

```c
printf("%.3f,%s,%s,%d,%s,%s,%llu,%.2f\n",
       now_seconds(), user_name, process_name, meta->pid,
       operation_name(meta->mask), path, size_bytes, entropy);
```

Those eight `printf` fields are, in order, the eight CSV columns:

```
timestamp_seconds,user_name,process_name,process_id,operation,path,bytes,byte_entropy
```

So in production, the `byte_entropy` value in the last column is **literally the output of `shannon_entropy()`** computed on the real bytes the process wrote or read. Notice `%.2f` — that is why entropy in the CSV always shows two decimal places (e.g. `7.90`).

### Path B — the hand-authored teaching file (what `sample_events.csv` actually is)

`sample_events.csv` is **not** a recording from a live machine. It is a small, deliberately hand-written teaching file — 12 events — designed so a student can read the whole attack story at a glance. Here it is in full:

```csv
timestamp_seconds,user_name,process_name,process_id,operation,path,bytes,byte_entropy
0,dave,code,1001,open,/home/dave/Documents/notes.txt,0,0.00
1,dave,code,1001,read,/home/dave/Documents/notes.txt,4096,4.20
3,dave,libreoffice,1002,open,/home/dave/Documents/budget.ods,0,0.00
4,dave,libreoffice,1002,write,/home/dave/Documents/budget.ods,8192,4.80
12,dave,firefox,1003,write,/home/dave/Downloads/report.pdf,1048576,5.10
20,dave,unknown_process,4242,open,/home/dave/Documents/tax/a.docx,0,0.00
21,dave,unknown_process,4242,read,/home/dave/Documents/tax/a.docx,8192,4.60
22,dave,unknown_process,4242,write,/home/dave/Documents/tax/a.locked,8192,7.90
23,dave,unknown_process,4242,rename,/home/dave/Documents/tax/a.docx,0,0.00
24,dave,unknown_process,4242,read,/home/dave/Pictures/family.jpg,1048576,6.20
25,dave,unknown_process,4242,write,/home/dave/Pictures/family.jpg.locked,1048576,7.95
26,dave,unknown_process,4242,read,/home/dave/Desktop/todo.txt,2048,4.10
27,dave,unknown_process,4242,write,/home/dave/Desktop/todo.txt.locked,2048,7.80
```

The entropy numbers here were **chosen by hand to be realistic**, following the physics from Part 1:

- `open` events have entropy `0.00` — opening a file reads no content, so there is nothing to measure.
- Benign reads/writes sit at `4.20`, `4.80`, `5.10`, `4.60` — normal document/PDF territory.
- The reads of the *original* files (`4.60`, `6.20`, `4.10`) are normal — the attacker hasn't encrypted them yet.
- Every `.locked` **write** is `7.90`, `7.95`, `7.80` — jammed against the 8.0 ceiling, exactly the encrypted-data signature.

That contrast — a benign `4.60` read of `a.docx` immediately followed by a `7.90` write of `a.locked` — is the entire attack pattern in miniature. The `unknown_process` (pid 4242) reads a real file, writes a near-random encrypted copy, and renames/removes the original. That is ransomware behavior, and it is why the README promises *"only `unknown_process` (pid 4242) is flagged."*

### A third, in-between path — the simulator

[`python/simulate_activity.py`](../python/simulate_activity.py) generates larger CSVs (like `attack_scenario.csv`) programmatically. It does **not** compute Shannon entropy on real bytes either — instead it **draws entropy from a probability distribution** chosen to match reality. For example the ransomware `.locked` writes are drawn from a normal distribution centered at 7.9:

```python
float(np.clip(rng.normal(7.9, 0.08), 0.0, 8.0))     # encrypted-looking writes
```

while benign writes are drawn around 4.3–5.2. So all three paths agree on the *meaning* of the number; they differ only in whether the number was measured from real bytes (Path A) or synthesized to look realistic (Paths B and C).

**Key takeaway:** In deployment the entropy column is a genuine `shannon_entropy()` measurement. In the demo/test files it is a hand-picked or simulated stand-in with the same physical meaning, so the rest of the pipeline behaves identically.

---

## Part 4 — How the Whole Machine-Learning Protocol Works

Now we connect entropy (one column of one event) to the actual detector. There are **four stages**: turn events into features, train a model on benign features, export the model, and score live windows against it.

```
raw events (CSV)
   → rolling window per process         (Stage A: feature engineering)
   → 6-number feature vector
   → Isolation Forest, trained on benign (Stage B: training, Python)
   → model.json                          (Stage C: export)
   → anomaly score in (0,1)              (Stage D: scoring, C++ daemon)
   → ALERT if score ≥ threshold
```

### Stage A — From events to a 6-number "feature vector"

A single event (one CSV line) is not enough to judge a process. `code` writing one file at entropy 4.8 is normal; a process writing 40 files/second at entropy 7.9 across 15 directories is not. So we summarize **a short rolling window of recent activity** — 10 seconds by default — into **six numbers**.

The canonical definition is in [`python/features.py`](../python/features.py#L23-L30), and the C++ daemon computes the identical six in [`src/daemon/feature_window.cpp`](../src/daemon/feature_window.cpp#L23-L57). The six features:

| # | Feature | How it's computed over the window | Why ransomware spikes it |
| --- | --- | --- | --- |
| 1 | `events_per_second` | (event count) ÷ window seconds | Attacks are bursty — 50+ ev/s |
| 2 | `writes_per_second` | (write count) ÷ window seconds | Encryption is write-heavy |
| 3 | `rename_delete_rate` | (rename+delete count) ÷ window seconds | The `.locked` rename + original delete cycle |
| 4 | `average_byte_entropy` | mean of the `byte_entropy` column over the window | **This is where entropy enters the model** — encrypted writes push it toward 8 |
| 5 | `unique_directory_count` | count of distinct parent directories | Attacks sweep the whole filesystem |
| 6 | `unique_extension_count` | count of distinct file extensions | Attacks encrypt every file type |

Notice feature #4: the raw per-event entropy from Part 2/3 gets **averaged across the whole window**. So entropy is not judged in isolation — it becomes one of six coordinates describing behavior.

**The rolling window** works like a queue. Each new event is added; events older than `window_seconds` are dropped. In C++ ([`feature_window.cpp`](../src/daemon/feature_window.cpp#L17-L21)):

```cpp
void FeatureWindow::expire_old_events(double now_seconds) {
    while (!events_.empty() && now_seconds - events_.front().timestamp_seconds > window_seconds_) {
        events_.pop_front();
    }
}
```

Crucially, **each process gets its own window** (`std::unordered_map<int, FeatureWindow> windows;` keyed by pid in [`main.cpp`](../src/daemon/main.cpp#L157)). That is what lets the detector name — and optionally pause — the *specific* offending process rather than just saying "something is wrong."

### Stage B — Training the Isolation Forest (Python, on benign data only)

**The central research idea:** the model is trained **only on normal (benign) activity**. It never sees ransomware during training. This is *unsupervised anomaly detection* — instead of learning "what ransomware looks like," it learns "what normal looks like" and flags anything that doesn't fit. That is why File Defender needs no ransomware samples and can catch brand-new, never-before-seen attacks. The README calls this out as *"Isolation Forest learns from benign data only."*

The training script is [`python/train_isolation_forest.py`](../python/train_isolation_forest.py). The heart of it:

```python
scaler = StandardScaler().fit(x)          # step 1: standardize features
x_scaled = scaler.transform(x)

model = IsolationForest(                   # step 2: train the forest
    n_estimators=200,                      #   200 trees
    max_samples=256,                       #   each tree sees 256 samples
    contamination="auto",
    random_state=42,
).fit(x_scaled)
```

**Step 1 — Standardize (the scaler).** The six features live on wildly different scales: entropy runs 0–8, but `unique_directory_count` might be 1–20 and `writes_per_second` might be 0–10. `StandardScaler` rescales each feature to have mean 0 and standard deviation 1 (subtract the mean, divide by the standard deviation), so no single feature dominates just because its raw numbers are bigger. The learned means and scales are saved (you can see them in `model.json` as `scaler_mean` and `scaler_scale`).

**Step 2 — The Isolation Forest itself.** Here is the beautifully simple idea behind the algorithm:

> **Anomalies are easy to isolate.** If you keep splitting the data with random cuts, a weird outlier gets cut off from everyone else after just a few cuts. A normal point, buried in the crowd, needs many cuts before it's alone.

Mechanically:

1. Build 200 random binary "isolation trees." To build one tree, repeatedly pick a random feature and a random split value, partitioning the points into two groups. Keep splitting until each point is isolated (or a depth limit is hit).
2. For any point, its **path length** = how many splits it took to isolate it (how deep in the tree it lands).
3. A **short average path length across all 200 trees = anomaly** (isolated quickly). A **long average path = normal** (took many questions to separate).

Because ransomware windows have extreme values in several of the six features at once (high entropy AND high write rate AND many directories…), they sit far from the benign cluster and get isolated in very few splits — a short path — which becomes a high anomaly score.

**Setting the alarm threshold.** After training, the script scores every benign training window and picks a threshold at a high percentile of those scores ([`train_isolation_forest.py`](../python/train_isolation_forest.py#L141-L142)):

```python
anomaly_scores = -model.score_samples(x_scaled)
recommended_threshold = float(np.quantile(anomaly_scores, 1.0 - args.max_fpr))
```

With the default `--max-fpr 0.005`, the threshold is the 99.5th percentile of benign scores. **By construction, at most 0.5% of normal windows will ever exceed it** — that is the target false-positive rate. Genuine ransomware, which the model has never seen, scores far higher and sails past the threshold.

### Stage C — Export to JSON (so C++ needs no Python at runtime)

The trained forest is serialized to `models/model.json`: every tree's structure (which feature each node splits on, its threshold, its children, its sample counts) plus the scaler and the threshold. The exporter is [`export_model_json`](../python/train_isolation_forest.py#L51-L86). The resulting JSON top-level keys:

```json
{
  "feature_columns": ["events_per_second", ... "unique_extension_count"],
  "scaler_mean":   [...],   "scaler_scale": [...],
  "max_samples":   256,
  "recommended_threshold": 0.7198...,
  "offset": -0.5,
  "trees": [ { "feature":[...], "threshold":[...],
               "children_left":[...], "children_right":[...],
               "n_node_samples":[...] }, ... 200 trees ... ]
}
```

Why bother? So the always-on detector is a **lightweight C++ daemon with no Python, no scikit-learn, no ML runtime** — it just walks trees and does arithmetic. The README lists this as a design goal: *"no Python runtime or ML libraries needed at runtime."*

### Stage D — Scoring a live window (C++ daemon)

The daemon [`src/daemon/anomaly_model.cpp`](../src/daemon/anomaly_model.cpp) re-implements scikit-learn's scoring exactly. For a feature vector it:

1. **Standardizes** it with the saved `scaler_mean`/`scaler_scale` (same transform as training):

   ```cpp
   scaled[i] = (features[i] - scaler_mean_[i]) / denom;
   ```

2. **Drops the point down all 200 trees** and records each path length. Leaves can hold several training samples (trees stop at a height limit), so a normalization term `c(n)` is added for the samples still bunched at the leaf ([`anomaly_model.cpp`](../src/daemon/anomaly_model.cpp#L26-L45)).

3. **Averages the depth across the forest and converts to a score in (0, 1)** with the Isolation Forest formula:

   ```cpp
   const double normalizer = average_path_length(max_samples_);
   return std::pow(2.0, -mean_depth / normalizer);   //  score = 2^(-mean_depth / c(n))
   ```

   The mathematics:

   $$s(x) = 2^{\,-\dfrac{E[h(x)]}{c(n)}}$$

   where `E[h(x)]` is the mean path length across trees and `c(n)` is the expected path length in a random binary tree of `n` points (the normalizer). Read the result as:

   - **score → 1.0** : isolated almost immediately → **strongly anomalous**
   - **score ≈ 0.5** : average depth → **typical / benign**

4. **Compares to the threshold and alerts.** In [`main.cpp`](../src/daemon/main.cpp#L176-L196), after every event the current window is re-scored:

   ```cpp
   const double anomaly_score = model.score(to_vector(features));
   if (anomaly_score >= threshold) {
       std::cout << "ALERT score=" << anomaly_score << " pid=" << event.process_id ...;
       // then (once per process): optional desktop notification, optional SIGSTOP pause
   }
   ```

   Defaults are deliberately safe: **alert-only**. `--notify` adds a desktop popup; `--stop` will `SIGSTOP`-pause the flagged process (never kill it — you can resume with `kill -CONT <pid>`).

### Why we can trust the C++ math: parity testing

Because the C++ daemon only runs on Linux, [`python/verify_parity.py`](../python/verify_parity.py) re-implements the JSON scoring in pure Python and proves it matches scikit-learn's own score to within `1e-9`. If parity passes, the JSON format and the scoring math are correct, so the C++ port (which mirrors the Python line for line) can be trusted. Run it with `uv run python python/verify_parity.py`.

---

## Putting It All Together: Tracing One Attack

Follow pid `4242` from `sample_events.csv` through the whole system:

1. **Events arrive.** At t=20–27s, `unknown_process` opens `a.docx`, reads it (entropy 4.60), writes `a.locked` (**entropy 7.90**), renames the original, then repeats on `family.jpg` (write entropy **7.95**) and `todo.txt` (write entropy **7.80**).

2. **The window fills.** All these events land in pid 4242's own 10-second rolling window.

3. **Six features are computed.** The window now shows: elevated `writes_per_second`, a nonzero `rename_delete_rate`, an `average_byte_entropy` dragged upward by the three ~7.9 writes, and multiple `unique_directory_count` (`/tax`, `/Pictures`, `/Desktop`) and `unique_extension_count` (`.locked`, `.jpg`, `.txt`).

4. **The forest scores it.** This vector sits far from every benign training window, so the isolation trees separate it in very few splits → short average path → **anomaly score near 1.0**.

5. **The threshold fires.** The score clears the `recommended_threshold`, and the daemon prints an `ALERT` naming pid 4242. Meanwhile `code`, `libreoffice`, and `firefox` stay comfortably below threshold and are never flagged.

That is the project's core research claim, demonstrated end to end: **ransomware can be recognized from a small set of behavioral features — entropy chief among them — without ever training on ransomware itself.**

---

## Quick Reference — Where Each Piece Lives

| Concept | File | Key lines |
| --- | --- | --- |
| Shannon entropy calculation | `src/collector/fanotify_collector.c` | `shannon_entropy()`, L63–82 |
| Entropy sampling (first 4 KB) | `src/collector/fanotify_collector.c` | L232–235 |
| CSV row printed per event | `src/collector/fanotify_collector.c` | L248–250 |
| The six features (definition) | `python/features.py` | L23–105 |
| The six features (C++, live) | `src/daemon/feature_window.cpp` | L23–57 |
| Rolling-window expiry | `src/daemon/feature_window.cpp` | L17–21 |
| Training the Isolation Forest | `python/train_isolation_forest.py` | L119–142 |
| Threshold from benign scores | `python/train_isolation_forest.py` | L141–142 |
| Model → JSON export | `python/train_isolation_forest.py` | L51–86 |
| Isolation Forest scoring (C++) | `src/daemon/anomaly_model.cpp` | L47–69 |
| Alert / notify / pause logic | `src/daemon/main.cpp` | L176–196 |
| Python↔C++ parity proof | `python/verify_parity.py` | whole file |
| Synthetic entropy for demos | `python/simulate_activity.py` | L199–217 |
```
