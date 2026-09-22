# Entropy and the Machine-Learning Pipeline, Explained

*A step-by-step companion to the File Defender research project.*

To follow a file event all the way to an alert, we first need to understand
the measurement that goes into the event record. This guide takes that path
in four steps:

1. **What does "entropy" actually mean?** (the concept)
2. **How is entropy calculated?** (the math, worked by hand)
3. **How does entropy get into `sample_events.csv`?** (the data path)
4. **How do the programs turn those numbers into an alert?** (training → export → scoring → alert)

Some experience with C++ and AP Calculus will help, but no previous study of
information theory or machine learning is assumed. The worked examples build
up the ideas before the guide connects them to the code. Links point to the
relevant files so you can follow the implementation as you read.

---

## Part 1 - What "Entropy" Means

### Start with the byte values

Entropy is often introduced as a measure of unpredictability. In this
project, we calculate it by counting how often each byte value occurs. A file
dominated by a few byte values has low entropy. A file with byte values spread
evenly across the full range has high entropy. Text and structured documents
tend toward the lower end; encrypted and compressed data tend toward the
higher end. We will also see why this measurement is not a test of randomness.

### Why a ransomware detector cares

Ransomware reads ordinary files and writes encrypted versions. Encryption is
designed to hide patterns in the original content, producing bytes that look
like random noise. Those bytes have high entropy.

This gives the detector a measurement it can use without knowing the name or
family of the ransomware. The table shows the kinds of values involved:

| Kind of data | Typical entropy (bits/byte) | Why |
| --- | --- | --- |
| A file of all zeros | 0.0 | Perfectly predictable - every byte is the same |
| Plain English text | ~4.0 - 4.5 | Only ~26 letters + spaces are common; `e` and `t` dominate |
| An old-style `.doc` or a plain PDF | ~4.5 - 6.0 | Structured, with headers and repeated tokens |
| A modern Office file (`.docx`, `.xlsx`, `.ods`) | ~7.0 - 7.8 | These are ZIP archives in disguise; almost everything inside is compressed |
| A JPEG or MP4 (already compressed) | ~7.0 - 7.9 | Compression already removed most redundancy |
| **Encrypted / ransomware output** | **~7.9 - 8.0** | Statistically indistinguishable from random |

The project looks for increases toward 8.0 across many files as one sign of
ransomware activity. To interpret that sign, keep two limitations in mind:

- **Compression can give the same result as encryption.** A `.docx` is a ZIP
  file, a JPEG contains compressed image data, and a backup tool may write
  compressed archives. All can have high entropy without being malicious.
  That is why the detector uses six features rather than entropy alone.
- **The count does not describe the order of the bytes.** A file containing
  0, 1, 2, ..., 255 in order, repeated over and over, is predictable. Its
  entropy is still exactly 8.0 because each value occurs equally often. A
  high result tells us that the byte values are evenly distributed, not that
  the file is random or malicious.

### Why the scale stops at 8

The unit is **bits per byte**. A byte has 256 possible values, numbered 0-255.
The greatest uncertainty about one byte occurs when all those values are
equally likely. Describing one of 256 equally likely outcomes takes
**log₂(256) = 8 bits**, so 8.0 is the maximum byte entropy.

One way to picture this is as a series of yes/no questions about a byte. If
every byte is zero, you already know the answer and need no questions. If
every possible value is equally likely, identifying the byte requires the
full 8 bits of information. This picture concerns the byte-value
probabilities; it does not account for patterns in their order.

---

## Part 2 - How Entropy Is Calculated

The calculation is called **Shannon entropy**. It comes from Shannon's work
founding information theory in 1948. The function `shannon_entropy` in
[`src/collector/fanotify_collector.c`](../src/collector/fanotify_collector.c#L63-L82)
implements it. Read the function once for its overall structure; the formula
and examples below explain each step.

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

Here is how the symbols relate to the byte counts:

- The index `i` runs through the 256 possible byte values, from 0 through 255.
- `p_i` is the **fraction of the file that is that byte value** (its probability).
- `log₂(p_i)` is negative (because probabilities are ≤ 1), so `-p_i · log₂(p_i)` is a positive contribution.
- **Add up all 256 contributions.** That sum is the entropy.

### The three-step recipe the code follows

1. **Count.** Walk through the bytes and tally how many times each of the 256 possible values appears (`counts[256]`).
2. **Convert counts to probabilities.** For each value, `p = count / length`.
3. **Sum `-p · log₂(p)`** over every value that actually appears. (Values that never appear contribute nothing, which is why the code `continue`s when `counts[symbol] == 0` - this also avoids `log₂(0)`, which is undefined.)

### Worked example #1: a file with one common byte value

Suppose a tiny 8-byte file contains: `A A A A A A A B`

- The byte `A` appears 7 times → p(A) = 7/8 = 0.875
- The byte `B` appears 1 time → p(B) = 1/8 = 0.125

$$H = -\big(0.875 \cdot \log_2 0.875\big) - \big(0.125 \cdot \log_2 0.125\big)$$
$$H = -(0.875 \cdot -0.1926) - (0.125 \cdot -3.0)$$
$$H = 0.1685 + 0.375 = \mathbf{0.544 \text{ bits/byte}}$$

The result is low because seven of the eight bytes have the same value.
There is little uncertainty about which value a byte will have.

### Worked example #2: a file with the highest possible entropy for its size

Suppose an 8-byte file contains 8 **different** byte values, each appearing once:

- Each of the 8 values has p = 1/8 = 0.125
- `log₂(0.125) = -3`, so each term is `-(0.125)(-3) = 0.375`
- There are 8 such terms: `H = 8 × 0.375 = 3.0 bits/byte`

With only 8 bytes the ceiling is log₂(8) = 3.0, and we hit it exactly. Scale this up: a 4096-byte file in which all 256 byte values appear about equally often approaches the true ceiling of **8.0 bits/byte** - that is what encrypted output looks like.

### Worked example #3: high entropy without any randomness

Now take a 256-byte file containing 0, 1, 2, ..., 255 in order. You can predict
every byte, but each of the 256 values appears exactly once. Each probability
is therefore p = 1/256. Each contribution is `-(1/256)(-8) = 8/256`, giving
`256 × 8/256 = 8.0 bits/byte` in total.

Why does a predictable file get the maximum result? The calculation counts
values; it never checks their order. This is the distinction introduced in
Part 1. Encrypted output, compressed output, and this ordered counting file
can all score high because their byte values are spread evenly. The result
is a useful clue about file activity, but it cannot decide whether the
activity is malicious.

### One practical detail: sampling

Reading an entire 2 GB video for each measurement would be slow. The collector
instead samples the **first 4096 bytes**, called the file's *prefix*, and
calculates entropy from that sample.

It samples only on `read` and `write` events. An `open` records 0.0 because
opening a file touches no content. A `close` also records 0.0: the convention
is to measure the content at the write rather than count it again when the
file closes. Both choices affect the average used later in the feature
window.

```c
#define ENTROPY_SAMPLE_BYTES 4096
...
unsigned char sample[ENTROPY_SAMPLE_BYTES];
double entropy = 0.0;
if (meta->mask & (FAN_ACCESS | FAN_MODIFY)) {                      // read or write only
    ssize_t sampled = pread(meta->fd, sample, sizeof(sample), 0);  // read up to 4096 bytes
    if (sampled > 0) {
        entropy = shannon_entropy(sample, (size_t)sampled);
    }
}
```

The calculation takes work proportional to the number of bytes examined,
written as O(n). Capping the sample at 4096 bytes limits that work even for
large files.

Sampling also limits what the number can tell us:

- **The sample comes from the file as it is when the collector reads it.**
  The collector never sees the exact buffer passed to `write()`. For a
  freshly encrypted file, the prefix contains the encrypted data. For a
  file edited in the middle, the first 4096 bytes may not have changed at all.
- **The prefix may not represent the whole file.** A PDF begins with
  readable text before its compressed sections, and a ZIP begins with a
  small header. A sample may therefore have higher or lower entropy than
  the file as a whole. Ransomware can also encrypt only part of a file to
  run faster, as described in the FBI and CISA advisory on the Royal family.
  A partly encrypted file can retain an ordinary-looking prefix that does
  not reveal the encrypted portion.

Prefix entropy is therefore a low-cost heuristic: a useful rule for common
cases, with limits on which bytes it observes and when it observes them.

The collector and the simulators in `python/` follow the same convention:
`open` and `close` get 0.0; `read` and `write` get a value representing the
current prefix entropy. Changing that rule on only one side would give
training data and live data different meanings. The two parity tests do not
check this part of the data collection. They start with existing CSV rows
and compare the features and scores calculated from those rows.

---

## Part 3 - How Entropy Gets Into `sample_events.csv`

An entropy number in a CSV may be measured from a real file or supplied as
part of a simulation. The short demo file uses hand-written values. We will
first follow the live measurement, then compare it with the teaching file
and the larger simulator.

### Path A - the live collector

On a real Linux machine, the flow is:

```text
A process touches a file
      ↓
fanotify (Linux kernel) notifies the collector, handing it:
   • the process id (pid) that did it
   • an open file descriptor to the file
      ↓
fanotify_collector.c:
   • for a read or a write: reads the first 4096 bytes of the file
     (pread) and runs shannon_entropy() on them
   • for an open or a close: records entropy 0.0
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

```text
timestamp_seconds,user_name,process_name,process_id,operation,path,bytes,byte_entropy
```

For sampled live events, the last column contains the result of
`shannon_entropy()` on the file bytes described above. The `%.2f` in the
print statement formats the entropy with two decimal places, such as `7.90`.

### Path B - the hand-written teaching file

`sample_events.csv` is not a live recording. Its 13 events were written by
hand so you can follow the activity of each process without searching through
a large log. Here is the complete file:

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

The entropy values were chosen to represent the kinds of content discussed
in Part 1:

- `open` events have entropy `0.00` - opening a file reads no content, so there is nothing to measure.
- Benign reads and writes use `4.20`, `4.80`, `5.10`, and `4.60` to represent ordinary document and PDF content.
- The reads of the *original* files (`4.60`, `6.20`, `4.10`) are normal - the attacker hasn't encrypted them yet.
- The `.locked` writes use `7.90`, `7.95`, and `7.80`, near the 8.0 maximum, to represent encrypted output.

Look at the sequence for `unknown_process` (pid 4242): a `4.60` read of
`a.docx` is followed by a `7.90` write of `a.locked`, then a rename of the
original. These rows represent the read, encrypted-write, and rename/remove
pattern of ransomware. In the README demo, this is the process that is
flagged; the benign processes are not.

### Path C - the simulator

[`python/simulate_activity.py`](../python/simulate_activity.py) generates
larger CSVs such as `attack_scenario.csv`. It does not read file bytes to
calculate entropy. Instead, it draws values from a probability distribution
chosen to represent the content. For example, simulated ransomware writes
use a normal distribution centered at 7.9:

```python
float(np.clip(rng.normal(7.9, 0.08), 0.0, 8.0))     # encrypted-looking writes
```

Benign write values are drawn around 4.3-5.2. The three paths give the column
the same intended meaning, but obtain its values differently: measurement
for the live collector, hand selection for the short teaching file, and
random sampling for the larger simulator. The later stages process the
column in the same way regardless of where its values came from.

---

## Part 4 - From Events to Alerts

So far, entropy has been one value in one event record. The detector needs
to combine that record with recent activity before it can make a decision.
There are four stages: build features from events, train on benign features,
save the trained model, and use that model to score new windows.

```text
raw events (CSV)
   → rolling window per process         (Stage A: feature engineering)
   → 6-number feature vector
   → Isolation Forest, trained on benign (Stage B: training, Python)
   → model.json                          (Stage C: export)
   → anomaly score in (0,1)              (Stage D: scoring, C++ daemon)
   → ALERT if score ≥ threshold
```

### Stage A - From events to a 6-number "feature vector"

A single event, represented by one CSV line, is not enough to judge a
process. Compare `code` writing one file at entropy 4.8 with a process
writing 40 files/second at entropy 7.9 across 15 directories. The first is
ordinary editing activity; the second is not. To describe that difference,
the detector summarizes a short rolling window, 10 seconds by default,
with six numbers.

The reference definitions are in
[`python/features.py`](../python/features.py#L23-L30). The C++ daemon computes
the same six measurements in
[`src/daemon/feature_window.cpp`](../src/daemon/feature_window.cpp#L23-L57):

| # | Feature | How it's computed over the window | Why ransomware spikes it |
| --- | --- | --- | --- |
| 1 | `events_per_second` | (event count) ÷ window seconds | Attacks are bursty - 50+ ev/s |
| 2 | `writes_per_second` | (write count) ÷ window seconds | Encryption is write-heavy |
| 3 | `rename_delete_rate` | (rename+delete count) ÷ window seconds | The `.locked` rename + original delete cycle |
| 4 | `average_byte_entropy` | mean of the `byte_entropy` column over the window | **This is where entropy enters the model** - encrypted writes push it toward 8 |
| 5 | `unique_directory_count` | count of distinct parent directories | Attacks sweep the whole filesystem |
| 6 | `unique_extension_count` | count of distinct file extensions | Attacks encrypt every file type |

For feature #4, the program averages the per-event entropy values across
the whole window. That average becomes one coordinate of the six-number
feature vector, rather than a separate decision about whether a file is
malicious.

**The rolling window** works like a queue. Each new event is added; events older than `window_seconds` are dropped. In C++ ([`feature_window.cpp`](../src/daemon/feature_window.cpp#L17-L21)):

```cpp
void FeatureWindow::expire_old_events(double now_seconds) {
    while (!events_.empty() && now_seconds - events_.front().timestamp_seconds > window_seconds_) {
        events_.pop_front();
    }
}
```

Each process has its own window. In
[`main.cpp`](../src/daemon/main.cpp#L157),
`std::unordered_map<int, FeatureWindow> windows;` stores the windows by PID.
Keeping them separate lets the detector associate an unusual score with a
particular process, which it can then name in an alert or optionally pause.

### Stage B - Training the Isolation Forest (Python, on benign data only)

> **Why this algorithm?** This section explains *how* the Isolation Forest works.
> For *why* it was chosen, where it is genuinely weak, and how it measures up
> against the alternatives, see [`WHY_ISOLATION_FOREST.md`](WHY_ISOLATION_FOREST.md)
> and [`EXPERIMENTS_AND_FINDINGS.md`](EXPERIMENTS_AND_FINDINGS.md).

The model trains only on normal, or *benign*, activity. Rather than learning
from examples of ransomware, it learns what benign windows look like and
scores windows that differ from them as unusual. This is the project's use
of *unsupervised anomaly detection*. It does not need ransomware samples for
training and can flag attacks it has not encountered before.

The main training steps in
[`python/train_isolation_forest.py`](../python/train_isolation_forest.py) are:

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

**Step 1 - Standardize the features.** For each feature, `StandardScaler`
subtracts the mean and divides by the standard deviation. This centers the
values at mean 0 and gives them standard deviation 1. The training means
and scales are saved in `model.json` as `scaler_mean` and `scaler_scale`,
so scoring can apply the same transformation later.

For the standard Isolation Forest, scaling changes almost nothing. Some
methods measure distances between points, so a feature with large numbers
can dominate their calculations. An isolation tree works differently: it
chooses a random cut between the smallest and largest values of one feature
at the current node. Shifting or stretching that feature moves the minimum,
maximum, and cut together. The same rows end up on each side, so in exact
arithmetic the tree is unchanged.

There is a numerical exception. scikit-learn skips a feature when its values
are closer together than about 0.0000001, treating it as constant. Scaling a
very narrow range can make that feature usable. This does not happen with
the six features here.

The scaler is kept for two reasons. It gives the exported JSON a consistent
format across model types, and it matters for the Extended Isolation Forest
in `python/extended_isolation_forest.py`. That variant uses slanted cuts that
combine features, so their relative scales affect the result.

**Step 2 - Build the Isolation Forest.** Imagine repeatedly dividing the
training rows into two groups using random cuts. A point far from the other
points can be separated after only a few cuts. A point surrounded by similar
ones usually needs more cuts before it is alone.

The algorithm uses that difference as follows:

1. Build 200 random binary "isolation trees." To build one tree, repeatedly pick a random feature and a random split value, partitioning the points into two groups. Keep splitting until each point is isolated (or a depth limit is hit).
2. For any point, its **path length** = how many splits it took to isolate it (how deep in the tree it lands).
3. A **short average path length across all 200 trees = anomaly** (isolated quickly). A **long average path = normal** (took many questions to separate).

Ransomware windows have extreme values in several features at once: high
entropy, a high write rate, and activity across many directories. These
values place them far from the benign group, so fewer splits isolate them.
The short path becomes a high anomaly score.

**Setting the alarm threshold.** After training, the script scores every benign training window and picks a threshold at a high percentile of those scores ([`train_isolation_forest.py`](../python/train_isolation_forest.py#L141-L142)):

```python
anomaly_scores = -model.score_samples(x_scaled)
recommended_threshold = float(np.quantile(anomaly_scores, 1.0 - args.max_fpr))
```

With the default `--max-fpr 0.005`, the threshold is the 99.5th percentile
of the scores from the model's own benign training data. This places it near
the top 0.5% of the calibration scores. It does not guarantee that only 0.5%
of future benign windows will cross it, for three reasons:

- On the calibration data itself, the exact fraction depends on how many rows there were and on ties. With three scores `[0, 1, 2]`, the "99.5th percentile" is 1.99, and one row in three is above it.
- On new benign data, the rate can be anything. The project's own experiment in [`EXPERIMENTS_AND_FINDINGS.md`](EXPERIMENTS_AND_FINDINGS.md) calibrated on one benign session, tested on another, and measured 1.15% instead of 0.5%.
- The training data and the calibration data are the same rows here. A stricter setup would fit the model on one recording, pick the threshold on a second, and test on a third.

The setting is therefore a calibration rule, not a promised future rate.
It gives you a starting threshold based on the benign activity seen so far.

### Stage C - Export to JSON (so C++ needs no Python at runtime)

After training, the program writes the model to `models/model.json`. This
step is called *serialization*. It saves each tree's structure: split
features, thresholds, child nodes, and sample counts. It also saves the
scaler and alert threshold. The function
[`export_model_json`](../python/train_isolation_forest.py#L51-L86) creates
the file, whose top-level entries look like this:

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

Saving the tree structure lets the C++ daemon score activity without running
Python or scikit-learn. It only needs to read the saved numbers, follow the
tree comparisons, and calculate the score.

**The shipped model uses only four of its six input features.** A feature can
separate training rows only if its values differ. In
`testdata/benign_baseline.csv`, every process stays in one directory and none
renames or deletes a file. Consequently, `rename_delete_rate` is always 0.0
and `unique_directory_count` is always 1.0. No tree splits on either feature,
so changing those inputs cannot affect the shipped model's score.

`python/inspect_model.py` checks this by examining every split in every tree.
The first block below reports that no split uses features 2 or 4. The second
block illustrates the result: setting either feature to a million on the
demo rows leaves the score unchanged. That illustration would not be enough
on its own, since a chosen row might stay on the same side of every split
even for a feature the model uses. The complete split scan establishes the
unused-feature result.

```text
  [2] rename_delete_rate       NEVER USED  (root split in 0 of 200 trees)
  [4] unique_directory_count   NEVER USED  (root split in 0 of 200 trees)
  ...
  rename_delete_rate       0.0000  <- the model cannot see this feature
  unique_directory_count   0.0000  <- the model cannot see this feature
```

The trainer prints a warning about unused features after each run. Making
these features useful requires training data in which they vary, rather
than a change to the scoring code. Until then, the model reads six columns
but bases its decisions on four.

### Stage D - Scoring a live window (C++ daemon)

The daemon in
[`src/daemon/anomaly_model.cpp`](../src/daemon/anomaly_model.cpp) applies
scikit-learn's scoring formula to the exported trees using double precision.
scikit-learn rounds its inputs to single precision first, so values exactly
on a split can produce slightly different results. The tests below measure
that difference.

For each feature vector, the daemon follows these steps:

1. **Standardizes** it with the saved `scaler_mean`/`scaler_scale` (same transform as training):

   ```cpp
   scaled[i] = (features[i] - scaler_mean_[i]) / denom;
   ```

2. **Follows the comparisons through all 200 trees** and records each path
   length. Trees stop at a height limit, so a leaf can still contain several
   training samples. The calculation adds `c(n)` to account for those
   samples remaining together
   ([`anomaly_model.cpp`](../src/daemon/anomaly_model.cpp#L26-L45)).

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

   Defaults are deliberately safe: **alert-only**. `--notify` adds a desktop popup; `--stop` will `SIGSTOP`-pause the flagged process (never kill it - you can resume with `kill -CONT <pid>`).

### How the C++ math is checked: two parity tests

The project has two *parity tests*, meaning tests that compare the outputs
of different implementations. They check different parts of the work.

**`verify_parity.py`** runs on any machine. It compares scikit-learn's scores
with a Python implementation that reads the JSON trees. On ordinary rows,
the scores agree to about `1e-16`. The script does not run C++, so this checks
the saved representation and scoring recipe rather than the daemon itself.

It also tests rows placed exactly on split thresholds. Those scores differ
by up to `2e-3`: rounding an input to single precision (`float32`) can put
it on a different side of a split from the double-precision value. Real
windows almost never land exactly on a threshold, but the test measures
this case explicitly.

**`verify_cpp_parity.py`** runs on Linux after the daemon has been built.
It starts the daemon with `--dump-features`, which prints the six features
and score for each event. It then compares those values with the Python
reference. Unlike the first test, it can catch a disagreement between
`feature_window.cpp` and `features.py`. Run it after changing a feature
definition:

```sh
uv run python python/verify_parity.py
uv run python python/verify_cpp_parity.py --daemon build/file_defender_daemon
```

---

## Putting It All Together: Tracing One Attack

Follow pid `4242` from `sample_events.csv` through the whole system:

1. **Events arrive.** At t=20-27s, `unknown_process` opens `a.docx`, reads it (entropy 4.60), writes `a.locked` (**entropy 7.90**), renames the original, then repeats on `family.jpg` (write entropy **7.95**) and `todo.txt` (write entropy **7.80**).

2. **The window fills.** All these events land in pid 4242's own 10-second rolling window.

3. **Six features are computed.** The window has an elevated write rate,
   a nonzero rename/delete rate, and an average entropy raised by the three
   writes near 7.9. It also spans several directories (`/tax`, `/Pictures`,
   `/Desktop`) and extensions (`.locked`, `.jpg`, `.txt`). As explained in
   Stage C, the shipped model does not use `rename_delete_rate` or
   `unique_directory_count`. Its score depends on the other four features:
   event rate, write rate, average entropy, and extension count.

4. **The forest scores it.** The vector differs from the benign training
   windows and is separated in fewer splits. Its shorter average path gives
   a higher score. With the shipped model, pid 4242's highest-scoring window
   reaches **0.77**, above the threshold of **0.72**. A score near 1.0 would
   require separation after only one or two cuts in every tree; the demo
   does not need a score that high to trigger an alert.

5. **The threshold fires.** The score clears the `recommended_threshold`, and the daemon prints an `ALERT` naming pid 4242. Meanwhile `code`, `libreoffice`, and `firefox` stay comfortably below threshold and are never flagged.

The example follows the project's central idea from an event record to an
alert: recognize ransomware behavior using a small set of measurements,
including entropy, without using ransomware examples for training.

---

## Quick Reference - Where Each Piece Lives

| Concept | File | Where to look |
| --- | --- | --- |
| Shannon entropy calculation | `src/collector/fanotify_collector.c` | `shannon_entropy()` |
| Entropy sampling (first 4 KB, read/write only) | `src/collector/fanotify_collector.c` | the `pread` call in `main()` |
| CSV row printed per event | `src/collector/fanotify_collector.c` | the `printf` in `main()` |
| The six features (definition) | `python/features.py` | `FEATURE_COLUMNS`, `build_feature_rows()` |
| The six features (C++, live) | `src/daemon/feature_window.cpp` | `FeatureWindow::features()` |
| Rolling-window expiry | `src/daemon/feature_window.cpp` | `FeatureWindow::expire_old_events()` |
| Training the Isolation Forest | `python/train_isolation_forest.py` | `main()` |
| Which features the forest really uses | `python/train_isolation_forest.py`, `python/inspect_model.py` | `report_unused_features()`, `describe_forest()` |
| Threshold from benign scores | `python/train_isolation_forest.py` | the `np.quantile` line in `main()` |
| Model → JSON export | `python/train_isolation_forest.py` | `export_model_json()` |
| Isolation Forest scoring (C++) | `src/daemon/anomaly_model.cpp` | `AnomalyModel::score()`, `AnomalyModel::path_length()` |
| Alert / notify / pause logic | `src/daemon/main.cpp` | the `while (std::getline(...))` loop |
| JSON-vs-scikit-learn check (any machine) | `python/verify_parity.py` | whole file |
| C++-vs-Python check (Linux) | `python/verify_cpp_parity.py` | whole file |
| Synthetic entropy for demos | `python/simulate_activity.py` | the `if operation in ("open", "close")` branches |

Function names are used instead of line numbers because line numbers drift every time a file is edited.
