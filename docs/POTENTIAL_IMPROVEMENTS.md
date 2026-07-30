# Potential Improvements

*Three recommendations from [`WHY_ISOLATION_FOREST.md`](WHY_ISOLATION_FOREST.md),
built and measured.*

That document ended with four ranked recommendations. This one implements three
of them: **temporal aggregation** (1), **baseline comparison** (2), and the
**Extended Isolation Forest** (4).

Two ground rules were followed throughout:

1. **The existing pipeline is untouched.** Every improvement lives in a new
   file. `features.py`, `train_isolation_forest.py`, `verify_parity.py`,
   `simulate_activity.py`, and the whole of `src/` behave exactly as before, so
   the working detector described in `README.md` still works and the six-feature
   contract in three places is still in sync.
2. **Nothing is claimed that was not measured.** Every number below is printed
   by a script in `python/`, and the command that produces it is listed. Where a
   proposed improvement turned out **not** to help, that is reported too. Two of
   the three did less than the original recommendation implied, and finding that
   out is the point of building them.

---

## The New Files

| File | Purpose |
| --- | --- |
| [`python/score_smoother.py`](../python/score_smoother.py) | EWMA and CUSUM aggregation over the score stream (improvement 1) |
| [`python/demo_temporal_aggregation.py`](../python/demo_temporal_aggregation.py) | Attack-pace sweep measuring what that aggregation buys |
| [`python/baseline_detectors.py`](../python/baseline_detectors.py) | Robust z-score and Mahalanobis detectors (improvement 2) |
| [`python/extended_isolation_forest.py`](../python/extended_isolation_forest.py) | Extended Isolation Forest with oblique cuts (improvement 4) |
| [`python/evaluation.py`](../python/evaluation.py) | Labeled feature rows, shared threshold rule, operational metrics |
| [`python/compare_detectors.py`](../python/compare_detectors.py) | The four-way comparison harness |
| [`python/simulate_realistic_baseline.py`](../python/simulate_realistic_baseline.py) | A benign baseline hard enough to tell detectors apart |

Reproduce everything with three commands:

```sh
uv run python python/demo_temporal_aggregation.py
uv run python python/compare_detectors.py
uv run python python/extended_isolation_forest.py
```

---

## Prerequisite: A Test Fixture That Can Fail

Before any of the three improvements could be measured, the evaluation data had
to be replaced. This was not on the original list, and it turned out to block
everything else.

`simulate_activity.py` generates a deliberately easy dataset. Its benign
processes emit only `open`, `read`, `write`, and `close`, so
`rename_delete_rate` is **identically zero** in every benign training window.
The consequence is severe: `StandardScaler` sees zero variance on that feature,
and any nonzero delete rate at scoring time falls outside everything the model
has ever seen. A single `delete` is therefore enough to flag a process. That
makes the pipeline look flawless and makes detector comparison meaningless,
because every candidate scores perfectly.

[`simulate_realistic_baseline.py`](../python/simulate_realistic_baseline.py)
adds the three benign behaviors that actually generate false positives:

| Benign behavior | Why it matters |
| --- | --- |
| Editors delete swap files, LibreOffice cycles lock files, the browser discards `.part` downloads | Gives `rename_delete_rate` a real, nonzero benign distribution |
| The browser writes `.zip` and `.jpg` files at 7.4 to 7.6 bits/byte | `average_byte_entropy` alone can no longer separate the classes |
| `git gc` repacks and `restic` runs a backup sweep | Fast, broad, high-entropy, delete-heavy, and completely benign |

The resulting benign baseline (90 simulated minutes, 6482 windows) has a mean
write entropy of 7.90 bits/byte for `git` and 7.92 for `restic`, which is
indistinguishable from ransomware output. It also supplies a
**rate-parameterized attacker**, `generate_paced_attack(files_per_minute)`, so
an experiment can vary encryption pace as an independent variable.

This fixture is what makes the rest of this document meaningful, and it is also
where the single most important result comes from. See
[The Real Bottleneck](#the-real-bottleneck) below.

---

## Improvement 1 - Temporal Aggregation

### The gap

The daemon keeps a rolling window of *events* but no memory at all of previous
*scores*. Each window is judged as though it were the only thing that ever
happened, so an attacker who rate-limits encryption below the threshold is
invisible however long they persist. No choice of tree count, subsample size, or
threshold fixes this, because the information never reaches the model.

### The two aggregation rules

[`score_smoother.py`](../python/score_smoother.py) adds two classical
sequential-change detectors, both a few arithmetic operations per event:

**EWMA.** An exponentially weighted moving average of the score,

$$s_i = \alpha \, x_i + (1 - \alpha)\, s_{i-1}$$

with $\alpha = 0.15$, which averages over roughly seven recent events. It asks
"has this process been mildly unusual for a while?".

**CUSUM.** A one-sided cumulative sum,

$$S_i = \max\left(0,\; S_{i-1} + \left(x_i - \mu_0 - k\right)\right)$$

where $\mu_0$ is the mean benign score and $k$ is a dead band set to half a
benign standard deviation. A brief benign burst adds a little and decays back to
the floor; a sustained mild elevation accumulates without bound. The alarm fires
on **persistence** rather than on magnitude.

Calibration follows the rule the project already uses for the forest: the
instantaneous and EWMA thresholds are the $(1 - \text{max\_fpr})$ quantile of
what each statistic reaches on benign data. The CUSUM limit cannot be a quantile
of per-observation values, because the statistic is serially dependent by
design, so it is set just above the worst excursion any benign process reaches.

### The pace sweep

A single hand-built "slow attack" would prove nothing, because whether it is
caught depends entirely on the pace chosen. So
[`demo_temporal_aggregation.py`](../python/demo_temporal_aggregation.py) sweeps
the pace from 600 files/minute down to 1 file/minute, runs five attacker seeds at
each pace, and reports the median number of files already encrypted when the
alarm first fired. Lower is better; 24 of 24 means the attack completed.

### Pace sweep results

**Calibration 1, every benign process included.** Thresholds:
instant $\ge 0.7503$, EWMA $\ge 0.7383$, CUSUM $\ge 64.74$.

```text
 files/min  attack len          instant             ewma            cusum
-------------------------------------------------------------------------
       600         2 s            18/24            18/24      24/24 (5/5)
       300         5 s            19/24            18/24      24/24 (5/5)
       120        12 s            19/24            18/24      24/24 (5/5)
        60        24 s      24/24 (5/5)      24/24 (5/5)      24/24 (5/5)
        30        48 s      24/24 (5/5)      24/24 (5/5)      24/24 (5/5)
        12       2 min      24/24 (5/5)      24/24 (5/5)      24/24 (5/5)
         6       4 min      24/24 (5/5)      24/24 (5/5)      24/24 (5/5)
         3       8 min      24/24 (5/5)      24/24 (5/5)      24/24 (5/5)
         1      24 min      24/24 (5/5)      24/24 (5/5)      24/24 (5/5)
```

`(5/5)` marks paces where the rule never fired in any of the five runs.

**Calibration 2, `git` and `restic` treated as triaged known applications.**
Thresholds: instant $\ge 0.5218$, EWMA $\ge 0.4764$, CUSUM $\ge 8.878$.

```text
 files/min  attack len          instant             ewma            cusum
-------------------------------------------------------------------------
       600         2 s             2/24             3/24            11/24
       300         5 s             3/24             3/24            12/24
       120        12 s             3/24             3/24            12/24
        60        24 s             3/24             3/24            12/24
        30        48 s             3/24             3/24            14/24
        12       2 min            20/24             5/24      24/24 (5/5)
         6       4 min      24/24 (3/5)      24/24 (5/5)      24/24 (5/5)
         3       8 min      24/24 (5/5)      24/24 (5/5)      24/24 (5/5)
         1      24 min      24/24 (5/5)      24/24 (5/5)      24/24 (5/5)
```

### Reading the pace sweep

**EWMA earns its keep, in a narrow band.** At 12 files/minute the
instantaneous rule loses 20 of 24 files while EWMA loses 5. That is the
predicted effect, and it is exactly where it was predicted: the pace at which
the per-window score is persistently but only mildly elevated. Everywhere else
EWMA matches the instantaneous rule to within one file.

**CUSUM, calibrated this way, is not competitive.** It is 8 to 9 files worse
than the instantaneous rule at every pace it detects at all, and it never fires
in calibration 1. The reason is visible in the benign data: `git`'s CUSUM
statistic peaks at 47.9 and `restic`'s at 33.3 during their bursts, so a limit
that tolerates them must sit above 64, and the attacker only ever produces 96
observations. The statistic cannot accumulate that far before the attack is
over. CUSUM is the textbook answer to "detect a small persistent shift", but it
assumes the shift outlasts the benign excursions, and here it does not.

**Nothing detects below 6 files/minute, and temporal aggregation cannot fix
it.** This is the most useful negative result in the document, and it disproves
part of the original recommendation. Aggregating a score only helps if the score
is elevated. Work through a single window for a patient attacker: one file's
worth of activity is `open`, `read`, `write`, `delete` over about 0.2 seconds,
so in a 10-second window

- `events_per_second` $= 0.4$ (benign median 0.6)
- `writes_per_second` $= 0.1$ (benign median 0.2)
- `average_byte_entropy` $= (0 + 5.2 + 7.9 + 0) / 4 = 3.3$ (benign median 2.4)
- `unique_directory_count` $= 1$, `unique_extension_count` $= 2$

Every coordinate is inside the benign body. The window is not mildly anomalous,
it is **ordinary**, and the measured mean score confirms it: 0.424 for the
attacker against a benign mean of 0.428. There is no signal to accumulate.

The root cause is a feature-design flaw, not a model flaw.
`average_byte_entropy` averages over *all* events in the window, and the
zero-entropy `open` and `delete` events dilute the one write that carries the
whole signal. A patient attacker gets that dilution for free. Fixing it means
changing the feature definition, which would require updating all three places
that define the features and re-running the parity check, so it is left as a
proposal rather than a change.

**Out-of-sample false-positive rates overshoot the target.** In calibration 2,
66 of 5762 held-out benign windows trip the instantaneous rule, which is 1.15%
against a 0.5% target, and EWMA reaches 1.6%. Both thresholds were fitted on one
benign session and evaluated on another, and neither generalized. This is worth
knowing before trusting any single-session calibration.

### Porting to the C++ daemon

`TemporalDetector` holds four doubles of state per process. In
[`main.cpp`](../src/daemon/main.cpp) it would live beside the `FeatureWindow` in
the per-pid map and be updated with the score that is already computed after
every event. No new dependency, no measurable cost.

---

## Improvement 2 - Baselines

### Why baselines

A detector is only as good as the simplest thing it beats. Two one-class
baselines are implemented in
[`baseline_detectors.py`](../python/baseline_detectors.py), both fitted on
benign data only so the project's central research claim is preserved.

**Robust z-score.** Per-feature median and median absolute deviation, with the
score being the largest one-sided deviation:

$$s(x) = \max_j \; \max\left(0, \; \frac{x_j - \text{median}_j}{1.4826 \cdot \text{MAD}_j}\right)$$

The MAD replaces the standard deviation because the benign data contains real
bursts, and a single `git gc` would inflate a standard deviation enough to hide
an attack. Clamping negative terms to zero encodes what the forest cannot know:
for all six features, high is suspicious and low is not.

**Mahalanobis distance.** A single Gaussian fitted to the benign cloud:

$$d(x) = \sqrt{(x - \mu)^{\mathsf{T}} \, S^{-1} \, (x - \mu)}$$

The inverse covariance is what makes this different in kind from the z-score. A
high write rate is unremarkable when the event rate is high too, because benign
windows always show those two rising together, but a high write rate with a low
event rate is far from the center even though neither value is individually
extreme. That is precisely the correlation structure an axis-aligned isolation
tree cannot represent. The covariance is estimated with Ledoit-Wolf shrinkage so
it stays invertible on a short baseline.

### The four-way comparison

[`compare_detectors.py`](../python/compare_detectors.py) fits all four detectors
on the same 6482 benign windows, calibrates each by the identical rule (the
99.5th percentile of its own benign training scores), and evaluates all four on a
held-out benign session plus a ransomware sweep.

### Comparison results

At 120 files/minute, target false-positive rate 0.5%:

| detector | benign FPR | detect | ROC-AUC | avg prec | files lost | latency | model |
| --- | --- | --- | --- | --- | --- | --- | --- |
| isolation_forest | 0.34% | 16.7% | 0.932 | 0.302 | 19 / 24 | 9.6 s | 562 KB |
| robust_zscore | 0.43% | 25.0% | 0.921 | 0.283 | 18 / 24 | 9.0 s | **0.4 KB** |
| mahalanobis | 0.40% | **54.2%** | 0.925 | **0.646** | **11 / 24** | **5.5 s** | 1.1 KB |
| extended_forest | 0.32% | 28.1% | 0.929 | 0.462 | 16 / 24 | 8.1 s | 2115 KB |

The ranking is stable. Across paces 600, 300, 120, and 60 files/minute with five
attacker seeds each, median files lost:

| detector | 600 | 300 | 120 | 60 |
| --- | --- | --- | --- | --- |
| mahalanobis | 10 | 11 | 11 | 23 |
| extended_forest | 16 | 16 | 16 | 24 |
| robust_zscore | 18 | 18 | 18 | 24 |
| isolation_forest | 18 | 19 | 19 | 24 |

At 60 files/minute the Mahalanobis detector is the only one of the four that
alerts at all, in 5 of 5 runs.

### Reading the comparison

**A 1.1 KB model beats a 562 KB forest on every operational metric at the same
false-positive rate.** The Mahalanobis detector halves the files lost, halves
the detection latency, and doubles the average precision. It is 500 times
smaller, needs no tree walk, and ports to C++ as a mean vector and a $6 \times 6$
matrix, which is 36 multiply-accumulates against 200 tree descents. On this data,
with these six features, the Isolation Forest is not the best available choice,
and the project should say so or explain why it keeps the forest anyway.

**ROC-AUC hides the entire difference.** All four detectors land between 0.921
and 0.932, a spread of 1%, while files lost varies by a factor of two. AUC
averages over every possible threshold, including thresholds no defender would
ever deploy. Average precision, which weights the high-score region where the
alert threshold actually sits, separates them cleanly: 0.65 against 0.30. Any
future evaluation of this project should report average precision and files lost,
not AUC.

**The z-score baseline is competitive and it can explain itself.** It matches
the forest on files lost with a 0.4 KB model, and its alert names the responsible
feature: the attacker's worst window is flagged as `events_per_second` at 17.1
robust sigmas above the benign median. Compare that with "the average path length
across 200 random trees was short". For a teaching project, and for a defender
deciding whether to trust an alert, this matters.

**Every detector is defeated by the same two benign processes.** `git` and
`restic` trip all four. This is not a modeling failure; those processes really do
write high-entropy data quickly across many directories while deleting files.
No purely behavioral detector on these six features can separate them from
ransomware, which is the subject of the next section.

### Honest caveats

- The data is synthetic. It was designed to be realistic, but it was designed by
  the same person evaluating the detectors on it.
- The Mahalanobis detector assumes one Gaussian blob, and real benign activity is
  multi-modal (idle, editing, compiling, backing up). It wins here anyway, but a
  Gaussian mixture is the honest next step, and a second benign session might
  narrow the gap.
- Thresholds were calibrated on one benign session, and the out-of-sample
  false-positive rates in improvement 1 show that single-session calibration
  overshoots its target by two to three times.

---

## Improvement 4 - Extended Isolation Forest

### The geometric problem

A standard isolation tree splits on one feature at a time, so every cut is
perpendicular to an axis and every leaf owns an axis-aligned box. When the
benign data is correlated, the union of those boxes covers rectangular regions
containing no training data at all. A point in such a region takes a long path
and receives a normal score even though nothing like it was ever observed.

### The oblique-cut forest

[`extended_isolation_forest.py`](../python/extended_isolation_forest.py)
implements the Hariri, Kind and Brunner (2018) algorithm in NumPy. Each node
draws a random unit normal vector $w$ and a random intercept $p$ inside the
node's data range, and splits on

$$w \cdot x + b \le 0, \qquad b = -(w \cdot p)$$

Everything else is unchanged, including the score

$$s(x) = 2^{\,-E[h(x)] / c(\psi)}$$

so the daemon's threshold logic would not need to change. Setting
`extension_level=0` reduces the algorithm to the standard one, which makes the
parameter a dial between the two designs rather than a fork in the road.

The export mirrors `models/model.json`, with a `normal` vector and a `bias`
scalar per node in place of `feature` and `threshold`. Running the module
directly re-scores a sample straight from the serialized dict and confirms it
reproduces the in-memory model to 0.0e+00, in the spirit of `verify_parity.py`.
That proves the export is complete and a C++ port is possible.

### The blind-spot probe

`compare_detectors.py` locates the most strongly correlated feature pair, then
builds probes from the median benign window with one of them pushed to its
97.5th percentile and the other to its 2.5th. Every coordinate stays inside the
benign range, so anything looking at features one at a time sees nothing wrong.

The most correlated pair is `events_per_second` and `writes_per_second`, with
$r = 0.973$. Training windows with the first in its top decile and the second in
its bottom decile: **0 of 6482**. The region is genuinely unobserved.

| detector | threshold | probe A | probe B | flags A | flags B |
| --- | --- | --- | --- | --- | --- |
| isolation_forest | 0.7503 | 0.5145 | 0.5154 | no | no |
| robust_zscore | 14.97 | 8.77 | 8.77 | no | no |
| mahalanobis | 8.44 | **16.36** | **10.99** | **yes** | **yes** |
| extended_forest | 0.7680 | 0.6291 | 0.6014 | no | no |

Three of four detectors call a combination that never once occurred in 6482
training windows perfectly normal. Only the covariance-aware one catches it.

### Reading the probe

**The extension helps, measurably, but not enough.** On the probe it lifts the
score from 0.515 to 0.629, moving a third of the way to its threshold: the
geometric argument is real and the fix works in the predicted direction. In the
detection comparison it beats the standard forest at every pace, cutting files
lost from 19 to 16 and raising average precision from 0.30 to 0.46. But it still
does not flag the probe, and it still loses to a 1.1 KB Gaussian.

**The cost is a 3.8x larger model.** 2115 KB against 562 KB, because each node
now stores a six-vector instead of a feature index and a threshold. Scoring cost
in C++ would be one dot product per node instead of one array lookup, which is
six multiply-adds on a tree walk that is already memory-bound.

**Standardization stops being decorative.** A monotone per-feature rescaling
cannot change an axis-aligned split, which is why `StandardScaler` is
mathematically a no-op for the standard forest (as noted in
[`WHY_ISOLATION_FOREST.md`](WHY_ISOLATION_FOREST.md)). An oblique cut mixes
features, so relative scale determines which hyperplanes are reachable. Under
this algorithm the scaler is load-bearing.

---

## The Real Bottleneck

The single most valuable result came from the test fixture rather than from any
of the three improvements.

In calibration 1, the false-positive budget is consumed entirely by two benign
processes. `git gc` and `restic` sit at the top of the benign score
distribution, with mean scores of 0.627 and 0.667 against a global benign mean of
0.428. Tolerating them forces the threshold up to 0.750, and at that threshold no
attacker slower than 120 files/minute is detected at all, while a smash-and-grab
still loses 18 of 24 files.

Move those two processes out of the calibration, as a deployment would after
triaging its first week of alerts, and the threshold drops to 0.522. At 120
files/minute the same attacker now loses 3 files instead of 19, and detection
extends down to 30 files/minute. **Recognizing two benign applications is worth
six times more than every algorithmic improvement in this document combined.**

That is recommendation 3 from `WHY_ISOLATION_FOREST.md`, and it was not on the
list to implement. It should be first.

---

## What I Would Do Next

Ranked by measured value, not by novelty:

1. **Get real benign data, including the heavy hitters.** Record an actual
   session with backups, compiles, package upgrades, and media transcoding. The
   evidence above says this dominates every model choice.
2. **Give known applications their own baseline.** Per-process-name statistics,
   or an explicit allowlist with a separate threshold. This is what recovers the
   6x improvement, and it is a small change to the daemon's per-pid map.
3. **Fix `average_byte_entropy`.** Average the entropy of *write* events only,
   instead of diluting it with zero-entropy `open` and `delete` events. This is
   what makes the patient attacker visible at all, and no amount of temporal
   smoothing substitutes for it. It requires changing the feature in all three
   places and re-running `verify_parity.py`.
4. **Add the Mahalanobis detector to the daemon, alongside the forest.** It is
   1.1 KB, it wins on every operational metric here, and it is 36
   multiply-accumulates in C++. Run both and alert on either.
5. **Add the EWMA layer.** Four doubles per process, and worth 15 files at the
   one pace where per-window detection is marginal.
6. **Report average precision and files lost, never ROC-AUC alone.** All four
   detectors look identical under AUC and differ by 2x under the metrics that
   matter.

The Extended Isolation Forest is a genuine improvement over the incumbent, but
it is not worth deploying ahead of items 1 through 5, and it costs 3.8 times the
model size. CUSUM as calibrated here is not an improvement at all and should not
be deployed without a different calibration strategy.

---

## What Was Deliberately Not Changed

These files were left exactly as they were, so the documented pipeline still
works and the three-way feature definition stays in sync:

- `python/features.py`
- `python/simulate_activity.py`
- `python/train_isolation_forest.py`
- `python/verify_parity.py`
- `models/model.json`, `models/model.joblib`
- everything under `src/`
- `testdata/*.csv`

The one thing the new code borrows from the old is
`train_isolation_forest.export_model_json`, used unmodified to measure the real
exported size of the forest rather than estimating it.
