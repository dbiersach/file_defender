# Experiments and Findings

*Tests of three recommendations from
[`WHY_ISOLATION_FOREST.md`](WHY_ISOLATION_FOREST.md).*

The rationale document proposes four improvements. This guide follows the
tests of three of them: combining scores over time, comparing simpler
detectors, and using Extended Isolation Forest. The sections keep the
original recommendation numbers: 1, 2, and 4. Later sections examine two
other findings about the training data and the shipped model.

Two details about the setup matter when reading the results:

1. **The experiments run separately from the monitoring pipeline.** Each
   has its own file. They leave `features.py`, the trainer's scoring, the
   simulators, and the daemon's behavior unchanged. The README demos still
   work, and the three feature definitions remain in agreement. A separate
   change to the collector's entropy rule is described at the end.
2. **The results can be reproduced.** The commands below generate the
   tables. The discussion includes both improvements and unsuccessful ideas,
   since both help determine what to try next.

All the data here is synthetic, meaning generated rather than recorded from
a live machine. It was designed to resemble real activity, but the person
who designed it also evaluated the detectors. This is a limitation of every
comparison below.

---

## Experiment Files

| File | Purpose |
| --- | --- |
| [`python/score_smoother.py`](../python/score_smoother.py) | EWMA and CUSUM aggregation over the score stream (improvement 1) |
| [`python/demo_temporal_aggregation.py`](../python/demo_temporal_aggregation.py) | Attack-pace sweep measuring what that aggregation buys |
| [`python/baseline_detectors.py`](../python/baseline_detectors.py) | Robust z-score and Mahalanobis detectors (improvement 2) |
| [`python/extended_isolation_forest.py`](../python/extended_isolation_forest.py) | Extended Isolation Forest with slanted cuts (improvement 4) |
| [`python/evaluation.py`](../python/evaluation.py) | Labeled feature rows, shared threshold rule, operational metrics |
| [`python/compare_detectors.py`](../python/compare_detectors.py) | The four-way comparison harness |
| [`python/simulate_realistic_baseline.py`](../python/simulate_realistic_baseline.py) | A benign baseline hard enough to tell detectors apart |
| [`python/inspect_model.py`](../python/inspect_model.py) | Reports what a trained forest actually contains |
| [`python/subsample_sweep.py`](../python/subsample_sweep.py) | What the subsample size does, in two settings |

Reproduce every table in this document with these commands:

```sh
uv run python python/demo_temporal_aggregation.py
uv run python python/compare_detectors.py --paces 600 300 120 60 30 --seeds 5
uv run python python/extended_isolation_forest.py
uv run python python/inspect_model.py
uv run python python/subsample_sweep.py
```

---

## Before Comparing Detectors: More Challenging Test Data

To compare the detectors, we first needed data on which they could make
different mistakes. The original examples were useful for demonstrating the
pipeline, but too easy to show which detector worked better.

`simulate_activity.py` generates a deliberately easy dataset. Its benign
processes emit only `open`, `read`, `write`, and `close`, and each stays in one
directory, so `rename_delete_rate` is 0.0 in every benign window and
`unique_directory_count` is 1.0 in every benign window. Every candidate
scores perfectly on this simple setup, so it cannot distinguish their
strengths and weaknesses.

It also affects what the shipped model can learn
(see [The Shipped Model Ignores Two Features](#the-shipped-model-ignores-two-features)).

[`simulate_realistic_baseline.py`](../python/simulate_realistic_baseline.py)
adds the three benign behaviors that generate false positives in real life:

| Benign behavior | Why it matters |
| --- | --- |
| Editors delete swap files, LibreOffice cycles lock files, the browser discards `.part` downloads | Gives `rename_delete_rate` a real, nonzero benign distribution |
| The browser writes `.zip` and `.jpg` files at 7.4 to 7.6 bits/byte | `average_byte_entropy` alone can no longer separate the classes |
| `git gc` repacks and `restic` runs a backup sweep | Fast, broad, high-entropy, delete-heavy, and completely benign |

The resulting benign baseline (90 simulated minutes, 6482 windows) has a mean
write entropy of 7.90 bits/byte for `git` and 7.92 for `restic`, which is
indistinguishable from ransomware output. The simulator also supplies
`generate_paced_attack(files_per_minute)`. Its argument controls the
attacker's pace, so the experiments can test the same detection rules
against faster and slower attacks.

---

## Improvement 1 - Temporal Aggregation

### The gap

The daemon remembers recent events in a rolling window, but it does not
remember the sequence of scores from earlier windows. An attacker whose
windows remain below the threshold can therefore continue without triggering
an alert. Changing the tree count, subsample size, or threshold does not add
that missing history to the model.

### The two aggregation rules

*Temporal aggregation* means combining measurements over time. Here the
measurements are the scores for one process. The two rules in
[`score_smoother.py`](../python/score_smoother.py) keep a small amount of
state between scores and update it with a few arithmetic operations per
event.

**EWMA: an exponentially weighted moving average.** Let $x_i$ be the newest
score and $s_{i-1}$ the previous average. The new average is

$$s_i = \alpha \, x_i + (1 - \alpha)\, s_{i-1}$$

The setting $\alpha = 0.15$ controls how much the new score contributes.
The rest comes from the previous average, which already contains information
from earlier scores. This gives an average over roughly seven recent scores
and lets the detector respond when a process remains mildly unusual.

**CUSUM: a one-sided cumulative sum.** Instead of averaging the scores,
this rule accumulates how far they rise above a reference level:

$$S_i = \max\left(0,\; S_{i-1} + \left(x_i - \mu_0 - k\right)\right)$$

Here $\mu_0$ is the mean benign score. The extra allowance $k$, called a
*dead band*, is set to half a benign standard deviation. It prevents small
fluctuations around the benign mean from immediately building up the sum.

Each new score adds $x_i - \mu_0 - k$ to the previous total. Scores above
that reference increase the total; lower scores reduce it. The maximum with
zero keeps the total from becoming negative. After a brief burst, the total
can return to zero. A sustained elevation keeps adding to it, allowing an
alert based on persistence rather than a single large score.

Both rules update once per scored window, which means once per event, not once
per second. "Seven recent scores" might cover a few seconds for a busy
process or a few minutes for a quiet one. The same averaging rule therefore
covers different amounts of elapsed time at different attack paces.

For the instantaneous rule and EWMA, calibration follows the forest's
existing method. Score the benign data, sort the values of the statistic,
and choose the $(1 - \text{max\_fpr})$ quantile, or percentile expressed as
a fraction.

CUSUM uses a different calibration here. Its running total depends on the
earlier scores, so the experiment sets its limit just above the largest
total reached by any benign process, rather than using a per-window
quantile. This is one possible strategy, not the only one. A different
calibration would give different results.

### The pace sweep

One hand-built slow attack would tell us little about the range of paces a
detector can catch. Instead,
[`demo_temporal_aggregation.py`](../python/demo_temporal_aggregation.py)
tests paces from 600 files/minute down to 1 file/minute. It runs five
attacker seeds at each pace. A seed fixes the random choices for a run,
making that run reproducible while allowing variation between runs.

The table reports the median number of files written before the first
alert: sort the five results and take the middle one. Lower is better.
A result of 24 out of 24 means all the files were written.

"Files lost" here counts the attacker's `write` events at or before the alarm,
including the write that triggered it, since the daemon only scores a window
after the event that filled it has happened. It is a simulation proxy: one
`write` row stands for one whole file, and there is no queueing or reaction
delay in the simulator. It is a way to compare the rules under the same
conditions, rather than a direct measurement of losses on a live computer.

### Pace sweep results

**Calibration 1, every benign process included.** Thresholds:
instant $\ge 0.7503$, EWMA $\ge 0.7383$, CUSUM $\ge 64.74$.

```text
 files/min  attack len          instant             ewma            cusum
-------------------------------------------------------------------------
       600         2 s            19/24            18/24      24/24 (5/5)
       300         5 s            20/24            18/24      24/24 (5/5)
       120        12 s            20/24            18/24      24/24 (5/5)
        60        24 s      24/24 (5/5)      24/24 (5/5)      24/24 (5/5)
        30        48 s      24/24 (5/5)      24/24 (5/5)      24/24 (5/5)
        12       2 min      24/24 (5/5)      24/24 (5/5)      24/24 (5/5)
         6       4 min      24/24 (5/5)      24/24 (5/5)      24/24 (5/5)
         3       8 min      24/24 (5/5)      24/24 (5/5)      24/24 (5/5)
         1      24 min      24/24 (5/5)      24/24 (5/5)      24/24 (5/5)
```

`(5/5)` marks paces where the rule never fired in any of the five runs.

**Calibration 2, `git` and `restic` left out of the calibration.** Thresholds:
instant $\ge 0.5218$, EWMA $\ge 0.4764$, CUSUM $\ge 8.878$.

```text
 files/min  attack len          instant             ewma            cusum
-------------------------------------------------------------------------
       600         2 s             2/24             3/24            12/24
       300         5 s             3/24             4/24            12/24
       120        12 s             3/24             4/24            12/24
        60        24 s             3/24             4/24            12/24
        30        48 s             3/24             4/24            15/24
        12       2 min            20/24             5/24      24/24 (5/5)
         6       4 min      24/24 (3/5)      24/24 (5/5)      24/24 (5/5)
         3       8 min      24/24 (5/5)      24/24 (5/5)      24/24 (5/5)
         1      24 min      24/24 (5/5)      24/24 (5/5)      24/24 (5/5)
```

Calibration 2 changes threshold selection, not model training. The forest
still trains on every benign process, including `git` and `restic`. Those
two are excluded only when choosing thresholds and reporting benign false
alarms. This lets us examine the effect of a lower threshold, but does not
implement an allowlist or decide how to handle the two programs in practice.

### Reading the pace sweep

**EWMA helps at one pace.** At 12 files/minute the instantaneous rule loses
20 of 24 files while EWMA loses 5. That is the expected benefit of combining
scores that remain mildly elevated. Everywhere else, EWMA is within one or
two files of the instantaneous rule.

**CUSUM does not improve detection with this calibration.** It is 9 to 12
files worse than the instantaneous rule at every pace it detects at all, and it never fires
in calibration 1. The reason is visible in the benign data: `git`'s CUSUM
statistic peaks at 47.9 and `restic`'s at 33.3 during their bursts, so a limit
that tolerates them must sit above 64, and the attacker only produces 96
observations. The statistic cannot climb that far before the attack is over.
CUSUM is intended to detect a small, sustained shift. Here the attack does
not last long enough for the statistic to overcome a limit that tolerates
the benign bursts. A different calibration might perform better; the one
tested here does not.

**The tested rules do not detect attacks below 6 files/minute.** To see why,
follow one window for a patient attacker. The activity for one file is
`open`, `read`, `write`, and `delete`, spread over about 0.2 seconds. In a
10-second window, this gives:

- `events_per_second` $= 0.4$ (benign median 0.6)
- `writes_per_second` $= 0.1$ (benign median 0.2)
- `average_byte_entropy` $= (0 + 5.2 + 7.9 + 0) / 4 = 3.3$ (benign median 2.4)
- `unique_directory_count` $= 1$, `unique_extension_count` $= 2$

These feature values are within the range of ordinary activity. The mean
score is also ordinary: 0.424 for the attacker, compared with a benign mean
of 0.428. There is no elevated mean score for these rules to accumulate.

Part of the reason is how `average_byte_entropy` is defined. It averages over
all events in the window, including the zero values assigned to `open` and
`delete`. Those zeros lower the average containing the high-entropy write.
Before changing that definition, two points need attention:

- This arithmetic uses the simulator's entropy rule (`open`, `close`, and
  `delete` carry 0.0). The live classic collector now follows the same rule
  for `open` and `close`, and the FID collector reports 0.0 for `delete`
  because it has no file content, so the dilution would be real on a live
  machine too. But it has only been measured in the simulator.
- Averaging over writes only is a possible change that has not been tested.
  It would change the feature in all three places it is defined and would
  need both parity checks rerun. Whether it recovers slow attacks at an
  acceptable false-alarm rate is an open question, not a result.

**False-alarm rates on a new session exceed the target.** In calibration 2,
66 of 5762 held-out benign windows trip the instantaneous rule, which is 1.15%
against a 0.5% target, and EWMA reaches 1.6%. Both thresholds were fitted on one
benign session and evaluated on another. The target rate did not carry over.
Choosing a threshold from a quantile does not guarantee the same false-alarm
rate on new data.

### Porting to the C++ daemon

`TemporalDetector` holds four doubles of state per process. In
[`main.cpp`](../src/daemon/main.cpp) it would live beside the `FeatureWindow` in
the per-pid map and be updated with the score that is already computed after
every event. This needs no new dependency and adds no measurable cost.

---

## Improvement 2 - Baselines

### Why baselines

A more complicated detector is useful only if its extra work improves the
result. To test that, we compare the forest with two simpler methods in
[`baseline_detectors.py`](../python/baseline_detectors.py). These are called
*baseline detectors*: reference methods against which to judge the forest.
Both train on benign data only, keeping the same training requirement as
the main project.

**Robust z-score.** This method first finds the median value of each feature
in the benign training data. It then measures each value's absolute distance
from that median and takes the median of those distances. That second
quantity is the *median absolute deviation*, or MAD, a measure of spread.

For a new window, each feature is compared with its benign median and scaled
by its MAD. The largest positive deviation becomes the score:

$$s(x) = \max_j \; \max\left(0, \; \frac{x_j - \text{median}_j}{1.4826 \cdot \text{MAD}_j}\right)$$

The formula uses MAD instead of standard deviation because the benign data
contains bursts. A single `git gc` burst would inflate a standard deviation
enough to hide an attack. The factor 1.4826 supplies the scale used by this
robust z-score.

The inner maximum replaces negative deviations with zero. A value below
the benign median therefore does not raise the score. The outer maximum
selects the largest deviation among the features. This explicitly encodes
the project's directional rule: high values are suspicious; low values
are not. The forest is not given that rule.

**Mahalanobis distance.** The second baseline fits a single Gaussian, or
bell-shaped, model to the benign feature vectors. Think of each vector as a
point with six coordinates. This method measures how far a new point is from the center
of the benign group, while accounting for how the coordinates vary together:

$$d(x) = \sqrt{(x - \mu)^{\mathsf{T}} \, S^{-1} \, (x - \mu)}$$

In the formula, $x$ is the new feature vector and $\mu$ is the mean benign
vector. The covariance matrix $S$ records how the features vary, both
individually and together. Its inverse, $S^{-1}$, adjusts the distance using
those relationships. You do not need to work through the matrix arithmetic
to understand why the relationships matter.

For example, a high write rate is unremarkable when the event rate is high
too, because those rates rise together in benign windows. A high write rate
paired with a low event rate is a different combination, even when neither
number is individually extreme. Mahalanobis distance accounts for this
relationship, which an axis-aligned isolation tree handles poorly.

The code estimates covariance using Ledoit-Wolf shrinkage, which keeps the
matrix invertible even with a short baseline. Unlike the one-sided z-score,
this detector measures distance in either direction. An unusually quiet
window can score the same as an unusually busy one at the same distance
from the center.

### The four-way comparison

[`compare_detectors.py`](../python/compare_detectors.py) fits all four detectors
on the same 6482 benign windows, calibrates each by the identical rule (the
99.5th percentile of its own benign training scores), and evaluates all four on a
held-out benign session plus a ransomware sweep. *Held out* means that this
session was not used to train the models.

In the table, benign FPR is the fraction of benign windows flagged by the
detector. Recall is the fraction of attack windows flagged, not the fraction
of attacks caught: one attack produces many windows. Latency is the time
until the first alert. ROC-AUC and average precision summarize performance
over thresholds rather than at only the chosen alert threshold; the
discussion below explains why those summaries can give different impressions.

### Comparison results

At 120 files/minute, target false-positive rate 0.5%, attacker seed 5:

| detector | benign FPR | recall | ROC-AUC | avg prec | files lost | latency | model |
| --- | --- | --- | --- | --- | --- | --- | --- |
| isolation_forest | 0.34% | 16.7% | 0.932 | 0.302 | 20 / 24 | 9.6 s | 562 KB |
| robust_zscore | 0.43% | 25.0% | 0.921 | 0.283 | 18 / 24 | 9.0 s | **0.4 KB** |
| mahalanobis | 0.40% | **54.2%** | 0.925 | **0.646** | **11 / 24** | **5.5 s** | 1.1 KB |
| extended_forest | 0.32% | 28.1% | 0.929 | 0.462 | 17 / 24 | 8.1 s | 2115 KB |

The ordering is consistent across repeated runs. Here are median files lost
at five paces, using five attacker seeds at each pace
(`--paces 600 300 120 60 30 --seeds 5`):

| detector | 600 | 300 | 120 | 60 | 30 |
| --- | --- | --- | --- | --- | --- |
| mahalanobis | 10 | 11 | 11 | 23 | 24 |
| extended_forest | 17 | 17 | 17 | 24 | 24 |
| robust_zscore | 18 | 18 | 18 | 24 | 24 |
| isolation_forest | 19 | 20 | 20 | 24 | 24 |

At 60 files/minute the Mahalanobis detector is the only one of the four whose
median run alerts at all, and it does so with one file to spare.

### Reading the comparison

**Mahalanobis distance gives the strongest operational results here.**
At the same target false-alarm rate, the Mahalanobis detector loses about half
as many files, alerts in about half the time, and doubles the average
precision. It is 500 times smaller, needs no tree walk, and ports to C++ as a
mean vector and a $6 \times 6$ matrix. It is not better on *every* column: its
achieved false-positive rate is a little higher than the forest's (0.40%
against 0.34%) and its ROC-AUC is a little lower. The four detectors do not
land on identical false-alarm rates even though they share a target, so read
the table as a comparison at similar rather than identical false-alarm
rates. With these six features and this data, Isolation Forest is not the
best available choice. Keeping it requires reasons beyond detection quality
on these tests.

**ROC-AUC alone does not show the operational difference.** All four
detectors fall between 0.921 and 0.932, while files lost varies by a factor
of two. AUC averages over every
possible threshold, including ones no defender would deploy. Average precision,
which weights the high-score region where the alert threshold actually sits,
separates them: 0.65 against 0.30. Neither is a measurement at the deployed
threshold, though; files lost and latency are. Report those first.

**The z-score gives a simpler explanation for an alert.** It roughly
matches the forest on files lost with a 0.4 KB model, and its alert names the
responsible feature: the attacker's worst window is flagged as
`events_per_second` at 17.1 robust sigmas above the benign median. Here a
robust sigma is the spread measure used in the z-score formula. The message
identifies both the feature and the size of its deviation. That is easier
to interpret than a statement that the average path through 200 trees was
short, whether you are learning the method or deciding how to respond.

**The false alarms involve the same benign applications, with one difference.**
`git` and `restic` trip the forest, the extended forest, and the Mahalanobis
detector. The z-score rule flags `restic` but not `git`. This is not a
modeling failure; those processes really do write high-entropy data quickly
across many directories while deleting files.

### Caveats

- The data is synthetic, designed by the same person who evaluated the
  detectors on it.
- The Mahalanobis detector assumes one Gaussian group. Real benign activity
  has several modes, such as idle time, editing, compiling, and backing up.
  It performs best here despite that limitation. A Gaussian mixture, which
  represents more than one group, is a natural next step; a second benign
  session might also narrow the performance gap.
- Thresholds were calibrated on one benign session, and the out-of-sample
  false-positive rates in improvement 1 show that single-session calibration
  overshoots its target by two to three times.
- Model fitting and threshold calibration used the same benign session. A
  stricter design would fit on one session, calibrate on a second, and test on
  a third.

---

## Improvement 4 - Extended Isolation Forest

### The geometric problem

A standard isolation tree splits on one feature at a time, so every cut is
perpendicular to an axis and every leaf owns an axis-aligned box. When the
benign data is correlated, the union of those boxes covers rectangular regions
containing no training data at all. A point in such a region can take a long
path and receive a normal score even though nothing like it was ever observed.
(Successive axis-aligned cuts *can* approximate a diagonal shape; they just do
it inefficiently and leave gaps.)

### The slanted-cut forest

[`extended_isolation_forest.py`](../python/extended_isolation_forest.py)
implements the Hariri, Kind and Brunner (2018) algorithm in NumPy. Each node
draws a random unit direction $w$ and a random point $p$ inside the node's
bounding box, and splits on

$$w \cdot x + b \le 0, \qquad b = -(w \cdot p)$$

The score formula is unchanged, so the daemon's threshold logic would not need
to change. Setting `extension_level=0` gives axis-aligned cuts, which makes the
parameter a dial between the two designs. It is an axis-aligned *variant* of
this code, not an exact copy of scikit-learn; see
[`ABOUT_THE_TREE.md`](ABOUT_THE_TREE.md) for the difference.

The export mirrors `models/model.json`, with a `normal` vector and a `bias`
scalar per node in place of `feature` and `threshold`. Running the module
directly re-scores a sample straight from the serialized dict and confirms it
reproduces the in-memory model exactly. That shows the export is complete and
a C++ port is possible.

### Testing an unobserved combination of features

`compare_detectors.py` finds the pair of features that vary together most
strongly. It then creates two test points, called *probes*. Starting with
the median benign feature vector, it moves one of the pair to its 97.5th
percentile and the other to its 2.5th, then reverses the two roles for the
other probe. Each coordinate stays within the benign range, but the
combination can be unusual. A method examining each coordinate separately
does not see that difference.

The most correlated pair is `events_per_second` and `writes_per_second`, with
$r = 0.973$. Training windows with the first in its top decile and the second in
its bottom decile: **0 of 6482**. The region is unobserved.

| detector | threshold | probe A | probe B | flags A | flags B |
| --- | --- | --- | --- | --- | --- |
| isolation_forest | 0.7503 | 0.5154 | 0.5145 | no | no |
| robust_zscore | 14.97 | 8.77 | 8.77 | no | no |
| mahalanobis | 8.44 | **10.99** | **16.36** | **yes** | **yes** |
| extended_forest | 0.7680 | 0.6014 | 0.6291 | no | no |

The script warns that probe A has 1.5 writes per second
and 0.1 events per second. Writes are a subset of events, so no real window can
look like that. This is a geometric test of the detectors' responses to an
unobserved combination, not evidence of a realizable ransomware attack.

### Reading the probe

**The extension improves scores without flagging the probes.** It raises the
score from about 0.515 to 0.60 or 0.63, a third of the way to its threshold:
the change is in the predicted direction. In
the detection comparison it beats the standard forest at the three faster
paces (600, 300, and 120 files/minute), cutting files lost from 20 to 17 and
raising average precision from 0.30 to 0.46, and ties with it at the two
slower paces, where both lose every file. But it still does not flag the
probes, and its detection results remain worse than the 1.1 KB Gaussian model's.

**The cost is a 3.8x larger model.** 2115 KB against 562 KB, because each node
now stores a six-vector instead of a feature index and a threshold. Scoring cost
in C++ would be one dot product per node instead of one array lookup.

**Standardization affects the extended forest.** Sliding and stretching a single
feature cannot move an axis-aligned cut relative to the data, which is why
`StandardScaler` changes nothing for the standard forest. A slanted cut mixes
features, so their relative scales change which directions are likely to be
drawn. For this algorithm, scaling is part of what determines the trained model.

---

## The Shipped Model Ignores Two Features

Inspecting the shipped model reveals a limitation that is separate from
the detector comparisons: two of its input features are never used in a
split.

`models/model.json` is trained on `testdata/benign_baseline.csv`. In that file,
`rename_delete_rate` is 0.0 in every window and `unique_directory_count` is 1.0
in every window. A tree cannot split on a feature that never changes, so no
tree in the shipped forest splits on either one. `python/inspect_model.py`
shows it directly:

```text
  [2] rename_delete_rate       NEVER USED  (root split in 0 of 200 trees)
  [4] unique_directory_count   NEVER USED  (root split in 0 of 200 trees)

  rename_delete_rate       0.0000  <- the model cannot see this feature
  unique_directory_count   0.0000  <- the model cannot see this feature
```

The second block sets each feature to one million on the demo windows and
measures how much the scores move. For those two, they do not move at all.

It is easy to read a six-feature table and assume that all six contribute
to every trained model. Here they do not. In particular, a zero delete rate
throughout training does not make a single delete trigger an alert. It
leaves the model unable to respond to that feature at all. The separate
synthetic-feature training mode, `--synthetic`, generates varying values
for those features, so a model trained that way does use them.

The trainer warns after each run about features never used in a split.
For the shipped model, using those features requires better training data,
not different scoring code. Retraining on the
realistic baseline does make the forest use all six features, but that baseline
contains `git` and `restic`, the threshold rises to about 0.75, and neither
README demo flags its attacker anymore. So the shipped model was left as it is,
with its blind spot documented, until a real benign recording exists.

---

## The Real Bottleneck

The choice of benign activity used for calibration had a larger effect on
the results than any of the three proposed improvements.

In calibration 1, the false-positive budget is consumed entirely by two benign
processes. `git gc` and `restic` sit at the top of the benign score
distribution, with mean scores of 0.627 and 0.667 against a global benign mean of
0.428. Tolerating them forces the threshold up to 0.750, and at that threshold no
attacker slower than 120 files/minute is detected at all. Even a fast attack
still results in 19 of 24 files lost.

Leave those two processes out of the calibration, and the threshold drops to
0.522. At 120 files/minute the same attacker now loses 3 files instead of 20,
and detection extends down to 30 files/minute. For scale: the best algorithmic
change in this document, the Mahalanobis detector, took files lost at 120
files/minute from 20 to 11, and EWMA took it from 20 to 18.

The conditions differ between those comparisons.
The algorithm changes were measured at a matched false-alarm target on the
whole benign population. Leaving `git` and `restic` out changes the population
the false-alarm rate is measured on *and* the achieved rate (1.15% instead of
0.34% on the remaining processes), not just the threshold. What the numbers
show is that the threshold's position matters more here than the detector
behind it, and that two programs largely determine that position. How to
handle those programs safely remains a separate, unsolved question.

This points back to recommendation 3 in `WHY_ISOLATION_FOREST.md`, which
was not among the three implemented proposals. The results make it the
first priority, with two qualifications:

- The experiment excludes the two programs from calibration and reporting. It
  does not build a separate baseline for them, and the forest is still trained
  on their windows. A real deployment still has to decide what to do with them.
- **Do not allowlist by process name.** The collector reads the name from
  `/proc/<pid>/comm`, which any program can set to anything. A process that
  calls itself `restic` has not established its identity. An allowlist needs the
  executable's path and owner at minimum, ideally a hash or package signature,
  and it should still cap how much a trusted program is allowed to do.

---

## Next Experiments

The results suggest the following order of work:

1. **Record real benign activity, including demanding tasks.** Record an actual
   session with backups, compiles, package upgrades, and media transcoding. The
   evidence above makes this more important than the choice of model. It is
   also the natural way to get training data in which all six features vary. Whether a
   model trained on a real recording still flags the README demos is
   something to measure, not assume; the synthetic realistic baseline did
   not.
2. **Identify known applications and give them their own baseline.**
   Per-program statistics or an explicit allowlist with a separate threshold,
   keyed on executable path and owner, never on the name alone. This is what
   recovers the improvement in "The Real Bottleneck."
3. **Test write-only `average_byte_entropy`.** Average the entropy of `write`
   events only, instead of diluting it with zero-entropy `open` and `delete`
   events. This is the most plausible way to make a patient attacker visible,
   and it has not been measured. It requires changing the feature in all three
   places and rerunning both parity checks.
4. **Add the Mahalanobis detector to the daemon, alongside the forest.** It is
   1.1 KB, it wins on files lost and latency here, and it is 36
   multiply-accumulates in C++. If the two are combined ("alert when either
   fires"), the combination has to be calibrated as one system: two detectors
   each aimed at 0.5% do not add up to a 0.5% combined rate.
5. **Add the EWMA layer.** Four doubles per process, and worth 15 files at the
   one pace where per-window detection is marginal.
6. **Report average precision and files lost, never ROC-AUC alone.** All four
   detectors look identical under AUC and differ by 2x under the metrics that
   matter.
7. **Evaluate with three separate sessions.** Use one session to fit the
   model, a second to choose the threshold, and a third to test it. Repeat
   with several seeds. This tests whether the chosen false-alarm target
   carries over to activity not used to choose it.

Extended Isolation Forest improves on the standard forest here, but items
1 through 5 deserve priority before deploying a model 3.8 times as large.
CUSUM does not improve the results with this calibration and should not be
deployed without trying a different calibration strategy.

---

## Relationship to the Monitoring Pipeline

The experiments leave the monitoring pipeline's feature calculations and
scores unchanged. The following files are unchanged or have only the noted
comments, warnings, and checks:

- `python/features.py` (unchanged)
- `python/simulate_activity.py` (comments only)
- `python/train_isolation_forest.py` (prints a feature-usage warning)
- `python/verify_parity.py` (adds a boundary check; the main check is unchanged)
- `models/model.json`, `models/model.joblib` (unchanged)
- `src/daemon/*` (a `--dump-features` flag was added for the C++ parity check;
  scoring is unchanged)
- `testdata/*.csv` (unchanged)

The one behavior change outside the experiments is in the collector:
`src/collector/fanotify_collector.c` now reports entropy 0.0 for `open` and
`close` events and samples the file only on `read` and `write`, matching the
rule both simulators already used, instead of sampling on every event. The
training data was generated under that rule already, so no table changed.
