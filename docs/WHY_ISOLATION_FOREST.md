# Why Isolation Forest?

*Why this project uses Isolation Forest, and where that choice falls short.*

Why use Isolation Forest to detect unusual file activity? Choosing a model
means considering both how well it detects attacks and how it will run on the
computer being protected. Isolation Forest fits several of this project's
requirements, but those advantages do not make it the best detector in every
test.

This document explains the choice, then looks at three limitations. It ends
with the experiments proposed to investigate them.

For how the algorithm actually works and where it sits in the pipeline, see
[`ENTROPY_AND_ML_EXPLAINED.md`](ENTROPY_AND_ML_EXPLAINED.md).

---

## Part 1 - Why It Fits This Project

### 1. The research claim requires one-class learning

The model is trained **only on benign data**, meaning ordinary activity rather
than attacks. As the [`README.md`](../README.md#L78) explains, it does not need
ransomware samples for training. This approach is called *one-class learning*:
the model learns one class of behavior and looks for activity that differs
from it.

That requirement rules out classifiers trained to distinguish labeled benign
and attack examples, such as a random forest classifier, gradient-boosted
classifier, or neural network trained on labeled attack traffic. Those
detectors learn from the ransomware families represented in their training
sets. New families continue to appear. Learning normal behavior instead gives
a one-class model a way to flag a family that did not exist during training.

Several methods can be used for one-class learning:

| Candidate | Family |
| --- | --- |
| Isolation Forest | Tree-based isolation |
| One-class SVM (SVDD) | Kernel boundary |
| Local Outlier Factor (LOF) | Local density |
| Elliptic Envelope / Mahalanobis | Single Gaussian |
| Gaussian Mixture Model | Multi-modal density |
| Autoencoder | Reconstruction error |

### 2. The model must run inside a small C++ program

Training runs in Python, but the daemon must score events with **no Python or
machine-learning library** running alongside it. It loads the saved model
from a JSON file and uses
[`src/daemon/anomaly_model.cpp`](../src/daemon/anomaly_model.cpp) to calculate
scores. This limits which methods are practical:

- **LOF** keeps the entire training set in memory while scoring. For every
  new window, it searches for the closest training examples, a step called a
  k-nearest-neighbor query. That repeated search does not fit the intended
  always-on daemon, which scores after every filesystem event.
- **One-class SVM** keeps selected training points called support vectors.
  Each score requires a kernel calculation against each of them. It could be
  implemented in C++, but scoring is slower and its behavior is sensitive to
  the training settings `nu` and `gamma`.
- **An autoencoder** could also be saved and evaluated with plain arithmetic,
  so the runtime requirement does not rule it out. The remaining obstacles
  are training and evidence. It needs a training framework and far more benign
  data than this project has. It would also need to show that learning a
  compressed representation of these six hand-picked inputs is useful. That
  has not been demonstrated here.
- **Isolation Forest** can be saved as integers and floating-point numbers:
  a feature index, a threshold, and two child indices per node. To score a
  window, the daemon follows the comparisons through each of the 200 trees.

This simple saved representation is a major reason for choosing Isolation
Forest. *Serialization* means writing a model's structure and numbers into a
file so another program can read them. Here, that file is
[`models/model.json`](../models/model.json).

### 3. The feature set is small

Isolation Forest can struggle when it is given many features that have little
to do with the behavior being studied. Since it chooses split features at
random, it spends cuts on those irrelevant measurements. Points then become
similarly easy to isolate, making their scores less useful.

This project uses six features chosen to describe file activity, rather than
a large collection of unrelated measurements (see
[`python/features.py`](../python/features.py#L23-L30)). That avoids this
particular high-dimensional failure mode.

### 4. Scores can be used to choose an alert threshold

The score is bounded in $(0, 1)$:

$$s(x) = 2^{\,-\dfrac{E[h(x)]}{c(n)}}$$

Higher scores mean more unusual windows. To choose a threshold, first score
the benign training windows, then sort their scores. A high percentile picks
a value near the top of that ordered list. The trainer uses this value as the
alert threshold
([`train_isolation_forest.py`](../python/train_isolation_forest.py#L141-L142)):

```python
anomaly_scores = -model.score_samples(x_scaled)
recommended_threshold = float(np.quantile(anomaly_scores, 1.0 - args.max_fpr))
```

Choosing the threshold from data is called *calibration*. The default rule
aims to flag about 0.5% of the benign windows used for calibration. It does
not promise the same rate on future activity. In the second-session test
([`EXPERIMENTS_AND_FINDINGS.md`](EXPERIMENTS_AND_FINDINGS.md)), the measured
rate was 1.15%.

The score's range from 0 to 1 is convenient to read, but it is not what makes
calibration possible. Any detector with scores that can be sorted, including
one-class SVM and Mahalanobis distance, can use the same rule. The comparison
in `EXPERIMENTS_AND_FINDINGS.md` does this for all four detectors. Calibration
is therefore a shared part of the evaluation, not an advantage unique to the
forest.

### 5. Teaching value

The main idea is easy to follow: unusual points tend to be separated from
other points after fewer random cuts. A student can trace those cuts through
a tree and see how path length contributes to a score. That makes Isolation
Forest useful in a project intended to teach both programming and detection.

---

## Part 2 - Three Limitations

### Weakness 1: no memory beyond the rolling window

The model does receive some information about time. Three features are rates,
and all six describe activity over the last 10 seconds. However, it scores
each window without remembering the previous window's score. Neighboring
windows share many events, but the forest does not use the sequence of scores
to make its decision.

A "low and slow" attacker encrypting three files per minute keeps each
window within the range of benign activity. Whether ten minutes of that
behavior could be distinguished from ordinary use remains an open question.
The current forest cannot examine that longer pattern because it receives
one window at a time.

Changing `n_estimators`, `max_samples`, or the threshold does not give the
model a memory of earlier scores. That limitation comes from how the model
is used, rather than from those settings.

To use information from earlier scores, the proposal is to add *temporal
aggregation*: combine a process's recent scores rather than treating them
separately. An exponentially weighted moving average or a CUSUM statistic
can accumulate sustained, mildly elevated scores into an alert, even when no
single window crosses the threshold. This is a small addition to
[`src/daemon/main.cpp`](../src/daemon/main.cpp). When it was built and
measured (see `EXPERIMENTS_AND_FINDINGS.md`), it helped at one pace where
detection was marginal. It did not recover the slowest attacks, whose scores
were not even mildly elevated. It narrows the gap rather than closing it.

### Weakness 2: it flags "unusual", not "malicious", and it is direction-blind

Isolation Forest is never told which *direction* along a feature axis is
suspicious. It flags whatever is rare. If the benign data happened to be
lopsided, its score would be lopsided too, so the score is not perfectly
symmetric; but nothing in the algorithm lets you write down the rule "more is
worse, less is fine."

The intended detection rule is directional: entropy rising toward 8.0 is
suspicious, while entropy falling toward 0.0 is not. A standard Isolation
Forest has no way to encode that rule directly.

The practical consequence is that the model will flag legitimate workloads that
happen to look extreme in the same six dimensions:

| Benign workload | Why it trips the same features |
| --- | --- |
| `tar`, `restic`, `borg` backups | High event rate, many directories, many extensions |
| `ffmpeg` transcoding | Write-heavy at entropy ~7.9 (compressed output) |
| `git gc` / repacking | Bursty writes, high-entropy packfiles |
| `apt upgrade` | Sweeps the filesystem, touches every extension |

These workloads are important sources of false alarms. The forest can learn
that their feature values are normal only if they appear in the training
data. Otherwise it flags them as unusual; the algorithm does not separately
recognize that a backup or package upgrade is legitimate.

### Weakness 3: axis-aligned splits miss correlations

Each standard Isolation Forest cut uses one feature at a time. On a plot
of two features, these cuts make horizontal and vertical boundaries, dividing
the plot into rectangles. This is what *axis-aligned* means.

A known problem is that gaps between groups of training points can receive
low scores. A point in a gap should look unusual, but may remain inside
the same rectangular regions as ordinary points because the single-axis
cuts do not separate it.

Extended Isolation Forest replaces these cuts with slanted, or *oblique*,
cuts and removes this artifact. In more dimensions, the dividing surface
is called a hyperplane. It can still be saved as numbers: a coefficient
vector and an intercept per node replace the feature index and threshold.
The scoring calculation in `anomaly_model.cpp` would use a dot product,
which combines several features, in place of the single-feature comparison.
This makes it a straightforward upgrade to the tree-based design.

---

## Part 3 - Why the Scaler Does Not Matter to the Forest

Scaling is important for methods that measure distances between points:
otherwise a feature with large numbers can dominate the calculation.
Isolation Forest does not calculate distances. At each node, scikit-learn
chooses a cut uniformly between one feature's minimum and maximum values.

`StandardScaler` shifts each feature and stretches it by a positive factor.
The minimum, maximum, and random cut all move together, leaving the same
rows on each side. In exact arithmetic, the tree structure, path lengths,
and scores are therefore unchanged.

There are two limits to this argument. First, it applies only to shifts and
stretches. A curved transformation, such as a logarithm, keeps the same
possible splits but changes their probabilities, so it can change the
scores. Second, scikit-learn treats a feature whose values at a node are
closer together than about 1e-7 as constant and skips it. Scaling an extremely
narrow range can make that feature available for splitting. Neither case
affects these six features.

Keeping the scaler is harmless and lets different model types use the same
JSON format. `ENTROPY_AND_ML_EXPLAINED.md` also explains this when introducing
the training steps.

---

## Part 4 - Recommendations

> Recommendations 1, 2, and 4 have been implemented and tested. Read
> [`EXPERIMENTS_AND_FINDINGS.md`](EXPERIMENTS_AND_FINDINGS.md) for the results.
> Two of the proposals helped less than expected, and the evaluation also
> identified a more important issue in the benign data.

Keep Isolation Forest as the primary model. In rough order of value:

1. **Add temporal aggregation.** An EWMA or CUSUM layer over the per-process
   score stream, to catch attackers whose windows are mildly but persistently
   elevated. (Measured result: it helped at one pace, 12 files per minute, and
   did nothing for slower attacks whose windows are not elevated at all.)

2. **Add baselines to the research writeup.** A per-feature robust z-score rule
   and a Mahalanobis-distance detector are each roughly thirty lines, and both
   export to C++ more easily than a forest does (a mean vector and a $6 \times 6$
   inverse covariance matrix is 36 multiply-accumulates, versus 200 tree
   descents). Comparing these simpler methods with the forest tests whether
   the forest's extra complexity improves detection. This recommendation
   calls for evidence for the model choice, rather than relying on the
   reasons it appeared suitable before testing.

3. **Train on benign activity that resembles an attack.** Include backups,
   compiling, media transcoding, and package upgrades. These ordinary tasks
   are important sources of false alarms. Representing them in training is
   a data problem, not a change to the detection algorithm.

4. **Consider Extended Isolation Forest** for better geometry at effectively no
   runtime cost.

---

## Summary

Isolation Forest meets three requirements of the project: it can train on
benign data alone, its saved model can be evaluated with plain arithmetic in
C++, and it suits the small set of behavioral features used here.

The limitations involve different parts of the design. Remembering earlier
scores requires an additional layer above the model. Reducing false alarms
requires better coverage of benign activity. Handling correlated features
calls for slanted cuts or a baseline that accounts for covariance. Replacing
the anomaly detector alone does not address all three.

`EXPERIMENTS_AND_FINDINGS.md` follows the tests of these ideas. In those
results, the choice of benign data mattered more than the algorithm changes.
