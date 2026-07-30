# Why Isolation Forest?

*A design-rationale companion to the File Defender research project.*

This document answers a question a reviewer of the research will eventually
ask: **why is Isolation Forest the machine-learning algorithm here, and is it
the best choice?**

Short answer: Isolation Forest is a defensible and well-matched choice for this
specific design, but for reasons that are partly about the *deployment*
constraints and only partly about detection quality. There are two places where
it is genuinely weak, and this document names them plainly rather than
defending the choice uncritically.

For how the algorithm actually works and where it sits in the pipeline, see
[`ENTROPY_AND_ML_EXPLAINED.md`](ENTROPY_AND_ML_EXPLAINED.md).

---

## Part 1 - Why It Fits This Project

### 1. The research claim requires one-class learning

The central promise in [`README.md`](../README.md#L78) is that the model is
trained **only on benign data, so it needs no ransomware samples**. That single
sentence immediately rules out every supervised algorithm: no gradient-boosted
trees, no random forest classifier, no neural network trained on labeled attack
traffic.

This is not a limitation to apologize for. It is the point. Supervised
detectors learn the ransomware families in their training set, and ransomware
authors ship new families continuously. A one-class model that learns "what
normal looks like" can flag a family that did not exist when the model was
trained.

Once you commit to one-class learning, the realistic candidates are:

| Candidate | Family |
| --- | --- |
| Isolation Forest | Tree-based isolation |
| One-class SVM (SVDD) | Kernel boundary |
| Local Outlier Factor (LOF) | Local density |
| Elliptic Envelope / Mahalanobis | Single Gaussian |
| Gaussian Mixture Model | Multi-modal density |
| Autoencoder | Reconstruction error |

### 2. The runtime constraint eliminates most of the rest

The daemon must score with **no Python and no ML library** at runtime; the
entire model is a JSON file walked by
[`src/daemon/anomaly_model.cpp`](../src/daemon/anomaly_model.cpp). That
constraint is brutal on the alternatives:

- **LOF** needs the entire training set resident at inference time and performs
  a k-nearest-neighbor query for every score. That is a non-starter for an
  always-on daemon that scores after *every* filesystem event.
- **One-class SVM** needs all support vectors plus a kernel evaluation against
  each one, and is notoriously sensitive to its `nu` and `gamma`
  hyperparameters. Portable in principle, fragile and slower in practice.
- **An autoencoder** needs a training framework and far more data than a
  6-dimensional input can justify. Six inputs cannot meaningfully be
  bottlenecked.
- **Isolation Forest** exports to nothing but integers and floats: a feature
  index, a threshold, and two child indices per node. Scoring is 200 tree
  descents of pointer-chasing arithmetic.

That last property is the reason [`models/model.json`](../models/model.json)
works at all. The algorithm was chosen, in large part, because it *serializes*.

### 3. Six dense continuous features is Isolation Forest's sweet spot

Isolation Forest's well-documented failure mode is high dimensionality with
many irrelevant features: random splits waste themselves on noise dimensions,
and every point starts to look equally isolated. With six hand-designed,
all-relevant features (see [`python/features.py`](../python/features.py#L23-L30)),
that failure mode never triggers.

### 4. It provides a direct false-positive-rate knob

The score is bounded in $(0, 1)$:

$$s(x) = 2^{\,-\dfrac{E[h(x)]}{c(n)}}$$

Because the output is bounded and monotone in anomalousness, the alarm
threshold can be set as a **percentile of benign training scores**
([`train_isolation_forest.py`](../python/train_isolation_forest.py#L141-L142)):

```python
anomaly_scores = -model.score_samples(x_scaled)
recommended_threshold = float(np.quantile(anomaly_scores, 1.0 - args.max_fpr))
```

The false-positive rate is therefore set **by construction**, not by tuning.
Mahalanobis distance offers the same property through the chi-square
distribution; one-class SVM does not offer it cleanly.

### 5. Teaching value

"Anomalies are isolated in few random cuts" is a one-sentence intuition, and
path length is directly explainable to a defender asking *why did you flag my
process?* For a project whose style guide leads with teaching value, an
algorithm whose decision can be narrated is worth real points.

---

## Part 2 - Where Isolation Forest Is Actually the Wrong Tool

### Weakness 1: no notion of time

This is the big one. Each 10-second window is scored **independently and
identically distributed**. The forest has no memory of the previous window.

A "low and slow" attacker who encrypts three files per minute keeps every
single window comfortably inside the benign envelope. The aggregate behavior
over ten minutes is unmistakably ransomware, and the forest **cannot see it at
all**.

This is not a tuning problem. It is a model-class problem: no choice of
`n_estimators`, `max_samples`, or threshold fixes it, because the information
needed to detect the attack never enters the model.

The fix is not a different anomaly detector. It is **temporal aggregation on
top of the existing one**: an exponentially weighted moving average or a CUSUM
statistic over each process's score stream, so that sustained mild elevation
accumulates into an alert even though no individual window crosses the
threshold. That is a small, self-contained addition to
[`src/daemon/main.cpp`](../src/daemon/main.cpp), and it closes the most obvious
evasion against the current design.

### Weakness 2: it flags "unusual", not "malicious", and it is direction-blind

Random axis-aligned cuts make the anomaly score **symmetric** in each feature.
Isolation Forest has no way to know which *direction* along a feature axis is
suspicious.

But we do know. Entropy climbing toward 8.0 is suspicious; entropy falling
toward 0.0 is not. Encoding that asymmetry is impossible in a standard
Isolation Forest.

The practical consequence is that the model will flag legitimate workloads that
happen to look extreme in the same six dimensions:

| Benign workload | Why it trips the same features |
| --- | --- |
| `tar`, `restic`, `borg` backups | High event rate, many directories, many extensions |
| `ffmpeg` transcoding | Write-heavy at entropy ~7.9 (compressed output) |
| `git gc` / repacking | Bursty writes, high-entropy packfiles |
| `apt upgrade` | Sweeps the filesystem, touches every extension |

This is where the project's false positives will actually come from. The
README's answer (*"the forest learns what's normal in all six dimensions"*)
only holds **if those workloads were present in the training data**. If they
were not, they will be flagged, and no property of the algorithm prevents it.

### Weakness 3: axis-aligned splits miss correlations

Standard Isolation Forest carves the feature space into axis-aligned
rectangles. A known artifact is spurious low-score regions in the gaps between
clusters: places that "should" look anomalous but receive a normal score
because no single-axis cut separates them.

**Extended Isolation Forest** replaces single-feature cuts with oblique
hyperplane cuts and removes this artifact. It exports just as easily: a
coefficient vector plus an intercept per node, instead of a feature index plus
a threshold. The scoring math in `anomaly_model.cpp` keeps the same shape, with
a dot product where the single comparison used to be. It is the cleanest
drop-in upgrade available.

---

## Part 3 - A Correction to the Existing Documentation

[`ENTROPY_AND_ML_EXPLAINED.md`](ENTROPY_AND_ML_EXPLAINED.md#L275) currently
explains `StandardScaler` this way:

> `StandardScaler` rescales each feature to have mean 0 and standard deviation
> 1 ... so no single feature dominates just because its raw numbers are bigger.

That reasoning is **correct for distance-based methods and incorrect for
Isolation Forest**. scikit-learn chooses each split value uniformly at random
between the node's per-feature minimum and maximum, so the algorithm is
invariant to any monotone per-feature rescaling. Standardizing is
mathematically a **no-op** for the forest: the tree structure, path lengths,
and scores are unchanged.

Keeping the scaler is harmless, and it does make the JSON contract uniform
across models. But the stated justification is wrong, and a sharp student will
catch it.

---

## Part 4 - Recommendations

> **Follow-up:** recommendations 1, 2, and 4 below have since been built and
> measured. See [`POTENTIAL_IMPROVEMENTS.md`](POTENTIAL_IMPROVEMENTS.md) for the
> results, including the two that did less than this section predicted and the
> one unlisted item that turned out to matter most.

Keep Isolation Forest as the primary model. In rough order of value:

1. **Add temporal aggregation.** An EWMA or CUSUM layer over the per-process
   score stream closes the low-and-slow gap, which is currently a complete
   blind spot.

2. **Add baselines to the research writeup.** A per-feature robust z-score rule
   and a Mahalanobis-distance detector are each roughly thirty lines, and both
   export to C++ more easily than a forest does (a mean vector and a $6 \times 6$
   inverse covariance matrix is 36 multiply-accumulates, versus 200 tree
   descents). If Isolation Forest does not beat them on the test scenarios,
   that is the most interesting finding in the project. If it does, the
   complexity has been earned. At present the choice is *asserted* rather than
   *demonstrated*, and demonstrating it is cheap.

3. **Train on adversarial-benign workloads.** Backup, compile, media
   transcode, and package upgrade. That is the real false-positive
   battleground, and it is a data problem, not a model problem.

4. **Consider Extended Isolation Forest** for better geometry at effectively no
   runtime cost.

---

## Summary

Isolation Forest is here because the research claim demands one-class learning,
the always-on C++ daemon demands a model that serializes to plain arithmetic,
and the six-feature vector sits exactly in the algorithm's comfort zone. Those
are good reasons.

Its two real weaknesses are that it cannot see across time and that it cannot
be told which direction along a feature axis is dangerous. Neither is fixed by
swapping in a different anomaly detector; the first is fixed by a temporal
layer above the model, and the second by better benign training data.
