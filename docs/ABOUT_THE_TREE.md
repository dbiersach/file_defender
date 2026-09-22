# How Isolation Trees Are Built and Scored

*Read [`ENTROPY_AND_ML_EXPLAINED.md`](ENTROPY_AND_ML_EXPLAINED.md) first.
This guide builds on its explanation of the six features and anomaly scores.*

The model included with File Defender contains 200 small decision trees.
During training, random choices determine which data each tree sees and how
it divides those data. Once training is finished, the choices are saved. The
detector uses those saved trees to score new activity.

To understand how that works, we will follow the construction of one tree
and answer three questions:

1. Where exactly does the randomness come in, and where does it stop?
2. What happens at the bottom of a tree, where the branches end?
3. Why does each tree only look at 256 rows of training data?

The explanations refer to the code and the model in
[`models/model.json`](../models/model.json). You can inspect the model and
repeat the subsampling experiments with these scripts:

```sh
uv run python python/inspect_model.py
uv run python python/subsample_sweep.py
```

---

## Part 0 - Training a Forest and Using It

There are two forest implementations in this project: the standard Isolation
Forest used by the daemon and an experimental Extended Isolation Forest.
For the standard forest, training and scoring also happen in different
programs:

| What | File | Who does the random part |
| --- | --- | --- |
| The real model, used by the daemon | [`python/train_isolation_forest.py`](../python/train_isolation_forest.py) | scikit-learn |
| The real scorer | [`src/daemon/anomaly_model.cpp`](../src/daemon/anomaly_model.cpp) | nobody: scoring has no randomness |
| An experimental variant | [`python/extended_isolation_forest.py`](../python/extended_isolation_forest.py) | this project, written from scratch |

The Python trainer calls scikit-learn's `IsolationForest` rather than
implementing tree construction itself. The random choices in Parts 1 to 4
therefore happen inside scikit-learn. The project's C++ code handles
*scoring*: it loads the finished trees from JSON and follows their saved
comparisons. That step does not make any new random choices.

The experimental Extended Isolation Forest includes its own tree-building
code. Part 5 explains how to read that code and where its behavior differs
from the standard algorithm.

A few tree terms will help. The *root* is the starting point. Each branch
point splits the rows into two groups. A *leaf* is an endpoint where no
further split is made. The depth of a leaf is the number of splits along the
path from the root; the depth of a tree is its longest such path.

### What the shipped model contains

Run `inspect_model.py` and you get this:

```text
  trees                : 200
  samples per tree     : 256
  tree depth           : 8 to 8
  training points/leaf : 1 to 91

  [0] events_per_second        used        (root split in 40 of 200 trees)
  [1] writes_per_second        used        (root split in 56 of 200 trees)
  [2] rename_delete_rate       NEVER USED  (root split in 0 of 200 trees)
  [3] average_byte_entropy     used        (root split in 51 of 200 trees)
  [4] unique_directory_count   NEVER USED  (root split in 0 of 200 trees)
  [5] unique_extension_count   used        (root split in 53 of 200 trees)
```

The output shows three properties that the next sections will explain:

- Every tree is exactly 8 levels deep. This comes from
  $\lceil \log_2 256 \rceil = 8$, the height limit from Part 3.
- Some leaves hold 91 training points. Trees stop before every point is alone,
  which is why the leaf correction in Part 3 exists.
- **Two of the six features are never used.** In the benign training file,
  no process renames or deletes anything and every process stays in one
  directory, so those two features are the same number in every row. A tree
  cannot split on a feature that never changes. The shipped forest is a
  four-feature detector even though its input has six columns. Retraining
  on a richer benign set makes those features usable. However, that set
  includes `git` and `restic`, which raise the alert threshold enough that
  the README demos no longer flag their attackers. This result is discussed
  in [`EXPERIMENTS_AND_FINDINGS.md`](EXPERIMENTS_AND_FINDINGS.md).

---

## Part 1 - Three Random Choices, Some Stopping Rules, One Correction

The phrase "random splits" describes only part of tree construction. There
are three random choices to keep track of. Separate rules decide when a
branch stops growing, and a correction is used later when calculating its
score:

| | What is decided | When | Random? |
| --- | --- | --- | --- |
| 1 | Which 256 training rows this tree gets to see | once per tree | yes |
| 2 | Which feature to cut on | at every branch point | yes |
| 3 | Where along that feature to cut | at every branch point | yes |
| | Whether to stop growing this branch | at every branch point | no |
| | How much extra depth to credit a crowded leaf | when scoring | no |

Choices 2 and 3 apply at the root just as they do farther down the tree. The
difference is that the root sees all 256 rows selected for that tree.

Once a tree is built, scoring follows its saved comparisons. The same window
sent through the same tree reaches the same leaf each time. Randomness is
part of training, not scoring.

---

## Part 2 - Building One Standard Tree

Imagine a tiny training set of eight benign windows and look at just one
feature, `writes_per_second`:

```text
0.0   0.1   0.1   0.2   0.2   0.3   0.3   3.0
```

Seven values are close together, while 3.0 is much larger. A random cut can
separate that one row from the other seven.

### Choice 2: pick a feature

The tree picks a feature at random, rather than searching for the feature
that best separates labeled classes. Each feature is equally likely to be
chosen, with one exception: a feature that is constant at this branch point
cannot separate any rows. scikit-learn skips it and tries another.

That exception explains why the shipped model never splits on
`rename_delete_rate`. Its value was the same in every training row, so it was
always skipped.

### Choice 3: pick where to cut

Suppose the selected feature is `writes_per_second`. The cut goes at a random
spot between
the **smallest and largest value at this branch point**, which here is
somewhere in $[0.0, 3.0]$. Every spot in that range is equally likely.

Suppose it lands at 1.7. Then seven rows go left (all below 1.7) and one row,
the 3.0, goes right, alone. That row has been *isolated* after one cut. The
seven rows on the left still need further cuts. This illustrates the idea
behind the score: a point far from the others can be separated quickly,
while points close together take more cuts to separate.

At the next branch point, the seven remaining values run from 0.0 to 0.3,
so the next random cut is drawn from $[0.0, 0.3]$, **not**
from $[0.0, 3.0]$. The range shrinks as you go down. If the code kept drawing
from the full range, most cuts would land in the empty space above 0.3, send
every row the same way, and waste a level of the tree without separating
anything. Using the range of the rows at the current branch point keeps the
cut relevant to the rows it is meant to separate.

### Why the scaler does not change the tree

[`ENTROPY_AND_ML_EXPLAINED.md`](ENTROPY_AND_ML_EXPLAINED.md) explains that the
trainer standardizes each feature by subtracting the mean and dividing by
the standard deviation. Here is why that does not matter to a standard
isolation tree.

Standardizing a feature slides it and stretches it: every value $x$ becomes
$(x - m) / s$. The smallest value, the largest value, and the random cut
between them all slide and stretch together. The same rows end up on the same
side. In exact arithmetic the tree, the depths, and the scores are identical.

There are two limits to this explanation:

- It only holds for slide-and-stretch changes. A *curved* change, such as
  taking a logarithm, keeps the same set of possible cuts but changes how
  likely each one is, so it can change the scores.
- scikit-learn treats a feature whose values at a branch point are closer
  together than about $10^{-7}$ as constant and skips it. Stretching such a
  feature can make it usable. The varying features here do not have such
  narrow ranges.

---

## Part 3 - Where a Branch Stops, and the Leaf Correction

### The stopping rules

A branch stops growing when any of these is true:

- **It has reached the height limit.** We use $\psi$ (the Greek letter psi)
  for the number of training rows selected for one tree. For $\psi$ rows the
  limit is $\lceil \log_2 \psi \rceil$, which is 8 for $\psi = 256$. That is the
  depth at which a perfectly balanced tree would have separated all 256 rows.
- **Only one row is left.** Nothing to split.
- **Every remaining row is identical.** Nothing to split on.

The height limit keeps tree construction and scoring inexpensive. The idea
is to separate unusual rows near the top, then avoid spending further work
distinguishing rows that remain together deep in the tree. That work can
instead go into another tree.

This is a design choice, not a way to prove that a row is benign. A row that
reaches level 8 has stayed with other rows in this particular tree. It has
not passed a test that rules out an attack.

### The correction: what to do with a crowded leaf

The height limit creates a problem. A leaf can still hold many rows (91 in the
shipped model). Those rows were never actually isolated, so their measured
depth of 8 is too small. Left uncorrected, they would all look a little more
suspicious than they are.

The score therefore includes an estimate of the additional cuts. If the leaf
holds $n$ training rows, the added amount is $c(n)$:

$$c(n) = \begin{cases} 0 & n \le 1 \\ 1 & n = 2 \\ 2\left(\ln(n-1) + \gamma\right) - \dfrac{2(n-1)}{n} & n > 2 \end{cases}$$

where $\gamma \approx 0.5772$ is the Euler-Mascheroni constant. The formula
comes from a classic result about random binary search trees: it is the
average number of steps an unsuccessful search takes in a random tree of $n$
items. The Isolation Forest paper borrowed it because a random isolation tree
looks a lot like a random search tree.

The distinction between an estimate and an exact answer matters here. The
remaining part of the tree was never built, so $c(n)$ does not tell us
exactly how many cuts that particular group of rows would need. The formula
also uses $\ln(n-1) + \gamma$ to approximate a harmonic sum.

All three copies of the function in this project match when read side by
side. `verify_parity.py` compares the Python scoring with scikit-learn on
every tested row. Running the C++ copy requires `verify_cpp_parity.py` on
Linux. Agreement between implementations checks that they use the same
formula; it does not make the estimate exact for every leaf.

The two special cases matter. Plugging $n = 2$ into the log formula gives
about 0.15; the code returns 1, because two points need exactly one more cut.
Plugging in $n = 1$ would take the log of zero, so the code returns 0. All
three copies of this function handle both cases:

- [`python/verify_parity.py`](../python/verify_parity.py), `average_path_length()`
- [`src/daemon/anomaly_model.cpp`](../src/daemon/anomaly_model.cpp), `average_path_length()`
- [`python/extended_isolation_forest.py`](../python/extended_isolation_forest.py), `average_path_length()`

### From depth to score

A window's path length in one tree is its depth plus $c(n)$ for the leaf it
lands in. Average that over all 200 trees to get $E[h(x)]$, then

$$s(x) = 2^{\,-\dfrac{E[h(x)]}{c(\psi)}}$$

The score is always between 0 and 1 simply because a path length is never
negative: 2 to a zero-or-negative power is at most 1. Dividing by
$c(\psi)$, the expected depth for a tree grown on $\psi$ rows, is not what
bounds it; it sets the *scale*. A path as long as the expected one gives
$2^{-1} = 0.5$; a much shorter path gives a score near 1. So 0.5 means "this
window took about as many cuts as a typical training window," which is a
reference point, not a certificate that the window is benign. Being between
0 and 1 is convenient for reading the number. It is not what lets the trainer
set the alert threshold as a percentile; any score you can sort would allow
that.

---

## Part 4 - Why Each Tree Sees Only 256 Rows

We can now return to the first random choice: selecting the rows for a tree.
Each tree uses a *subsample* of $\psi = 256$ benign training rows, chosen
without replacement. That means a row cannot be chosen twice for the same
tree. The reasons for using a subsample depend on whether the training set
contains only benign data or also contains anomalies. We will consider those
settings separately.

### In this project: benign-only training

File Defender trains on benign windows only. Ransomware windows are never in
the training set, so they are never in any tree. In that setting, subsampling
does three things:

- **Each tree sees a different sample of benign activity.** The 200 random
  subsets lead to somewhat different trees. Averaging their results gives a
  steadier score than relying on one tree.
- **It bounds the height and the cost.** A tree on 256 rows is at most 8 deep
  and has at most 511 nodes. The daemon walks 200 of them per event.
- **It follows the paper's default.** Liu, Ting and Zhou found $\psi = 256$
  works well across many datasets and recommended it. This project adopts
  that choice.

Here is the measured effect on this project's own features, from
`subsample_sweep.py` (benign-only training on 400 synthetic windows, scored on
a fresh set with both kinds):

| $\psi$ | threshold | ransomware caught | benign flagged |
| --- | --- | --- | --- |
| 16 | 0.5830 | 100.0% | 0.0% |
| 32 | 0.5871 | 100.0% | 0.5% |
| 64 | 0.6017 | 100.0% | 0.2% |
| 128 | 0.6012 | 100.0% | 0.0% |
| 256 | 0.6023 | 100.0% | 0.0% |
| 400 (all of it) | 0.6089 | 100.0% | 0.2% |

Every tested subsample size catches every attack row in this synthetic data.
The attacks have extreme values in all six features, so the test is too easy
to identify a preferred $\psi$. The project keeps 256 because it is inexpensive
and is the published default, not because this table shows it is better.

### In the textbooks: contaminated training (an aside)

The original paper also studied training data that already contained
anomalies. Two effects help explain the role of subsampling in that setting:

- *Masking*: if the training set holds a dense clump of anomalies, the clump
  is hard to cut apart, so its members get long paths and look normal. A small
  random subsample thins the clump out.
- *Swamping*: with a big sample, normal points that sit near the anomalies get
  caught by the same cuts and look suspicious. Thinning helps them too.

The second experiment in `subsample_sweep.py` uses that setting. It puts two
thousand ordinary points and two hundred tightly clustered anomalies into
the training set, then builds 200 trees:

| $\psi$ | benign mean | anomaly mean | gap |
| --- | --- | --- | --- |
| 8 | 0.4784 | 0.6580 | 0.1797 |
| 16 | 0.4722 | 0.7067 | 0.2345 |
| **32** | 0.4614 | 0.7155 | **0.2541** |
| 64 | 0.4577 | 0.6771 | 0.2194 |
| 128 | 0.4509 | 0.6521 | 0.2012 |
| 256 | 0.4455 | 0.6210 | 0.1755 |
| 1024 | 0.4387 | 0.5733 | 0.1346 |
| 2200 (all of it) | 0.4358 | 0.5518 | 0.1160 |

The gap between the average scores is widest at $\psi = 32$ and shrinks as
the subsample grows. This shows the masking effect. The gap is not a detection
rate, though: halving the difference between two averages does not mean the
detector catches half as many attacks.

This table does not describe File Defender's benign-only training. Its purpose
is to show why the explanation from the paper cannot simply be carried over
to this project.

There is a related issue in benign-only training. Real benign data contains
dense clusters, such as a backup tool writing hundreds of similar windows.
Those are not anomalies; the detector *should* learn them as normal. Thinning
them with a small subsample makes them easier to isolate, which pushes their
score *up*, which means more false alarms on backups. That is a coverage
problem rather than masking. It is a reason to consider how well a subsample
represents benign activity, not just how much computation it saves.

---

## Part 5 - The Extended Isolation Forest, and How It Differs

[`python/extended_isolation_forest.py`](../python/extended_isolation_forest.py)
implements a variant from Hariri, Kind and Brunner (2018). A standard tree
cuts perpendicular to one feature axis; the extended tree cuts along a slanted
line. In six dimensions the corresponding dividing surface is called a
*hyperplane*. The code in this file lets you follow how those cuts are made
and compare them with the standard tree.

### Choosing a direction

Instead of picking one feature, the extended tree picks a random *direction*.
The direction is represented by a vector, a list of six numbers. The code
draws those numbers from a bell curve and scales the vector to length 1
(`_random_normal()`). That is the correct way to pick a direction uniformly at
random in six dimensions. Drawing six numbers from a flat range and scaling
would *not* be uniform; it would favor the corners of the cube.

An `extension_level` setting zeroes out some of the six numbers. At level 0
only one survives, and the cut is axis-aligned again. The setting controls
how many features a cut combines. Level 0 is not a bit-for-bit copy of
scikit-learn; the retry rule below explains one difference.

### Choosing where to cut: a different rule

The standard tree picks a cut uniformly between the local minimum and maximum
of one feature. The extended tree does something else: it picks a random
*point* uniformly inside the box that contains the rows at this branch point,
and puts the cut through that point (`_grow()`, the `rng.uniform(low, high)`
line). Projecting a uniformly random box point onto a slanted line does not
give a uniform position along that line. Cuts near the middle of the box are
more likely than cuts near its edges, in the same way that the sum of two dice
is more likely to be 7 than 2. That matches the paper; it is simply a different
rule from choosing a uniform position along the direction of the cut.

### The scaler matters here

A slanted cut mixes features. If one feature is measured in units a thousand
times bigger than another, the mix is dominated by the big one, and which
directions are likely to be drawn changes. Standardization therefore affects
this variant, unlike the standard tree in Part 2. It changes the probabilities
of the possible hyperplanes, not which hyperplanes are possible.

### The retry rule, and what it costs

A random slanted cut can occasionally leave every row on one side. The code
tries up to ten times. If none of the attempts separates the rows, it makes
that branch point a leaf. There are two consequences to consider:

- At `extension_level=0` with one varying feature and five constant ones, a
  single attempt lands on a constant feature 5 times out of 6, so all ten
  attempts fail with probability $(5/6)^{10} \approx 16\%$. In a test with 256
  distinct rows, **35 of 200 trees stopped at the root** even though a valid
  cut existed. scikit-learn would have skipped the constant features and never
  failed. This is why level 0 is "the axis-aligned variant of this code," not
  a substitute for scikit-learn.
- When the guard fires, the leaf gets the $c(n)$ credit from Part 3 instead of
  the cuts that would have happened. Whether that makes a given window look
  more or less normal than a fully grown branch would depends on where the
  window sits. No direction is claimed, because none has been measured.

---

## Part 6 - What the Parity Tests Do and Do Not Show

The project uses *parity tests* to compare implementations: given the same
input, do they produce the same output? The two scripts check different parts
of the calculation.

- [`python/verify_parity.py`](../python/verify_parity.py) runs on any machine.
  It scores rows with scikit-learn and with a Python copy of the JSON tree
  walk, and reports the largest difference: about $10^{-16}$ on ordinary rows.
  It also reports a *boundary* number, about $2 \times 10^{-3}$, for rows
  placed exactly on a split threshold; scikit-learn rounds its inputs to
  single precision before walking, the JSON walk does not, and a row sitting
  exactly on the line can go different ways. This script never runs C++.
- [`python/verify_cpp_parity.py`](../python/verify_cpp_parity.py) runs on
  Linux. It launches the real daemon with `--dump-features`, which prints the
  six features and the score for every event, and compares that against
  Python. This is the test that would catch a disagreement between
  `feature_window.cpp` and `features.py`.

The first test checks the JSON representation and the scoring recipe. The
second checks whether the daemon agrees with the Python reference on the
fixture files, which are the example event files supplied to the test. Only
the second runs C++. Agreement on two files is evidence, not proof for every
possible input. The checker's `--self-test` mode also supplies deliberately
broken tables and verifies that they are rejected.

---

## Part 7 - Summary

| Level | What is random | How |
| --- | --- | --- |
| Per tree | which 256 rows it sees | drawn without replacement |
| Every branch point | the cut feature (standard) or direction (extended) | uniform over features; uniform over directions |
| Every branch point | the cut position | uniform on the local range (standard); a random box point, projected (extended) |
| Branch ends | nothing | height limit $\lceil \log_2 \psi \rceil$, one row left, or all rows identical |
| Scoring | nothing | depth plus the $c(n)$ estimate, averaged over trees |

The main points are:

1. **The root is not special.** Every branch point is built the same way.
2. **Once built, a tree is fixed.** Training is randomized; scoring is not.
3. **The leaf correction is a borrowed estimate**, applied deterministically,
   that stands in for cuts the height limit skipped.
4. **Subsampling does different things in different settings.** In this
   benign-only project it is about diversity, cost, and following the paper's
   default; on the project's own synthetic data no $\psi$ is measurably better
   than another. The textbook masking story belongs to contaminated training
   and does not apply here.

The shipped forest has the expected structure: 200 trees, 256 training rows
per tree, depth exactly 8, and leaves of different sizes. scikit-learn builds
the trees, and the JSON scoring recipe agrees with it to $10^{-16}$ on
ordinary rows. The C++ comparison is a separate check, run with
`verify_cpp_parity.py` on Linux after changes. These checks support the
implementation without proving it correct for every input. The extended
forest also uses the expected direction sampling and local cut ranges, with
the differences described in Part 5.

---

## References

- F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation Forest," *IEEE
  International Conference on Data Mining (ICDM)*, 2008. The original
  algorithm, the height limit, $c(n)$, and the $\psi = 256$ recommendation.
- F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation-Based Anomaly Detection,"
  *ACM Transactions on Knowledge Discovery from Data*, 6(1), 2012. The longer
  version, with the masking and swamping discussion.
- S. Hariri, M. Carrasco Kind, and R. J. Brunner, "Extended Isolation Forest,"
  *IEEE Transactions on Knowledge and Data Engineering*, 2019
  (arXiv:1811.02141). The slanted-cut variant in Part 5.
- scikit-learn user guide, section 2.7.3, "Isolation Forest," and the
  `sklearn.ensemble.IsolationForest` API reference. Source of the constant
  feature skip and the single-precision rounding noted above.
- `fanotify(7)`, Linux manual pages. The kernel interface the collector uses.
