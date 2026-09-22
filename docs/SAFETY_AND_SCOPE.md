# Safety and Scope

This project is defensive. It watches file activity and raises alerts. It
never encrypts, corrupts, or mass-modifies a user's files, and it contains no
ransomware.

The monitoring tools only observe activity. The lab script is the one
exception: it creates and deletes test files so you can try the detector.
Read the limits below before using it.

## What the tools do

- Watch file access metadata: who touched which file, when, and how.
- Read the first 4096 bytes of a file that a process is reading or writing,
  only to measure byte entropy. Those bytes are not stored.
- Build a baseline of what normal activity looks like.
- Score live activity against that baseline and alert on anything unusual.
- Optionally pause a suspicious process with `SIGSTOP`, and only when the
  user explicitly turns that on.

## The one exception: the lab script

`scripts/simulate_ransomware_lab.sh` produces file activity for the detector
to observe without running real malware. It creates disposable test files,
writes random-looking copies, and deletes the originals. This resembles the
file-access pattern the project is trying to detect, but uses test data rather
than personal files.

The script applies the following checks. Cleanup needs particular care:

1. It only ever works inside one folder, `~/ransomware_lab` by default. It
   resolves that path (following any symbolic links) and refuses to run if
   the result is your home directory or the root of the disk.
2. It leaves a hidden marker file in any folder it creates. **Every mode,
   including `--clean`, refuses to touch a folder that lacks the marker.** A
   folder you made yourself is never written to or deleted.
3. Before writing anything, it checks every decoy path it is about to use.
   If any of them already exists, or any directory on the way is a symbolic
   link, it stops with nothing changed. So a normal run never overwrites or
   deletes a file it did not create in that same run.
4. `--clean` deletes the entire marked lab folder, including anything you
   may have added to it. That is the one operation that can remove a file
   the script did not create, and it only happens on a folder the script
   made and only when you ask for it. Do not keep anything in the lab folder.

Use a virtual machine or a disposable account for this experiment. Do not run
it on the machine that holds your homework or other important files.

## What is out of scope

- Writing real ransomware, encryption loops, or anything that hides from
  detection, gains extra privileges, spreads, or persists after reboot.
- Running experiments on real personal files without a backup.
- Killing processes. The daemon can pause a process, never kill it.
- Turning on automatic pausing by default, or on a machine whose owner did not
  opt in.

## What the collector sees, and why that matters

The collector's records include file paths, process names, and usernames.
Even without storing a file's contents, a path can reveal personal information.
On a shared machine, the logs can include other people's file names. Keep the
CSV logs private, delete them when you are done, and do not commit a real
recording to a public repository.

A process name or number also has limits as a way to identify a program:

- The process name comes from `/proc/<pid>/comm`. Any program can set that
  name to anything it likes, so a process called `restic` is not proof that
  it is the real backup tool. An allowlist is a list of programs you choose
  to trust; do not build one using process names alone.
- Process ids get reused. A pid that was paused an hour ago may belong to a
  different program now. Check before you resume or pause anything by pid.

## Pausing a process

With `--stop`, the daemon sends `SIGSTOP` to a process it flags. This pauses
the process without closing the files it had open. To let it continue, use:

```sh
kill -CONT <pid>
```

The daemon sends the optional notification or pause signal once per process,
so it does not repeatedly take the same action against that program.

## Where the project stands

This is a research prototype for learning and experimentation, not a finished
security product. Its detection numbers come from simulated activity.
[`EXPERIMENTS_AND_FINDINGS.md`](EXPERIMENTS_AND_FINDINGS.md) explains those
results, including the ideas that did not work as expected. The detector needs
testing on real recordings of ordinary use before anyone relies on it to
protect files. Until then, start in alert-only mode and keep backups.

## Recommended lab setup

- Use a virtual machine or a disposable Linux account.
- Use the synthetic datasets in `testdata/` and copies of files, never
  originals.
- Keep backups or snapshots.
- Start with alert-only mode, and add `--stop` only once you have watched the
  alerts for a while and know what they look like.
