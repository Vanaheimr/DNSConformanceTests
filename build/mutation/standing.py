# -*- coding: utf-8 -*-
"""Where the sweep stands, derived rather than typed.

This number has been recomputed by hand four times and was wrong twice, both
times because the triage read a source tree that had moved under it while the
verdicts stayed pinned to the revision they were measured on. So neither this
script nor the files it reads touch the source at all:

  results/records-classified.tsv   every survivor, classified against the
                                   revision the sweep measured
  results/records-closed.tsv       every gap since closed, declared equivalent, or
                                   left behind by a fix that removed its line

Run it instead of trusting a count written in prose.
"""

import io
import os
import sys

HERE  = os.path.dirname(os.path.abspath(__file__))

# Which block to report on. The records block was the first measured and is the
# default; the others were swept later and are named on the command line.
BLOCK      = sys.argv[1] if len(sys.argv) > 1 else "records"
CLASSIFIED = os.path.join(HERE, "results", "%s-classified.tsv" % BLOCK)
CLOSED     = os.path.join(HERE, "results", "%s-closed.tsv" % BLOCK)


def rows(path):
    # A block that has been measured but has nothing closed yet has no ledger,
    # and that is a state rather than an error.
    if not os.path.exists(path):
        return []
    out = []
    for line in io.open(path, encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        out.append(line.rstrip("\n").split("\t"))
    return out


def main():

    survivors = rows(CLASSIFIED)
    closed    = rows(CLOSED)

    real  = [r for r in survivors if not r[3].startswith("noise")]
    noise = [r for r in survivors if r[3].startswith("noise")]

    done  = {(r[0], r[1], r[2]): r[3] for r in closed}

    killed     = sum(1 for r in real if done.get((r[0], r[1], r[2])) == "killed")
    equivalent = sum(1 for r in real if done.get((r[0], r[1], r[2])) == "equivalent")
    superseded = sum(1 for r in real if done.get((r[0], r[1], r[2])) == "superseded")
    still_open = len(real) - killed - equivalent - superseded

    if not survivors:
        sys.exit("no classified survivors for block '%s': %s" % (BLOCK, CLASSIFIED))

    print("=" * 74)
    print("MUTATION SWEEP - standing state - block '%s'" % BLOCK)
    print("=" * 74)
    print()
    print("  survivors of the sweep     %4d   (%d of them not really code)" % (len(survivors), len(noise)))
    print("  real gaps                  %4d" % len(real))
    print()
    print("  closed by a test           %4d" % killed)
    print("  declared equivalent        %4d" % equivalent)
    print("  the line is gone           %4d" % superseded)
    print("  still open                 %4d" % still_open)
    print()

    if still_open == 0:
        print("  Nothing is left. Every mutant this sweep could not kill has since been")
        print("  killed, shown unreachable, or had its line replaced by a fix.")
        print()
        print("=" * 74)
        return

    by_kind = {}
    for r in real:
        if (r[0], r[1], r[2]) not in done:
            by_kind[r[3]] = by_kind.get(r[3], 0) + 1

    print("  what is left, by kind:")
    for kind, n in sorted(by_kind.items(), key=lambda kv: -kv[1]):
        print("    %-12s %4d" % (kind, n))
    print()

    by_file = {}
    for r in real:
        if (r[0], r[1], r[2]) not in done:
            name = r[0].split("/")[-1]
            by_file[name] = by_file.get(name, 0) + 1

    print("  and by file:")
    for name, n in sorted(by_file.items(), key=lambda kv: -kv[1])[:12]:
        print("    %-28s %4d" % (name, n))

    print()
    print("=" * 74)


if __name__ == "__main__":
    main()
