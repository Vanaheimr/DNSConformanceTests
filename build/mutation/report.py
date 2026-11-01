# -*- coding: utf-8 -*-
"""The gap list, deduplicated and sorted into kinds.

A raw list of 265 lines is a number, not a finding. What makes it usable is
that the survivors fall into three kinds that mean different things:

  rejection   `return false` / `return null` on a failure path, mutated to
              succeed, and nothing notices. That is not "a line is untested" —
              it is "this parser is never given input it must refuse", which is
              where findings 21 and 51 lived
  boundary    a comparison shifted by one. The test material exercises the
              middle of the range and never its edge
  branch      && / || flipped, or a bool flipped: a condition whose two sides
              are never both exercised

Noise is separated rather than deleted, with its reason, because a filter
nobody can audit is just a smaller unexplained number.

Every count is of mutants, one per row of the passes. It used to be of distinct
(file, line, operator) keys, and a line can carry the same operator up to four
times: 585 "viable mutants" were 605, and a key that pass 1 both killed and let
survive was counted on both sides. The triage is classify.py's, which reads the
source as it stood at 973fed31. This script used to read the working tree, and
by the time the occurrences were counted it put 255 real gaps where the pinned
triage had 240.
"""

import io
import os

HERE       = os.path.dirname(os.path.abspath(__file__))
PASS1      = os.path.join(HERE, "results", "records-pass1.tsv")
PASS2      = os.path.join(HERE, "results", "records-pass2.tsv")
CLASSIFIED = os.path.join(HERE, "results", "records-classified.tsv")

NOISE = {"noise-region": "#region", "noise-attribute": "attribute", "noise-default": "default parameter"}


def rows(path):
    out = []
    if os.path.exists(path):
        for line in io.open(path, encoding="utf-8"):
            if line.startswith("#") or not line.strip():
                continue
            out.append(line.rstrip("\n").split("\t"))
    return out


def count(path, wanted):
    return sum(1 for p in rows(path) if len(p) >= 4 and p[3] == wanted)


def main():

    k1 = count(PASS1, "KILLED")
    s1 = count(PASS1, "SURVIVED")
    u1 = count(PASS1, "BUILD-FAILED")
    k2 = count(PASS2, "KILLED-ELSEWHERE")

    survivors = [{"file": p[0], "line": int(p[1]), "op": p[2], "kind": p[3], "source": p[4]}
                 for p in rows(CLASSIFIED)]

    noise = {name: [r for r in survivors if r["kind"] == kind] for kind, name in NOISE.items()}
    real  = [r for r in survivors if r["kind"] not in NOISE]

    kinds = {}
    for r in real:
        kinds.setdefault(r["kind"], []).append(r)

    viable = k1 + s1
    caught = k1 + k2

    print("=" * 96)
    print("GLOBAL MUTATION RUN - Hermod/DNS/ResourceRecords, judged by seven conformance projects")
    print("=" * 96)
    print()
    print("  viable mutants                 %4d      (%d more would not compile)" % (viable, u1))
    print("  caught by the record tests     %4d" % k1)
    print("  caught only by another project %4d      pass 1 alone was too narrow by this much" % k2)
    print("  caught by nothing              %4d" % len(survivors))
    if k2 + len(survivors) != s1:
        print("  !! pass 1 let %d through and pass 2 accounts for %d - the files disagree"
              % (s1, k2 + len(survivors)))
    print()
    print("  of those, not really code:")
    for name, found in noise.items():
        print("    %-20s %4d" % (name, len(found)))
    print("    %-20s %4d" % ("real code", len(real)))
    print()
    print("  score as measured   %5.1f%%   (%d of %d)" % (100.0 * caught / viable, caught, viable))
    print("  score once noise is out     %5.1f%%   (%d of %d)" % (100.0 * caught / (caught + len(real)), caught, caught + len(real)))
    print()

    titles = {
        "rejection": "REJECTION PATHS - a parser told to succeed where it should refuse, and nothing notices",
        "boundary":  "BOUNDARIES - a comparison shifted by one; the edge of the range is never exercised",
        "branch":    "BRANCHES - a condition whose two sides are never both taken",
    }

    for kind in ("rejection", "boundary", "branch") + tuple(sorted(set(kinds) - set(titles))):
        found = kinds.get(kind, [])
        if not found:
            continue
        print("=" * 96)
        print("%s  (%d)" % (titles.get(kind, kind.upper()), len(found)))
        print("=" * 96)
        by_file = {}
        for r in found:
            by_file.setdefault(r["file"], []).append(r)
        for rel, rs in sorted(by_file.items(), key=lambda kv: -len(kv[1])):
            print()
            print("  %s  (%d)" % (rel.replace("DNS/ResourceRecords/", ""), len(rs)))
            shown = set()
            for r in sorted(rs, key=lambda x: x["line"]):
                if r["line"] in shown:
                    continue
                shown.add(r["line"])
                ops = sorted({x["op"] for x in rs if x["line"] == r["line"]})
                print("    :%-5d %-46s %s" % (r["line"], r["source"][:46], ",".join(ops)[:40]))
        print()


if __name__ == "__main__":
    main()
