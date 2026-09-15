# -*- coding: utf-8 -*-
"""Pin the classification to the same revision as the verdicts.

The triage in report.py reads the current source to decide whether a survivor is
a real gap or a #region name. That was fine until a round of fixes moved a
file's line numbers, at which point the classification silently started reading
different lines than the sweep measured — and the standing count drifted without
anything looking wrong.

This writes it down once, against the revision the sweep ran on, so the numbers
afterwards come from a file instead of from a source tree that keeps moving.
"""

import io
import os
import re
import subprocess

import os as _os

# The repository this script lives in, found from the script rather than
# written down: build/mutation/<this file>  ->  two levels up.
ROOT = _os.path.abspath(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", ".."))
OUT  = os.path.join(ROOT, r"build\mutation\results\records-classified.tsv")
IN   = os.path.join(ROOT, r"build\mutation\results\records-pass2.tsv")
PASS1 = os.path.join(ROOT, r"build\mutation\results\records-pass1.tsv")

REVISION = "973fed31"

REGION    = re.compile(r"^#(region|endregion)")
ATTRIBUTE = re.compile(r"^\[")
DEFAULT   = re.compile(r"^(Boolean|String|Int32|UInt16|UInt32|UInt64|Byte|TimeSpan|DNSQueryClasses)\s+\w+\s*=")
REJECTION = re.compile(r"\breturn\s+(false|null)\s*;")
BOUNDARY  = ("less-to-less-or-equal", "greater-to-ge", "le-to-less", "ge-to-greater")

cache = {}


def snapshot(rel):
    """The file as it stood when the sweep measured it."""
    if rel not in cache:
        out = subprocess.run(["git", "-C", os.path.join(ROOT, "libs", "Hermod"),
                              "show", "%s:Hermod/%s" % (REVISION, rel)],
                             capture_output=True, text=True, encoding="utf-8", errors="replace")
        if out.returncode != 0:
            raise SystemExit("cannot read %s at %s: %s" % (rel, REVISION, out.stderr[:200]))
        cache[rel] = out.stdout.replace("\r\n", "\n").split("\n")
    return cache[rel]


def classify(rel, line_no, op):
    text = snapshot(rel)[line_no - 1].strip()
    if REGION.match(text):
        return "noise-region", text
    if ATTRIBUTE.match(text):
        return "noise-attribute", text
    if DEFAULT.match(text):
        return "noise-default", text
    if REJECTION.search(text):
        return "rejection", text
    if op in BOUNDARY:
        return "boundary", text
    return "branch", text


seen = set()
rows = []

for line in io.open(IN, encoding="utf-8"):
    p = line.rstrip("\n").split("\t")
    if len(p) >= 5 and p[3] == "SURVIVED-EVERYWHERE":
        key = (p[0], p[1], p[2])
        if key in seen:
            continue
        seen.add(key)
        kind, text = classify(p[0], int(p[1]), p[2])
        rows.append((p[0], p[1], p[2], kind, text))

with io.open(OUT, "w", encoding="utf-8", newline="\n") as f:
    f.write("# Every mutant that survived every project, classified against Hermod %s —\n" % REVISION)
    f.write("# the revision the sweep measured. Line numbers move; this file does not.\n")
    f.write("# file\tline\toperator\tkind\tsource\n")
    for r in rows:
        f.write("\t".join(r) + "\n")

kinds = {}
for _, _, _, kind, _ in rows:
    kinds[kind] = kinds.get(kind, 0) + 1

print("wrote %s" % OUT)
for kind, n in sorted(kinds.items(), key=lambda kv: -kv[1]):
    print("  %-18s %4d" % (kind, n))
print("  %-18s %4d" % ("real gaps", sum(n for k, n in kinds.items() if not k.startswith("noise"))))
