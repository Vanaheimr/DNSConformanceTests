# -*- coding: utf-8 -*-
"""Pin a block's classification to the revision its verdicts were measured on.

Same job as `classify.py`, which did it for the records block against
`973fed31`: decide for each survivor whether it is a real gap or a `#region`
name, reading the source as it stood when the sweep ran rather than as it stands
now. A round of fixes moves line numbers, and a triage that reads the current
tree silently starts classifying different lines than were measured.

    python build/mutation/classify_folder.py core
    python build/mutation/classify_folder.py core 973fed31

With no revision it uses Hermod's HEAD, and refuses if the working tree is
dirty — because "HEAD" would then not describe what was actually measured.
"""

import io
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from sweep_folder import BLOCKS, ROOT

HERMOD = os.path.join(ROOT, "libs", "Hermod")

REGION    = re.compile(r"^#(region|endregion)")
ATTRIBUTE = re.compile(r"^\[")
DEFAULT   = re.compile(r"^(Boolean|String|Int32|UInt16|UInt32|UInt64|Byte|TimeSpan|DNSQueryClasses)\s+\w+\s*=")
REJECTION = re.compile(r"\breturn\s+(false|null)\s*;")
BOUNDARY  = ("less-to-less-or-equal", "greater-to-ge", "le-to-less", "ge-to-greater")


def git(*args):
    return subprocess.run(["git", "-C", HERMOD] + list(args),
                          capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def head_revision():
    dirty = git("status", "--porcelain").stdout.strip()
    if dirty:
        sys.exit("Hermod's working tree is not clean, so HEAD does not describe what was\n"
                 "measured. Commit it, or name the revision explicitly.")
    return git("rev-parse", "--short", "HEAD").stdout.strip()


def main():

    if len(sys.argv) < 2 or sys.argv[1] not in BLOCKS:
        sys.exit("usage: classify_folder.py <%s> [revision]" % "|".join(sorted(BLOCKS)))

    name     = sys.argv[1]
    revision = sys.argv[2] if len(sys.argv) > 2 else head_revision()

    src = os.path.join(HERE, "results", "%s-pass2.tsv" % name)
    out = os.path.join(HERE, "results", "%s-classified.tsv" % name)

    if not os.path.exists(src):
        sys.exit("no second pass to read: " + src)

    cache = {}

    def snapshot(rel):
        if rel not in cache:
            got = git("show", "%s:Hermod/%s" % (revision, rel))
            if got.returncode != 0:
                sys.exit("cannot read %s at %s: %s" % (rel, revision, got.stderr[:200]))
            cache[rel] = got.stdout.replace("\r\n", "\n").split("\n")
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

    seen, rows = set(), []

    for line in io.open(src, encoding="utf-8"):
        p = line.rstrip("\n").split("\t")
        if len(p) >= 4 and p[3] == "SURVIVED-EVERYWHERE":
            key = (p[0], p[1], p[2])
            if key in seen:
                continue
            seen.add(key)
            kind, text = classify(p[0], int(p[1]), p[2])
            rows.append((p[0], p[1], p[2], kind, text))

    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write("# Every mutant of the '%s' block that survived every project,\n" % name)
        f.write("# classified against Hermod %s — the revision the sweep measured.\n" % revision)
        f.write("# Line numbers move; this file does not.\n")
        f.write("# file\tline\toperator\tkind\tsource\n")
        for r in rows:
            f.write("\t".join(r) + "\n")

    kinds = {}
    for _, _, _, kind, _ in rows:
        kinds[kind] = kinds.get(kind, 0) + 1

    print("block     %s" % name)
    print("revision  %s" % revision)
    print("wrote %s" % out)
    for kind, n in sorted(kinds.items(), key=lambda kv: -kv[1]):
        print("  %-18s %4d" % (kind, n))
    print("  %-18s %4d" % ("real gaps", sum(n for k, n in kinds.items() if not k.startswith("noise"))))


if __name__ == "__main__":
    main()
