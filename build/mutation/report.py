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
"""

import io
import os
import re

HERE    = os.path.dirname(os.path.abspath(__file__))
PASS1   = os.path.join(HERE, "results", "records-pass1.tsv")
PASS2   = os.path.join(HERE, "results", "records-pass2.tsv")
import os as _os2
SRCROOT = _os2.path.join(_os2.path.abspath(_os2.path.join(_os2.path.dirname(_os2.path.abspath(__file__)), "..", "..")), "libs", "Hermod", "Hermod")

REGION    = re.compile(r"^#(region|endregion)")
ATTRIBUTE = re.compile(r"^\[")
DEFAULT   = re.compile(r"^(Boolean|String|Int32|UInt16|UInt32|UInt64|Byte|TimeSpan|DNSQueryClasses)\s+\w+\s*=")

REJECTION = re.compile(r"\breturn\s+(false|null)\s*;")
BOUNDARY  = ("less-to-less-or-equal", "greater-to-ge", "le-to-less", "ge-to-greater")
BRANCH    = ("logical-and-to-or", "logical-or-to-and", "true-to-false", "false-to-true")


def load(path, wanted):
    rows, seen = [], set()
    if os.path.exists(path):
        for line in io.open(path, encoding="utf-8"):
            p = line.rstrip("\n").split("\t")
            if len(p) >= 5 and p[3] == wanted:
                key = (p[0], p[1], p[2])
                if key in seen:
                    continue
                seen.add(key)
                rows.append({"file": p[0], "line": int(p[1]), "op": p[2]})
    return rows


def count(path, wanted):
    seen = set()
    if os.path.exists(path):
        for line in io.open(path, encoding="utf-8"):
            p = line.rstrip("\n").split("\t")
            if len(p) >= 5 and p[3] == wanted:
                seen.add((p[0], p[1], p[2]))
    return len(seen)


def source_line(rel, line_no):
    path = os.path.join(SRCROOT, rel.replace("/", "\\"))
    try:
        lines = io.open(path, encoding="utf-8-sig").read().replace("\r\n", "\n").split("\n")
        return lines[line_no - 1].strip()
    except Exception:
        return "<unreadable>"


def main():

    k1 = count(PASS1, "KILLED")
    s1 = count(PASS1, "SURVIVED")
    u1 = count(PASS1, "BUILD-FAILED")
    k2 = count(PASS2, "KILLED-ELSEWHERE")

    survivors = load(PASS2, "SURVIVED-EVERYWHERE")

    noise, real = {"#region": [], "attribute": [], "default parameter": []}, []

    for r in survivors:
        text = source_line(r["file"], r["line"])
        r["source"] = text
        if REGION.match(text):
            noise["#region"].append(r)
        elif ATTRIBUTE.match(text):
            noise["attribute"].append(r)
        elif DEFAULT.match(text):
            noise["default parameter"].append(r)
        else:
            real.append(r)

    kinds = {"rejection": [], "boundary": [], "branch": []}
    for r in real:
        if REJECTION.search(r["source"]):
            kinds["rejection"].append(r)
        elif r["op"] in BOUNDARY:
            kinds["boundary"].append(r)
        elif r["op"] in BRANCH:
            kinds["branch"].append(r)
        else:
            kinds.setdefault("other", []).append(r)

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
    print()
    print("  of those, not really code:")
    for name, rows in noise.items():
        print("    %-20s %4d" % (name, len(rows)))
    print("    %-20s %4d" % ("real code", len(real)))
    print()
    print("  score as measured   %5.1f%%   (%d of %d)" % (100.0 * caught / viable, caught, viable))
    print("  score once noise is out     %5.1f%%   (%d of %d)" % (100.0 * caught / (caught + len(real)), caught, caught + len(real)))
    print()

    titles = {
        "rejection": "REJECTION PATHS - a parser told to succeed where it should refuse, and nothing notices",
        "boundary":  "BOUNDARIES - a comparison shifted by one; the edge of the range is never exercised",
        "branch":    "BRANCHES - a condition whose two sides are never both taken",
        "other":     "OTHER",
    }

    for kind in ("rejection", "boundary", "branch", "other"):
        rows = kinds.get(kind, [])
        if not rows:
            continue
        print("=" * 96)
        print("%s  (%d)" % (titles[kind], len(rows)))
        print("=" * 96)
        by_file = {}
        for r in rows:
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
