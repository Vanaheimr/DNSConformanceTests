# -*- coding: utf-8 -*-
"""Write down which of a block's gaps are closed, so its standing count is
derived instead of typed.

Same job as `make_closed.py` does for the records block, and the same three
states:

  killed      a mutation taken from this sweep's output now fails a test
  equivalent  the mutation is real and the program is the same either way
  superseded  the line the verdict belongs to no longer exists, because a fix
              replaced it

    python build/mutation/make_closed_folder.py core

Line numbers are the sweep's own — for the core block, Hermod `e592b5e7`.
"""

import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from sweep_folder import BLOCKS


# ---------------------------------------------------------------------- core

CORE_KILLED = {

    # RFC 9525 §6.3 and §7.1, reached from RFC 8310 §8.1: which certificate
    # vouches for which host name. Twenty of the twenty-one, by mutations taken
    # from this sweep's own output.
    "pattern": {
        "DNS/DNSNamePattern.cs": {40, 47, 218, 231, 234, 259, 268, 279,
                                  329, 341, 342, 349, 355, 359, 378,
                                  422, 430, 438, 446, 503},
    },

    # RFC 1035 §4.1.1 header flags as the client reads them, and what a query
    # that never got an answer is allowed to claim. Nineteen of the twenty.
    "dnsinfo": {
        "DNS/DNSInfo.cs": {321, 323, 326, 433,
                           524, 525, 526, 527, 532,
                           543, 544, 545, 546, 552,
                           568, 569, 570, 571, 577},
    },

}

CORE_EQUIVALENT = {

    "DNS/DNSInfo.cs": {
        319: "the QR bit is read into a local that nothing reads back — it appears twice in the "
             "file, one of them in the licence header — so both readings assign a value nobody "
             "observes. Not checking it is conformant besides: RFC 5452 §9.1 enumerates what a "
             "resolver MUST match a response against, and the six are the addresses, the port, "
             "the ID, the name, the class and the type. QR is not among them",
    },

    "DNS/DNSNamePattern.cs": {
        347: "the left-most label of a parsed host name cannot be empty — DomainName refuses an "
             "empty label before Matches is ever reached — so this guard has nothing to guard "
             "against. The comment above it says as much: \"the check costs nothing and this is "
             "the wrong place to find out\"",
    },

}

CORE_SUPERSEDED = {}


LEDGERS = {
    "core": (CORE_KILLED, CORE_EQUIVALENT, CORE_SUPERSEDED),
}


def main():

    if len(sys.argv) < 2 or sys.argv[1] not in BLOCKS:
        sys.exit("usage: make_closed_folder.py <%s>" % "|".join(sorted(BLOCKS)))

    name = sys.argv[1]
    if name not in LEDGERS:
        sys.exit("no ledger for block '%s' yet — add one above" % name)

    killed, equivalent, superseded = LEDGERS[name]

    classified = os.path.join(HERE, "results", "%s-classified.tsv" % name)
    out        = os.path.join(HERE, "results", "%s-closed.tsv" % name)

    if not os.path.exists(classified):
        sys.exit("no classification to read: " + classified)

    rows = []

    for line in io.open(classified, encoding="utf-8"):

        if line.startswith("#"):
            continue

        p = line.rstrip("\n").split("\t")
        if len(p) < 5 or p[3].startswith("noise"):
            continue

        rel, ln, op = p[0], int(p[1]), p[2]

        for round_name, files in killed.items():
            if ln in files.get(rel, ()):
                rows.append((rel, str(ln), op, "killed", round_name, ""))
                break

        else:
            why = equivalent.get(rel, {}).get(ln)
            if why:
                rows.append((rel, str(ln), op, "equivalent", "", why))
            else:
                why = superseded.get(rel, {}).get(ln)
                if why:
                    rows.append((rel, str(ln), op, "superseded", "", why))

    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write("# Gaps of the '%s' block that are no longer gaps, keyed to the same\n" % name)
        f.write("# revision as the verdicts.\n")
        f.write("# 'killed' means a mutation taken from this sweep's output now fails a test.\n")
        f.write("# 'equivalent' means the mutation is real and the program is the same either way.\n")
        f.write("# 'superseded' means the line the verdict belongs to was replaced by a fix.\n")
        f.write("# file\tline\toperator\tstate\tround\twhy\n")
        for r in rows:
            f.write("\t".join(r) + "\n")

    print("wrote %s" % out)
    for state in ("killed", "equivalent", "superseded"):
        n = sum(1 for r in rows if r[3] == state)
        if n:
            print("  %-12s %3d" % (state, n))


if __name__ == "__main__":
    main()
