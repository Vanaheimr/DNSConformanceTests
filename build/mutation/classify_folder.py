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
# An attribute is compile-time and mutating one changes nothing that runs.
# Matching only at the start of a line misses the common case: a nullability
# annotation inside a parameter list, as in
#     public static Boolean IsNotNullOrEmpty([NotNullWhen(true)] this Foo? X)
# where the line begins with "public". Five of the core block's "real gaps"
# were that, and the first of them was found by writing a test for it and
# watching the mutation survive anyway.
ATTRIBUTE = re.compile(r"^\[|\[(NotNullWhen|MaybeNullWhen|DoesNotReturnIf)\(")
DEFAULT   = re.compile(r"^(Boolean|String|Int32|UInt16|UInt32|UInt64|Byte|TimeSpan|DNSQueryClasses)\s+\w+\s*=")
# ...but a default is only noise when it is a convention. Some of them are policy:
# flipping one changes what every caller that did not choose gets, and nothing
# about the line says which kind it is - the name does. These are listed rather
# than matched, because no pattern can tell "the usual value" from "the safe
# value", and a rule that cannot be written down should not be pretended into a
# regex.
POLICY_DEFAULTS = {
    # RFC 5155 section 6: opt-out leaves insecure delegations out of the NSEC3
    # chain. As a default it decides what every zone signed without an opinion
    # proves.
    ("DNS/DNSSEC/DNSSECZoneSigner.cs", "OptOut"),
    # A key generated without an opinion is a zone signing key, not a key
    # signing key - the two sit at different places in the chain of trust.
    ("DNS/DNSSEC/DNSSECSigningKey.cs", "KeySigningKey"),
    # RFC 6762 §5.4, §18.5 and §10.2: the QU bit, the TC bit and the cache-flush
    # bit. The browser's questions, every query and every response, and the
    # records a probe proposes all go out on these defaults, and the RFC says
    # which way each of them must read. Two of them the querier tests kill.
    ("DNS/Multicast/MulticastDNSMessage.cs", "UnicastResponseRequested"),
    ("DNS/Multicast/MulticastDNSMessage.cs", "Truncated"),
    ("DNS/Multicast/MulticastDNSMessage.cs", "CacheFlush"),
}


# `await x.ConfigureAwait(false)` read as `true` is a real change and an
# invisible one: a test host has no synchronization context, so both
# continuations go to the thread pool and nothing here can tell them apart. The
# difference lives in a UI or classic ASP.NET host, which this suite does not
# build and has no reason to. Not noise - this is code - and not a gap either,
# because no test written for a DNS conformance suite will ever close one. See
# MUTATION.md for what does judge them.
# Without the leading dot: where the awaited expression spans lines, the dot
# sits at the end of the previous one and the call stands alone on this.
CONFIGURE_AWAIT = re.compile(r"ConfigureAwait\(false\)")

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
        if op == "false-to-true" and CONFIGURE_AWAIT.search(text):
            return "host-only", text
        if REGION.match(text):
            return "noise-region", text
        if ATTRIBUTE.search(text):
            return "noise-attribute", text
        if DEFAULT.match(text):
            name = text.split("=")[0].split()[-1]
            if (rel, name) not in POLICY_DEFAULTS:
                return "noise-default", text
        if REJECTION.search(text):
            return "rejection", text
        if op in BOUNDARY:
            return "boundary", text
        return "branch", text

    # A verdict pass 2 could not reach is an open question, not a non-entry.
    # Reading only SURVIVED-EVERYWHERE made a line the machine failed to measure
    # indistinguishable from a line the suite covers, and that silence is how
    # five lines in blocks reported closed were never looked at.
    UNMEASURED = {
        "TIMED-OUT":    "unmeasured-timeout",
        "SETUP-ERROR":  "unmeasured-refused",
        "PARSE-ERROR":  "unmeasured-noanswer",
        "STALE-BINARY": "unmeasured-stale",
    }

    entries = []
    for line in io.open(src, encoding="utf-8"):
        p = line.rstrip("\n").split("\t")
        if len(p) >= 4:
            entries.append(p)

    # A line can carry the same operator more than once, and the sweep has told
    # the occurrences apart in a sixth column since sweep_folder.py learned to.
    # This key had not: it kept the first occurrence and dropped the others, so
    # a survivor that shared a line and an operator with another one was not in
    # this file at all — ten of them in the multicast block, and on two of those
    # lines the querier tests kill one occurrence and not the other. A pass
    # written before the column existed has its occurrences in order and
    # unnumbered, and keeps the old key rather than a guessed one.
    def occurrence(p):
        return p[5] if len(p) >= 6 and p[5] != "" else None

    def key_of(p):
        return (p[0], p[1], p[2], occurrence(p))

    def row(p, kind, text):
        r = (p[0], p[1], p[2], kind, text)
        return r if occurrence(p) is None else r + (occurrence(p),)

    seen, rows = set(), []

    # The measured ones first, so a key that got an answer keeps it even when
    # another row for the same key was refused.
    for p in entries:
        if p[3] == "SURVIVED-EVERYWHERE":
            key = key_of(p)
            if key in seen:
                continue
            seen.add(key)
            kind, text = classify(p[0], int(p[1]), p[2])
            rows.append(row(p, kind, text))

    for p in entries:
        if p[3] in UNMEASURED:
            key = key_of(p)
            if key in seen:
                continue
            seen.add(key)
            _, text = classify(p[0], int(p[1]), p[2])
            rows.append(row(p, UNMEASURED[p[3]], text))

    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write("# Every mutant of the '%s' block that survived every project,\n" % name)
        f.write("# classified against Hermod %s — the revision the sweep measured.\n" % revision)
        f.write("# Line numbers move; this file does not.\n")
        if any(len(r) > 5 for r in rows):
            f.write("# file\tline\toperator\tkind\tsource\toccurrence\n")
        else:
            f.write("# file\tline\toperator\tkind\tsource\n")
        for r in rows:
            f.write("\t".join(r) + "\n")

    kinds = {}
    for r in rows:
        kinds[r[3]] = kinds.get(r[3], 0) + 1

    print("block     %s" % name)
    print("revision  %s" % revision)
    print("wrote %s" % out)
    for kind, n in sorted(kinds.items(), key=lambda kv: -kv[1]):
        print("  %-20s %4d" % (kind, n))

    unmeasured = sum(n for k, n in kinds.items() if k.startswith("unmeasured"))
    print("  %-20s %4d" % ("real gaps",
                           sum(n for k, n in kinds.items()
                               if not k.startswith("noise")
                               and not k.startswith("unmeasured")
                               and k != "host-only")))
    if unmeasured:
        print("")
        print("  %d of these carry no verdict at all - the run refused them or" % unmeasured)
        print("  never finished on them. They are neither killed nor survived,")
        print("  and no test can be argued from this file alone. Re-measure.")


if __name__ == "__main__":
    main()
