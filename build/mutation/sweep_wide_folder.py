# -*- coding: utf-8 -*-
"""Second pass for a block: re-judge its survivors with the wider bench.

The first pass asks "do the tests of one project catch this", which is not the
question worth asking: the DNS code is shared, and a mutant in `DomainName` that
the record tests cannot see may well be caught by the server or DNSSEC ones. A
mutant is only a gap once no project sees it.

Only survivors are re-run, which is what makes it affordable, and the block's own
judge is left out because pass 1 already asked it.

    python build/mutation/sweep_wide_folder.py core

Three outcomes:
  KILLED-ELSEWHERE     another project caught it — the first pass was too narrow
  SURVIVED-EVERYWHERE  no test in any of these projects notices the change
  BUILD-FAILED         not a viable mutant (pass 1 should have filtered these)
"""

import io
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from sweep_folder import (BLOCKS, SRCROOT, ROOT, project, assembly, read, write,
                          run, TIMEOUT, TIMED_OUT, BUILD_FLAGS)

# Every conformance project that needs neither Docker nor WSL. The interop lane
# is left out on purpose: its judges live outside this machine's control, and a
# mutant "surviving" because BIND was unavailable would be a lie.
BENCH = ["WireFormat", "Edns", "Dnssec", "Server", "Client", "SecureTransports",
         "Multicast", "ResourceRecords"]

FAILED = re.compile(r"(?:Fehler|Failed):\s*(\d+)")

# The one thing that tells "the compiler rejected this mutant" apart from "this
# machine could not build at all". Without it a locked output file, a wedged
# test host or a full disk is recorded as a property of the code - which is how
# 179 lines that had already built in pass 1 came to be filed as not viable.
COMPILER_ERROR = re.compile(r": error CS[0-9]+", re.IGNORECASE)


def not_the_mutants_fault(Result):
    """True when a build failed for a reason the mutation cannot explain."""
    return COMPILER_ERROR.search((Result.stdout or "") + (Result.stderr or "")) is None

TOTAL  = re.compile(r"(?:gesamt|total):\s*(\d+)", re.IGNORECASE)


def build(proj):
    return run(["dotnet", "build", proj, "-v", "q", "--nologo"])


def build_all():
    """One build for the whole bench rather than seven.

    A mutant that survives everywhere pays for every project in the bench, and
    seven `dotnet build` invocations cost fourteen seconds more than one over
    the solution — measured, not assumed. Over a few hundred survivors that is
    an hour of the run spent starting the same tool again."""
    return run(["dotnet", "build", os.path.join(ROOT, "DNSConformanceTests.slnx")]
               + BUILD_FLAGS)

# A test that is red for a documented reason cannot serve as a detector: it fails
# for the mutant and for the clean tree alike. TestCategories.KnownIssue marks
# exactly those - an RFC requirement Hermod is known to violate, with an entry in
# FINDINGS.md and the test left red as the tracking signal PLAN.md section 9 asks
# for. The sweep leaves them out so that a documented deviation and a broken
# bench do not look the same from here.
KNOWN_ISSUE = ["--filter", "TestCategory!=KnownIssue"]


def run_tests(proj, timeout=1800):

    result = run(["dotnet", "test", proj, "--no-build", "-v", "q", "--nologo"] + KNOWN_ISSUE,
                 timeout=timeout)

    if result.returncode == TIMED_OUT:
        return TIMEOUT

    out  = result.stdout or ""
    f, t = FAILED.search(out), TOTAL.search(out)
    return (int(f.group(1)), int(t.group(1))) if f and t else None


def main():

    if len(sys.argv) < 2 or sys.argv[1] not in BLOCKS:
        sys.exit("usage: sweep_wide_folder.py <%s> [limit]" % "|".join(sorted(BLOCKS)))

    name    = sys.argv[1]
    limit   = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    block   = BLOCKS[name]
    bench   = [b for b in BENCH if b != block["judge"]]

    pass1   = os.path.join(HERE, "results", "%s-pass1.tsv" % name)
    results = os.path.join(HERE, "results", "%s-pass2.tsv" % name)

    if not os.path.exists(pass1):
        sys.exit("no first pass to read: " + pass1)

    # Counted over every row, not just the surviving ones: at LOC.cs:487 the
    # survivors are candidates 0, 1 and 3, and counting survivors alone would
    # send the third re-plant at candidate 2 - the one a test kills.
    survivors, tally = [], {}
    for line in io.open(pass1, encoding="utf-8"):
        p = line.rstrip("\n").split("\t")
        if len(p) < 4:
            continue
        key = (p[0], int(p[1]), p[2])
        k   = int(p[5]) if len(p) >= 6 else tally.get(key, 0)
        tally[key] = tally.get(key, 0) + 1
        if p[3] in ("SURVIVED", "TIMED-OUT"):
            survivors.append((p[0], int(p[1]), p[2], k))

    # Round-robin over the files rather than straight down the list. Pass 1
    # orders by file, so a straight read spends its first hour on one of them
    # and says nothing about the rest — and the first verdicts are the ones that
    # tell you whether the harness is working at all.
    by_file = {}
    for s_ in survivors:
        by_file.setdefault(s_[0], []).append(s_)

    interleaved = []
    while any(by_file.values()):
        for rel in sorted(by_file):
            if by_file[rel]:
                interleaved.append(by_file[rel].pop(0))
    survivors = interleaved

    def load_done(path):
        found, tally = set(), {}
        if not os.path.exists(path):
            return found
        for line in io.open(path, encoding="utf-8"):
            p = line.rstrip("\n").split("\t")
            if len(p) >= 3:
                key = (p[0], p[1], p[2])
                k   = p[5] if len(p) >= 6 else str(tally.get(key, 0))
                tally[key] = tally.get(key, 0) + 1
                found.add(key + (k,))
        return found

    done = load_done(results)

    print("block      %s" % name)
    print("bench      %s" % ", ".join(bench))
    print("survivors  %d, %d already recorded\n" % (len(survivors), len(done)), flush=True)

    # A green baseline on every bench project, and the test count each one has,
    # so a mutant that changes the count is visible rather than averaged away.
    if build_all().returncode != 0:
        sys.exit("baseline build of the solution failed")

    expected = {}
    caps     = {}

    for b in bench:

        proj     = project(b)

        measured = time.time()
        counted  = run_tests(proj)
        seconds  = time.time() - measured

        if counted is TIMEOUT or counted is None or counted[0] != 0:
            sys.exit("baseline is not clean for %s: %s" % (b, counted))

        expected[b] = counted[1]

        # Each project gets its own bound, ten times its clean run. Without one
        # a single mutant that spins costs thirty minutes per project rather
        # than per pass.
        caps[b] = max(120, int(seconds * 10))

        print("  baseline %-18s %4d tests in %3.0f s (a mutant gets %d s)"
              % (b, counted[1], seconds, caps[b]), flush=True)

    print()

    # A line can carry the same operator more than once, so (file, line,
    # operator) names several mutants and not one. The occurrence index is what
    # tells them apart: pass 2 needs it to re-plant the one that survived, and a
    # resumed run needs it to tell the third occurrence from the first.
    nth = [0]

    def record(rel, line_no, op, verdict, detail):
        with io.open(results, "a", encoding="utf-8") as f:
            f.write("%s\t%s\t%s\t%s\t%s\t%d\n"
                    % (rel, line_no, op, verdict, detail, nth[0]))

    import genmut

    started = time.time()
    counts  = {}
    ran     = 0

    for rel, line_no, op, occurrence in survivors:

        nth[0] = occurrence

        if (rel, str(line_no), op, str(occurrence)) in done:
            continue

        if limit and ran >= limit:
            break

        ran += 1

        path = os.path.join(SRCROOT, rel.replace("/", "\\"))
        text, nl, bom = read(path)
        lines = text.replace("\r\n", "\n").split("\n")

        candidates = [m for m in genmut.mutants_for(path, rel)
                      if m[1] == line_no and m[2] == op]

        # Not "there must be exactly one". There may be several, and the index
        # says which. A count that no longer reaches it means the line changed
        # under the measurement, and that is worth stopping on rather than
        # planting whichever mutant happens to be first.
        if occurrence >= len(candidates):
            record(rel, line_no, op, "SETUP-ERROR",
                   "occurrence %d of %d - the line no longer generates it"
                   % (occurrence + 1, len(candidates)))
            continue

        mutated = candidates[occurrence][4]

        try:

            lines[line_no - 1] = mutated + "  /*MUTANT*/"
            write(path, "\n".join(lines), nl, bom)

            back, _, _ = read(path)
            if "/*MUTANT*/" not in back:
                record(rel, line_no, op, "SETUP-ERROR", "marker not on disk")
                continue

            verdict, detail = "SURVIVED-EVERYWHERE", ""

            # Break on the first kill: one project noticing is the whole answer,
            # and the remaining builds would cost a minute each to confirm it.
            before = {b: os.path.getmtime(assembly(b)) for b in bench}

            built = build_all()

            if built.returncode != 0:

                if not_the_mutants_fault(built):
                    sys.exit(("the build failed with no compiler error in it, so this "
                              "is the machine and not the mutant. Stopping rather than "
                              "recording %s:%d as not viable:" + chr(10) + chr(10) + "%s")
                             % (rel, line_no,
                                ((built.stdout or "") + (built.stderr or ""))[-3000:]))

                record(rel, line_no, op, "BUILD-FAILED", "not a viable mutant")
                counts["BUILD-FAILED"] = counts.get("BUILD-FAILED", 0) + 1
                continue

            stale = [b for b in bench if os.path.getmtime(assembly(b)) <= before[b]]
            if stale:
                record(rel, line_no, op, "STALE-BINARY",
                       "not rebuilt: " + ", ".join(stale))
                counts["STALE-BINARY"] = counts.get("STALE-BINARY", 0) + 1
                continue

            for b in bench:

                proj = project(b)

                counted = run_tests(proj, timeout=caps[b])

                if counted is TIMEOUT:
                    verdict = "TIMED-OUT"
                    detail  = "%s was still running after %d s" % (b, caps[b])
                    break

                if counted is None:
                    verdict, detail = "PARSE-ERROR", "no summary line from %s" % b
                    break

                failed, total = counted
                if failed > 0:
                    verdict = "KILLED-ELSEWHERE"
                    detail  = "%s: %d of %d failed" % (b, failed, total)
                    break

                if total != expected[b]:
                    verdict = "KILLED-ELSEWHERE"
                    detail  = "%s: the test count moved from %d to %d" % (b, expected[b], total)
                    break

            record(rel, line_no, op, verdict, detail)
            counts[verdict] = counts.get(verdict, 0) + 1

        finally:
            write(path, text, nl, bom)

        if ran % 5 == 0:
            rate = (time.time() - started) / ran
            left = (len(survivors) - len(done) - ran) * rate / 60.0
            print("  %4d/%d  %s  (%.0fs each, ~%.0f min left)"
                  % (ran, len(survivors) - len(done),
                     "  ".join("%s %d" % (k, v) for k, v in sorted(counts.items())),
                     rate, left), flush=True)

    for b in bench:
        build(project(b))

    print("\nran %d in %.0f min" % (ran, (time.time() - started) / 60.0))
    for k, v in sorted(counts.items()):
        print("  %-22s %4d" % (k, v))
    print("sources restored and rebuilt")
    print("results: %s" % results)


if __name__ == "__main__":
    main()
