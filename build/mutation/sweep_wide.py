# -*- coding: utf-8 -*-
"""Second pass: re-judge the survivors with a wider bench.

The first pass mutated DNS/ResourceRecords/** and ran only the 226 tests of the
ResourceRecords project. That answers "do the record tests catch this", which is
not the question worth asking. Record parsing is also exercised by the wire
format, EDNS, DNSSEC and server projects, so a mutant that survived the first
pass may well be caught elsewhere.

Only survivors are re-run, which is what makes this affordable: everything the
first pass killed is already answered.

Three outcomes:
  KILLED-ELSEWHERE   another project caught it — the first pass was too narrow
  SURVIVED-EVERYWHERE  no test in any of these projects notices the change
  BUILD-FAILED       not a viable mutant (should not appear; the first pass filtered these)
"""

import io
import os
import re
import subprocess
import sys
import time

HERE    = os.path.dirname(os.path.abspath(__file__))
import os as _os

# The repository this script lives in, found from the script rather than
# written down: build/mutation/<this file>  ->  two levels up.
ROOT = _os.path.abspath(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", ".."))
SRCROOT = os.path.join(ROOT, r"libs\Hermod\Hermod")

# Every conformance project that needs neither Docker nor WSL. The interop lane
# is left out on purpose: its judges live outside this machine's control, and a
# mutant "surviving" because BIND was unavailable would be a lie.
PROJECTS = [
    ("wireformat", r"conformance\DNSConformance.WireFormat.Tests\DNSConformance.WireFormat.Tests.csproj",       81),
    ("edns",       r"conformance\DNSConformance.Edns.Tests\DNSConformance.Edns.Tests.csproj",                   32),
    ("dnssec",     r"conformance\DNSConformance.Dnssec.Tests\DNSConformance.Dnssec.Tests.csproj",              251),
    ("server",     r"conformance\DNSConformance.Server.Tests\DNSConformance.Server.Tests.csproj",              140),
    ("client",     r"conformance\DNSConformance.Client.Tests\DNSConformance.Client.Tests.csproj",               89),
    ("transports", r"conformance\DNSConformance.SecureTransports.Tests\DNSConformance.SecureTransports.Tests.csproj", 129),
]

FIRST_PASS = os.path.join(HERE, "results", "records-pass1.tsv")
RESULTS    = os.path.join(HERE, "results", "records-pass2.tsv")

FAILED = re.compile(r"(?:Fehler|Failed):\s*(\d+)")
TOTAL  = re.compile(r"(?:gesamt|total):\s*(\d+)", re.IGNORECASE)


def run(cmd, timeout=1800):
    return subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def build(proj):
    return run(["dotnet", "build", os.path.join(ROOT, proj), "-v", "q", "--nologo"])


def test(proj):
    out = run(["dotnet", "test", os.path.join(ROOT, proj), "--no-build", "-v", "q", "--nologo"]).stdout or ""
    f, t = FAILED.search(out), TOTAL.search(out)
    return (int(f.group(1)), int(t.group(1))) if f and t else None


def read(path):
    with open(path, "rb") as f:
        raw = f.read()
    bom = raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8-sig" if bom else "utf-8")
    nl = "\r\n" if "\r\n" in text else "\n"
    return text, nl, bom


def write(path, text, nl, bom):
    data = text.replace("\r\n", "\n").replace("\n", nl).encode("utf-8")
    if bom:
        data = b"\xef\xbb\xbf" + data
    with open(path, "wb") as f:
        f.write(data)


def already_done():
    done = set()
    if os.path.exists(RESULTS):
        for line in io.open(RESULTS, encoding="utf-8"):
            p = line.rstrip("\n").split("\t")
            if len(p) >= 3:
                done.add((p[0], p[1], p[2]))
    return done


def record(rel, line_no, op, verdict, detail):
    with io.open(RESULTS, "a", encoding="utf-8") as f:
        f.write("%s\t%s\t%s\t%s\t%s\n" % (rel, line_no, op, verdict, detail))


def main():

    sys.path.insert(0, HERE)
    import genmut

    survivors = set()
    for line in io.open(FIRST_PASS, encoding="utf-8"):
        p = line.rstrip("\n").split("\t")
        if len(p) >= 4 and p[3] == "SURVIVED":
            survivors.add((p[0], int(p[1]), p[2]))

    print("%d survivors from the first pass" % len(survivors))

    catalogue = genmut.mutants_for  # not used directly; we regenerate below
    all_mutants = []
    for dirpath, _, filenames in os.walk(os.path.join(SRCROOT, r"DNS\ResourceRecords")):
        for filename in sorted(filenames):
            if filename.endswith(".cs"):
                full = os.path.join(dirpath, filename)
                rel = os.path.relpath(full, SRCROOT).replace("\\", "/")
                all_mutants.extend(genmut.mutants_for(full, rel))

    todo = [m for m in all_mutants if (m[0], m[1], m[2]) in survivors]
    print("%d of them located in the regenerated catalogue\n" % len(todo))

    # Baseline: every project green before anything is touched.
    for name, proj, expected in PROJECTS:
        b = build(proj)
        if b.returncode != 0:
            sys.exit("baseline build failed for %s" % name)
        counted = test(proj)
        if counted is None:
            sys.exit("baseline %s: could not parse the summary" % name)
        if counted[0] != 0:
            sys.exit("baseline %s is not clean: %d failed" % (name, counted[0]))
        print("baseline %-11s %d tests, 0 failures" % (name, counted[1]))

    print()

    done    = already_done()
    started = time.time()
    counts  = {}

    for n, (rel, line_no, op, original, mutated) in enumerate(todo, start=1):

        if (rel, str(line_no), op) in done:
            continue

        path = os.path.join(SRCROOT, rel.replace("/", "\\"))
        text, nl, bom = read(path)
        lines = text.replace("\r\n", "\n").split("\n")

        if line_no > len(lines) or lines[line_no - 1] != original:
            record(rel, line_no, op, "SETUP-ERROR", "line moved or did not match")
            continue

        lines[line_no - 1] = mutated + "  /*MUTANT*/"

        try:

            write(path, "\n".join(lines), nl, bom)

            back, _, _ = read(path)
            if "/*MUTANT*/" not in back:
                record(rel, line_no, op, "SETUP-ERROR", "marker not on disk")
                continue

            killer = None
            broken = False

            for name, proj, expected in PROJECTS:

                b = build(proj)
                if b.returncode != 0:
                    broken = True
                    break

                counted = test(proj)
                if counted is None:
                    continue

                if counted[0] > 0:
                    killer = "%s (%d of %d failed)" % (name, counted[0], counted[1])
                    break

            if broken:
                verdict, detail = "BUILD-FAILED", "not a viable mutant"
            elif killer:
                verdict, detail = "KILLED-ELSEWHERE", killer
            else:
                verdict, detail = "SURVIVED-EVERYWHERE", original.strip()[:120]

            record(rel, line_no, op, verdict, detail)
            counts[verdict] = counts.get(verdict, 0) + 1

            if verdict == "SURVIVED-EVERYWHERE":
                print("  SURVIVES  %s:%d  %-24s %s" % (rel, line_no, op, original.strip()[:80]))

        except subprocess.TimeoutExpired:
            record(rel, line_no, op, "TIMEOUT", "a test run did not finish")
            counts["TIMEOUT"] = counts.get("TIMEOUT", 0) + 1

        finally:
            write(path, text, nl, bom)

        if n % 20 == 0:
            print("[%d/%d]  %.0f min  %s" % (n, len(todo), (time.time() - started) / 60, counts))

    print()
    print("=" * 80)
    for verdict, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print("%-22s %4d" % (verdict, n))
    print("=" * 80)

    for _, proj, _ in PROJECTS:
        build(proj)
    print("sources restored and rebuilt")


if __name__ == "__main__":
    main()
