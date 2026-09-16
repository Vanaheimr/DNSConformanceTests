# -*- coding: utf-8 -*-
"""The sweep, pointed at a folder other than the resource records.

`sweep.py` is kept as it ran: it produced `results/records-pass1.tsv` and
MUTATION.md describes it. This is the same harness with the folder, the judging
test project and the results file taken from a table instead of written into the
source, because the resource records were one of six places the DNS code lives
and the other five had never been measured.

The blocks are here rather than in a command line so that the map is readable in
one screen and each row can be run on its own:

    python build/mutation/sweep_folder.py core
    python build/mutation/sweep_folder.py core 50      # stop after 50 mutants

A block names one primary judge, which is the cheapest test project that
exercises it heavily. That is deliberately not the only judge: a survivor of
pass 1 is re-judged against the rest by `sweep_wide.py`, because a mutant that
one project cannot see is not yet a gap.

Results are appended as they happen, so a partial run is a readable one and a
rerun skips what is already recorded.
"""

import io
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import genmut

ROOT    = os.path.abspath(os.path.join(HERE, "..", ".."))
SRCROOT = os.path.join(ROOT, r"libs\Hermod\Hermod")

CONFORMANCE = os.path.join(ROOT, "conformance")


def project(name):
    return os.path.join(CONFORMANCE,
                        "DNSConformance.%s.Tests" % name,
                        "DNSConformance.%s.Tests.csproj" % name)


def assembly(name):
    return os.path.join(CONFORMANCE,
                        "DNSConformance.%s.Tests" % name,
                        r"bin\Debug\net10.0\org.GraphDefined.Vanaheimr.Hermod.dll")


# Every part of the DNS code, which folder it is, and the cheapest project that
# exercises it. "records" is the block the first sweep measured, kept here so the
# map is complete rather than because it needs running again.
BLOCKS = {

    # The code every query passes through, whatever its type: names, the message,
    # the zone file, the shared reading helpers.
    "core":      dict(root="DNS",
                      exclude=("ResourceRecords", "Client", "Server", "Multicast", "DNSSEC", "TSIG"),
                      judge="ResourceRecords"),

    "multicast": dict(root=r"DNS\Multicast", exclude=(), judge="Multicast"),
    "dnssec":    dict(root=r"DNS\DNSSEC",    exclude=(), judge="Dnssec"),
    "tsig":      dict(root=r"DNS\TSIG",      exclude=(), judge="SecureTransports"),
    "client":    dict(root=r"DNS\Client",    exclude=(), judge="Client"),
    "server":    dict(root=r"DNS\Server",    exclude=(), judge="Server"),
    "records":   dict(root=r"DNS\ResourceRecords", exclude=(), judge="ResourceRecords"),

}

FAILED = re.compile(r"(?:Fehler|Failed):\s*(\d+)")
TOTAL  = re.compile(r"(?:gesamt|total):\s*(\d+)", re.IGNORECASE)


def run(cmd, timeout=1800):
    return subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def build(proj):
    return run(["dotnet", "build", proj, "-v", "q", "--nologo"])


def run_tests(proj):
    out = run(["dotnet", "test", proj, "--no-build", "-v", "q", "--nologo"]).stdout or ""
    f, t = FAILED.search(out), TOTAL.search(out)
    return (int(f.group(1)), int(t.group(1))) if f and t else None


def read(path):
    with open(path, "rb") as f:
        raw = f.read()
    bom  = raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8-sig" if bom else "utf-8")
    nl   = "\r\n" if "\r\n" in text else "\n"
    return text, nl, bom


def write(path, text, nl, bom):
    data = text.replace("\r\n", "\n").replace("\n", nl).encode("utf-8")
    if bom:
        data = b"\xef\xbb\xbf" + data
    with open(path, "wb") as f:
        f.write(data)


def mutants_in(block):
    """Every mutant in the block's folder, busiest file first — so a run cut
    short has covered the most-mutated file rather than the alphabetical one."""

    root = os.path.join(SRCROOT, block["root"])
    out  = []

    for dirpath, _, names in os.walk(root):

        if any(skip in os.path.relpath(dirpath, root).split(os.sep) for skip in block["exclude"]):
            continue

        for filename in sorted(names):
            if filename.endswith(".cs"):
                full = os.path.join(dirpath, filename)
                rel  = os.path.relpath(full, SRCROOT).replace("\\", "/")
                out.extend(genmut.mutants_for(full, rel))

    order = {}
    for rel, _, _, _, _ in out:
        order[rel] = order.get(rel, 0) + 1
    out.sort(key=lambda m: (-order[m[0]], m[0], m[1]))

    return out


def main():

    if len(sys.argv) < 2 or sys.argv[1] not in BLOCKS:
        sys.exit("usage: sweep_folder.py <%s> [limit]" % "|".join(sorted(BLOCKS)))

    name    = sys.argv[1]
    limit   = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    block   = BLOCKS[name]
    proj    = project(block["judge"])
    dll     = assembly(block["judge"])
    results = os.path.join(HERE, "results", "%s-pass1.tsv" % name)

    if not os.path.exists(dll):
        sys.exit("guard is broken, no such assembly: " + dll)

    print("block   %s" % name)
    print("source  %s" % block["root"])
    print("judge   %s" % os.path.basename(proj))
    print("guard   %s" % dll)
    print()

    b = build(proj)
    if b.returncode != 0:
        sys.exit("baseline build failed:\n" + (b.stdout or "")[-2000:])

    baseline = run_tests(proj)
    if baseline is None:
        sys.exit("baseline: could not parse the test summary")
    if baseline[0] != 0:
        sys.exit("baseline is not clean: %d of %d failed" % baseline)

    expected = baseline[1]
    print("baseline: %d tests, 0 failures\n" % expected, flush=True)

    mutants = mutants_in(block)

    done = set()
    if os.path.exists(results):
        for line in io.open(results, encoding="utf-8"):
            p = line.rstrip("\n").split("\t")
            if len(p) >= 3:
                done.add((p[0], p[1], p[2]))

    print("%d mutants, %d already recorded\n" % (len(mutants), len(done)), flush=True)

    def record(rel, line_no, op, verdict, detail):
        with io.open(results, "a", encoding="utf-8") as f:
            f.write("%s\t%s\t%s\t%s\t%s\n" % (rel, line_no, op, verdict, detail))

    started = time.time()
    counts  = {}
    ran     = 0

    for n, (rel, line_no, op, original, mutated) in enumerate(mutants, start=1):

        if (rel, str(line_no), op) in done:
            continue

        if limit and ran >= limit:
            break

        # Counted here rather than after the verdict, so that a mutant the
        # harness refuses to run still uses up a place in a limited run — a
        # limit that silently skipped them would keep going.
        ran += 1

        path = os.path.join(SRCROOT, rel.replace("/", "\\"))
        text, nl, bom = read(path)
        lines = text.replace("\r\n", "\n").split("\n")

        if line_no > len(lines) or lines[line_no - 1] != original:
            record(rel, line_no, op, "SETUP-ERROR", "line moved or did not match")
            continue

        try:

            lines[line_no - 1] = mutated + "  /*MUTANT*/"
            write(path, "\n".join(lines), nl, bom)

            back, _, _ = read(path)
            if "/*MUTANT*/" not in back:
                record(rel, line_no, op, "SETUP-ERROR", "marker not on disk")
                continue

            before = os.path.getmtime(dll)

            if build(proj).returncode != 0:
                record(rel, line_no, op, "BUILD-FAILED", "not a viable mutant")
                counts["BUILD-FAILED"] = counts.get("BUILD-FAILED", 0) + 1
                continue

            if os.path.getmtime(dll) <= before:
                record(rel, line_no, op, "STALE-BINARY", "the loaded assembly was not rebuilt")
                counts["STALE-BINARY"] = counts.get("STALE-BINARY", 0) + 1
                continue

            counted = run_tests(proj)
            if counted is None:
                record(rel, line_no, op, "PARSE-ERROR", "no summary line")
                counts["PARSE-ERROR"] = counts.get("PARSE-ERROR", 0) + 1
                continue

            failed, total = counted
            verdict = "KILLED" if failed > 0 else "SURVIVED"
            detail  = "%d of %d failed" % (failed, total)
            if total != expected:
                detail += " (total moved from %d)" % expected

            record(rel, line_no, op, verdict, detail)
            counts[verdict] = counts.get(verdict, 0) + 1

        finally:
            write(path, text, nl, bom)

        if ran % 10 == 0:
            done_so_far = sum(counts.values())
            rate = (time.time() - started) / ran
            left = (len(mutants) - len(done) - ran) * rate / 60.0
            print("  %4d/%d  %s  (%.1fs each, ~%.0f min left)"
                  % (ran, len(mutants) - len(done),
                     "  ".join("%s %d" % (k, v) for k, v in sorted(counts.items())),
                     rate, left), flush=True)

    build(proj)

    print("\nran %d in %.0f min" % (ran, (time.time() - started) / 60.0))
    for k, v in sorted(counts.items()):
        print("  %-14s %4d" % (k, v))
    print("sources restored and rebuilt")
    print("results: %s" % results)


if __name__ == "__main__":
    main()
