# -*- coding: utf-8 -*-
"""The control pass 2 did not carry.

Pass 1 verified, for every mutant, that the assembly the test host loads was
actually rebuilt. Pass 2 did not: it only checked that the build command
returned zero. That is the shortcut that once cost this project an entire run —
a guard watching a file that did not exist would have reported STALE-BINARY for
everything, and only a self-test caught it.

So before any of pass 2's 345 survivors is called a gap, one mutation that
*must* be caught goes through the same six projects: every received TTL becomes
zero. If a project reports no failures for that, its verdicts mean nothing.

Two things are measured per project:
  refreshed   did org.GraphDefined.Vanaheimr.Hermod.dll in that project's bin
              directory actually get a newer timestamp
  failures    how many tests noticed
"""

import io
import os
import re
import subprocess
import sys
import time

import os as _os

# The repository this script lives in, found from the script rather than
# written down: build/mutation/<this file>  ->  two levels up.
ROOT = _os.path.abspath(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", ".."))
SRCROOT = os.path.join(ROOT, r"libs\Hermod\Hermod")
TARGET  = os.path.join(SRCROOT, r"DNS\ResourceRecords\ADNSResourceRecord.cs")

PROJECTS = [
    ("records",    r"conformance\DNSConformance.ResourceRecords.Tests\DNSConformance.ResourceRecords.Tests.csproj"),
    ("wireformat", r"conformance\DNSConformance.WireFormat.Tests\DNSConformance.WireFormat.Tests.csproj"),
    ("edns",       r"conformance\DNSConformance.Edns.Tests\DNSConformance.Edns.Tests.csproj"),
    ("dnssec",     r"conformance\DNSConformance.Dnssec.Tests\DNSConformance.Dnssec.Tests.csproj"),
    ("server",     r"conformance\DNSConformance.Server.Tests\DNSConformance.Server.Tests.csproj"),
    ("client",     r"conformance\DNSConformance.Client.Tests\DNSConformance.Client.Tests.csproj"),
    ("transports", r"conformance\DNSConformance.SecureTransports.Tests\DNSConformance.SecureTransports.Tests.csproj"),
]

OLD = """            => (RawTTL & 0x80000000) != 0
                   ? 0
                   : RawTTL;"""

# RFC 2181 §8's masking disabled: a TTL with the sign bit set is taken at face
# value instead of being read as zero. Both branches are UInt32, so this
# compiles — unlike the first attempt at this control, `? 0 : 0`, whose two int
# literals gave the conditional a natural type of int and failed to build. That
# failure was silent in the sense that mattered: every project reported
# refreshed=False and zero failures, which reads exactly like a broken bench.
#
# And nine tests in WireFormat.Tests assert this very rule, so the expected
# result is known in advance rather than discovered.
NEW = """            => (RawTTL & 0x80000000) != 0
                   ? RawTTL /*MUTANT*/
                   : RawTTL;"""

FAILED = re.compile(r"(?:Fehler|Failed):\s*(\d+)")
TOTAL  = re.compile(r"(?:gesamt|total):\s*(\d+)", re.IGNORECASE)


def run(cmd, timeout=1800):
    return subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def dll_of(proj):
    return os.path.join(ROOT, os.path.dirname(proj),
                        "bin", "Debug", "net10.0", "org.GraphDefined.Vanaheimr.Hermod.dll")


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


def endings(s, nl):
    return s.replace("\r\n", "\n").replace("\n", nl)


def main():

    for name, proj in PROJECTS:
        if not os.path.exists(dll_of(proj)):
            sys.exit("guard is broken, no such assembly for %s:\n  %s" % (name, dll_of(proj)))

    print("all seven assemblies found\n")

    text, nl, bom = read(TARGET)
    needle = endings(OLD, nl)

    if text.count(needle) != 1:
        sys.exit("anchor occurs %dx in ADNSResourceRecord.cs, expected 1" % text.count(needle))

    # Baseline, so "failures" below is caused by the mutation and nothing else.
    print("baseline:")
    baseline = {}
    for name, proj in PROJECTS:
        run(["dotnet", "build", os.path.join(ROOT, proj), "-v", "q", "--nologo"])
        out = run(["dotnet", "test", os.path.join(ROOT, proj), "--no-build", "-v", "q", "--nologo"]).stdout or ""
        f, t = FAILED.search(out), TOTAL.search(out)
        baseline[name] = (int(f.group(1)), int(t.group(1))) if f and t else None
        print("  %-11s %s" % (name, baseline[name]))
        if baseline[name] is None or baseline[name][0] != 0:
            sys.exit("baseline for %s is not clean" % name)

    print()
    print("mutation: RFC 2181 &sect;8 masking disabled - a sign-bit TTL taken at face value")
    print()

    results = []

    try:

        write(TARGET, text.replace(needle, endings(NEW, nl), 1), nl, bom)

        back, _, _ = read(TARGET)
        if "/*MUTANT*/" not in back:
            sys.exit("marker not on disk")

        for name, proj in PROJECTS:

            dll    = dll_of(proj)
            before = os.path.getmtime(dll)

            b = run(["dotnet", "build", os.path.join(ROOT, proj), "-v", "q", "--nologo"])
            built_ok = b.returncode == 0

            after     = os.path.getmtime(dll)
            refreshed = after > before

            out = run(["dotnet", "test", os.path.join(ROOT, proj), "--no-build", "-v", "q", "--nologo"]).stdout or ""
            f, t = FAILED.search(out), TOTAL.search(out)
            counted = (int(f.group(1)), int(t.group(1))) if f and t else None

            results.append((name, built_ok, refreshed, counted))
            print("  %-11s build=%-5s refreshed=%-5s %s"
                  % (name, built_ok, refreshed, counted))

    finally:
        write(TARGET, text, nl, bom)
        for _, proj in PROJECTS:
            run(["dotnet", "build", os.path.join(ROOT, proj), "-v", "q", "--nologo"])
        print("\nsource restored and every project rebuilt")

    print()
    print("=" * 78)

    not_refreshed = [n for n, _, r, _ in results if not r]
    blind         = [n for n, _, _, c in results if c is not None and c[0] == 0]

    if not_refreshed:
        print("BROKEN: these projects did not rebuild Hermod: %s" % ", ".join(not_refreshed))
        print("        every SURVIVED-EVERYWHERE verdict from them is worthless.")
    else:
        print("every project rebuilt the assembly it loads - pass 2's builds took effect")

    print()
    print("projects that noticed a TTL of zero: %s"
          % ", ".join(n for n, _, _, c in results if c and c[0] > 0))
    print("projects that did not:               %s" % (", ".join(blind) or "none"))
    print("=" * 78)


if __name__ == "__main__":
    main()
