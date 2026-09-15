# -*- coding: utf-8 -*-
"""Write down which gaps are closed, so the standing count is derived instead of
typed. Four rounds so far, each verified by mutations taken from the sweep's own
output."""

import io
import os

ROOT = r"D:\Coding\Vanaheimr\DNSConformanceTests"
CLASSIFIED = os.path.join(ROOT, r"build\mutation\results\records-classified.tsv")
OUT        = os.path.join(ROOT, r"build\mutation\results\records-closed.tsv")

# Line numbers as the sweep measured them, at Hermod 973fed31.
KILLED = {
    "apl":    {"DNS/ResourceRecords/APL.cs": {114, 178, 181, 189, 192, 202, 203, 206, 216, 217, 220, 231, 317}},
    "txt":    {"DNS/ResourceRecords/TXT.cs": {338, 392, 478, 503, 534, 535, 539, 540, 551, 554, 555, 557,
                                              561, 569, 570, 573, 578, 581}},
    "adns":   {"DNS/ResourceRecords/ADNSResourceRecord.cs": {515, 703, 731, 758, 759, 761, 778, 779, 827,
                                                             832, 833, 953, 959, 1045, 1052, 1056,
                                                             1171, 1179, 1180, 1191}},
    "bounds": {"DNS/ResourceRecords/SRV/DNSSRVEndpoint.cs":  {162, 177, 192, 207},
               "DNS/ResourceRecords/SRV/SRVSpec.cs":         {302, 317, 332, 347},
               "DNS/ResourceRecords/IPSECKEY.cs":            {230, 231, 232},
               "DNS/ResourceRecords/DHCID.cs":               {157, 191},
               "DNS/ResourceRecords/OTP/EDNSExtendedDNSError.cs": {265, 270},
               "DNS/ResourceRecords/SVCB.cs":                {368, 376},
               "DNS/ResourceRecords/HTTPS.cs":               {274},
               "DNS/ResourceRecords/NSEC.cs":                {175},
               "DNS/ResourceRecords/LOC.cs":                 {451}},

    # Branches: conditions whose two sides were never both taken. Only the lines
    # actually mutated and seen to fall are listed; the neighbouring ones that a
    # test happens to cover are not claimed without a verdict.
    "branch": {"DNS/ResourceRecords/SSHFP.cs":     {169, 172},
               "DNS/ResourceRecords/SVCB.cs":      {434, 437},
               "DNS/ResourceRecords/HTTPS.cs":     {340, 343},
               "DNS/ResourceRecords/IPSECKEY.cs":  {166, 175, 187},
               "DNS/ResourceRecords/LOC.cs":       {470, 471, 486},
               "DNS/ResourceRecords/ADNSResourceRecord.cs": {656, 690},
               "DNS/ResourceRecords/RRSIG.cs":     {291}},
}

# Mutations that are real and unobservable: the program is the same either way.
EQUIVALENT = {
    "DNS/ResourceRecords/APL.cs": {
        144:  "width is 4, 16, or AFDPart.Length itself, so both branches return the same octets",
        188:  "a slash at position 0 leaves an empty address the parser refuses twelve lines later",
        401:  "TryParse nulls Item on every false it returns, so the two operands never differ",
    },
    "DNS/ResourceRecords/TXT.cs": {
        452:  "only an empty text leaves the builder empty, and ValidateStrings turns [] into [\"\"] anyway",
        508:  "equals is 0 only when the text starts with '=', which ParseKeyValues skipped four lines earlier",
        509:  "the same: position zero is unreachable here",
    },
    "DNS/ResourceRecords/ADNSResourceRecord.cs": {
        1162: "a window header at the very end of the buffer carries no bitmap, so entering it and skipping it both end in false",
    },
}

rows = []
for line in io.open(CLASSIFIED, encoding="utf-8"):
    if line.startswith("#"):
        continue
    p = line.rstrip("\n").split("\t")
    if len(p) < 5 or p[3].startswith("noise"):
        continue
    rel, ln, op = p[0], int(p[1]), p[2]

    for round_name, files in KILLED.items():
        if ln in files.get(rel, ()):
            rows.append((rel, str(ln), op, "killed", round_name, ""))
            break
    else:
        why = EQUIVALENT.get(rel, {}).get(ln)
        if why:
            rows.append((rel, str(ln), op, "equivalent", "", why))

with io.open(OUT, "w", encoding="utf-8", newline="\n") as f:
    f.write("# Gaps that are no longer gaps, keyed to the same revision as the verdicts.\n")
    f.write("# 'killed' means a mutation taken from this sweep's output now fails a test.\n")
    f.write("# 'equivalent' means the mutation is real and the program is the same either way.\n")
    f.write("# file\tline\toperator\tstate\tround\twhy\n")
    for r in rows:
        f.write("\t".join(r) + "\n")

killed = sum(1 for r in rows if r[3] == "killed")
equiv  = sum(1 for r in rows if r[3] == "equivalent")
print("wrote %s" % OUT)
print("  killed      %3d" % killed)
print("  equivalent  %3d" % equiv)
