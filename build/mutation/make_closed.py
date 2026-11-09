# -*- coding: utf-8 -*-
"""Write down which gaps are closed, so the standing count is derived instead of
typed. Keyed to the block's second measurement, at Hermod 38f6a355. The first,
at 973fed31, and its nine rounds of tests are in this file's history; every
kill of those rounds dies again, and what they left open is listed here.

Three ways a gap stops being one:

  killed      a mutation taken from this sweep's output now fails a test
  equivalent  the mutation is real and the program is the same either way
  superseded  the line the verdict belongs to no longer exists, because a fix
              replaced it — neither of the other two would be true of it
"""

import io
import os

HERE       = os.path.dirname(os.path.abspath(__file__))
CLASSIFIED = os.path.join(HERE, "results", "records-classified.tsv")
OUT        = os.path.join(HERE, "results", "records-closed.tsv")

# Line numbers as the sweep measured them, at Hermod 38f6a355.
#
# Every row the first measurement's rounds closed by a test dies again in one
# of the two passes — except seven, which those rounds had claimed by line: a
# test killed one operator on the line and the entry named the line, so a
# second operator on it was closed unseen. MUTATION.md, "The result: the
# resource records, measured again", lists them. So every entry here names its
# operator, and an entry that names one matching no open row stops the script.
KILLED = {

    # The rows a test could reach without a fix: SSHFP in RFC 3597 §5's generic
    # form, a DHCID of exactly its header in base64, the two ends of a signature
    # time, \X before two digits, and \255. Each was planted on its own and
    # fails its own test and nothing else.
    "the-open-rows-a-test-reaches": {
        "DNS/ResourceRecords/SSHFP.cs":              {(169, "logical-and-to-or"), (172, "logical-and-to-or")},
        "DNS/ResourceRecords/DHCID.cs":              {(191, "ge-to-greater")},
        "DNS/ResourceRecords/ADNSResourceRecord.cs": {(832, "less-to-less-or-equal"), (832, "greater-to-ge")},
        "DNS/ResourceRecords/TXT.cs":                {(565, "logical-and-to-or"), (566, "logical-and-to-or"),
                                                      (574, "greater-to-ge")},
    },

}

# Mutations that are real and unobservable: the program is the same either way.
# Read again against 38f6a355. The first measurement argued all of them but the
# three in TXT, whose lines moved when e592b5e7 (findings 55 and 56) rewrote the
# quoted reader, and whose arguments are worded for the code they now sit in.
EQUIVALENT = {
    "DNS/ResourceRecords/APL.cs": {
        144:  "width is 4, 16, or AFDPart.Length itself, so both branches return the same octets",
        188:  "a slash at position 0 leaves an empty address the parser refuses twelve lines later",
        401:  "TryParse nulls Item on every false it returns, so the two operands never differ",
    },
    "DNS/ResourceRecords/TXT.cs": {
        459:  "an empty text returns before the loop, and every other text leaves its last rune in the builder, "
              "so the builder is never empty here",
        515:  "equals is 0 only when the text starts with '=', which ParseKeyValues skipped five lines earlier",
        516:  "the same: position zero is unreachable here",
    },
    "DNS/ResourceRecords/ADNSResourceRecord.cs": {
        1162: "a window header at the very end of the buffer carries no bitmap, so entering it and skipping it both end in false",
        572:  "the owner name of a record it has just serialized always ends in a root label, so the walk cannot reach the end of the buffer",
        1206: "entering the loop at the end of the bitmap breaks at the window-header check two lines below",
        1209: "a window header with nothing behind it adds no types whether the loop leaves here or at the bitmap-length check",
        1222: "0x80 >> 8 is zero, so the ninth pass masks nothing and adds nothing",
        244:  "both call sites ask whether the record is null before calling, so the null check inside is one "
              "the caller has already made",
        567:  "Serialize is called with no offset table, and DomainName.Serialize starts a fresh empty one per "
              "name, so nothing is ever in it to point at",
        622:  "the name is the first thing written into a fresh stream with an empty table",
        1089: "ReadBackFromWire writes the stated class into the wire form it reads back, so a record reaching "
              "this line is already in the class the line stated",
        1387: "the same as 622: the new owner goes first, into an empty stream with an empty table",
    },

    # RFC 1035 §2.3.4 stops a domain name at 255 octets on the wire, so a record
    # whose RDATA is names plus fixed fields cannot come within three orders of
    # magnitude of the 65535 its serializer guards against. The test that shows
    # the cap is in the suite, not in this comment: RdataLengthTests.
    "DNS/ResourceRecords/CNAME.cs":  {199: "one name, and RFC 1035 §2.3.4 stops a name at 255 octets"},
    "DNS/ResourceRecords/NS.cs":     {197: "one name, and RFC 1035 §2.3.4 stops a name at 255 octets"},
    "DNS/ResourceRecords/PTR.cs":    {223: "one name, and RFC 1035 §2.3.4 stops a name at 255 octets"},
    "DNS/ResourceRecords/DNAME.cs":  {372: "one name, and RFC 1035 §2.3.4 stops a name at 255 octets"},
    "DNS/ResourceRecords/MX.cs":     {215: "two octets and a name, so at most 257"},
    "DNS/ResourceRecords/AFSDB.cs":  {218: "two octets and a name, so at most 257"},
    "DNS/ResourceRecords/SRV.cs":    {272: "six octets and a name, so at most 261"},
    "DNS/ResourceRecords/RP.cs":     {227: "two names, so at most 510"},
    "DNS/ResourceRecords/SOA.cs":    {316: "two names and twenty octets, so at most 530"},
    "DNS/ResourceRecords/NAPTR.cs":  {276: "four octets, three character-strings capped at 255 each, and a name — at most 1027"},

    "DNS/ResourceRecords/LOC.cs": {
        461: "parts.Length < 4 has already returned; idx is 0 here, so both readings are true",
        465: "idx is 1 and parts.Length at least 4",
        466: "idx is 1 or 2 and parts.Length at least 4",
        468: "idx is at most 3 and parts.Length at least 4",
        331: "9e9 centimetres reduces through the loop to 9e0 as well, so both paths return 0x99",
    },

    "DNS/ResourceRecords/NSEC3.cs": {
        364: "base32hex: whenever a five-bit group is emitted it is still the k-th group of the stream, "
             "and the trailing partial group is written with an expression that coincides with the loop's "
             "at that offset — the same string comes out either way, which a test written to kill it proved "
             "by surviving",
    },

    "DNS/ResourceRecords/OTP/EDNSClientSubnetOption.cs": {
        132: "a source prefix of zero bits makes trailingBits zero as well, and the inner guard skips the indexing",
    },
    "DNS/ResourceRecords/OTP/OPT.cs": {
        124: "entering the loop with no octets left breaks immediately at the four-octet header check",
        146: "ReadExactly of zero octets is exactly what the skipped branch does",
    },
    "DNS/ResourceRecords/OTP/EDNSExtendedDNSError.cs": {
        247: "Array.Copy of zero octets is exactly what the skipped branch does",
    },
    "DNS/ResourceRecords/OTP/EDNSCookieOption.cs": {
        57: "the constructor refuses a server cookie shorter than eight octets (RFC 7873 §5.2), so an empty one never reaches this",
    },

    "DNS/ResourceRecords/IPSECKEY.cs": {
        419: "the gateway name is serialized on its own, with no offset table at all",
        432: "parts[4..] of a four-element array is empty, and Convert.FromBase64String(\"\") is the empty array the other branch starts with",
    },
    "DNS/ResourceRecords/SRV/DNSSRVCacheEntry.cs": {
        50: "the boundary is one instant of the system clock, and no test can place Timestamp.Now exactly on it",
    },
    "DNS/ResourceRecords/SRV/SRVSpec.cs": {
        77: "the constructor is private and TryParse refuses a half, so the two identifiers are empty together "
            "or neither is — and || and && agree on both states",
        83: "the same pair, the same two states",
    },
}

# Lines a fix removed. The verdict was measured on code that is no longer there,
# so neither "killed" nor "equivalent" would be a true thing to write down. The
# first measurement had three; at 38f6a355 none of their lines carries a
# survivor, so there is nothing here to supersede.
SUPERSEDED = {}

def listed(entries, line, operator, occurrence):
    for entry in ((line, operator, occurrence), (line, operator), line):
        if entry in entries:
            return entry
    return None


rows, used = [], set()
for line in io.open(CLASSIFIED, encoding="utf-8"):
    if line.startswith("#"):
        continue
    p = line.rstrip("\n").split("\t")
    if len(p) < 5 or p[3].startswith("noise"):
        continue
    rel, ln, op = p[0], int(p[1]), p[2]

    # A bare line number claims every operator on the line and every occurrence
    # of each, and a line can carry one operator up to four times. Where a round
    # did not see all of them, the entry names the operator, or the operator and
    # the occurrence, as make_closed_folder.py's entries can. Each row keeps its
    # occurrence, which standing.py reads as a seventh column. MUTATION.md, "One
    # row per mutant", has which lines needed it.
    occ  = int(p[5]) if len(p) > 5 else None
    tail = () if occ is None else (str(occ),)

    for round_name, files in KILLED.items():
        entry = listed(files.get(rel, ()), ln, op, occ)
        if entry is not None:
            used.add((round_name, rel, entry))
            rows.append((rel, str(ln), op, "killed", round_name, "") + tail)
            break
    else:
        why = EQUIVALENT.get(rel, {}).get(ln)
        if why:
            rows.append((rel, str(ln), op, "equivalent", "", why) + tail)
        else:
            why = SUPERSEDED.get(rel, {}).get(ln)
            if why:
                rows.append((rel, str(ln), op, "superseded", "", why) + tail)

# An entry that names an operator or an occurrence and closes nothing is a typo
# that leaves its row open without a word, so it is refused. A bare line that
# matches nothing is the older form and keeps the older leniency.
stray = ["%s %s:%s" % (round_name, rel, ":".join(str(x) for x in entry))
         for round_name, files in KILLED.items()
         for rel, entries in files.items()
         for entry in entries
         if isinstance(entry, tuple) and (round_name, rel, entry) not in used]
if stray:
    raise SystemExit("these ledger entries match no gap in records-classified.tsv:\n  "
                     + "\n  ".join(sorted(stray)))

with io.open(OUT, "w", encoding="utf-8", newline="\n") as f:
    f.write("# Gaps that are no longer gaps, keyed to the same revision as the verdicts.\n")
    f.write("# 'killed' means a mutation taken from this sweep's output now fails a test.\n")
    f.write("# 'equivalent' means the mutation is real and the program is the same either way.\n")
    f.write("# 'superseded' means the line the verdict belongs to was replaced by a fix.\n")
    if any(len(r) > 6 for r in rows):
        f.write("# file\tline\toperator\tstate\tround\twhy\toccurrence\n")
    else:
        f.write("# file\tline\toperator\tstate\tround\twhy\n")
    for r in rows:
        f.write("\t".join(r) + "\n")

killed = sum(1 for r in rows if r[3] == "killed")
equiv  = sum(1 for r in rows if r[3] == "equivalent")
gone   = sum(1 for r in rows if r[3] == "superseded")
print("wrote %s" % OUT)
print("  killed      %3d" % killed)
print("  equivalent  %3d" % equiv)
print("  superseded  %3d" % gone)
