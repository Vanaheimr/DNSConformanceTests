# -*- coding: utf-8 -*-
"""Write down which gaps are closed, so the standing count is derived instead of
typed. Seven rounds so far, each verified by mutations taken from the sweep's own
output.

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

    # The rest of the boundaries. Twelve of these are the same guard in twelve
    # record types — RFC 1035 §4.1.3's 65535 — reached from both sides for the
    # first time; the others are where a presentation format is allowed to stop.
    "bounds2": {"DNS/ResourceRecords/TXT.cs":            {614},
                "DNS/ResourceRecords/SPF.cs":            {197},
                "DNS/ResourceRecords/URI.cs":            {258},
                "DNS/ResourceRecords/UnknownRecord.cs":  {127},
                "DNS/ResourceRecords/RRSIG.cs":          {364},
                "DNS/ResourceRecords/SIG.cs":            {361},
                "DNS/ResourceRecords/TSIG.cs":           {280},
                "DNS/ResourceRecords/TKEY.cs":           {272},
                "DNS/ResourceRecords/NSEC.cs":           {219},
                "DNS/ResourceRecords/ADNSResourceRecord.cs": {344, 388, 617, 1013},
                "DNS/ResourceRecords/SVCB.cs":           {172, 288, 330, 496},
                "DNS/ResourceRecords/HTTPS.cs":          {196, 237, 282, 402},
                "DNS/ResourceRecords/LOC.cs":            {257, 337, 477, 481, 482, 484, 493},
                "DNS/ResourceRecords/NSEC3.cs":          {439},
                "DNS/ResourceRecords/NSEC3PARAM.cs":     {211},
                "DNS/ResourceRecords/OTP/EDNSClientSubnetOption.cs": {161},
                "DNS/ResourceRecords/IPSECKEY.cs":       {314}},

    # The branches, and the last six rejections. Where a line carries several
    # mutations of one operator — LOC's four hemisphere spellings, the printable
    # range's three ands — every one of them was run, because the sweep's row does
    # not say which of them survived.
    "branch2": {"DNS/ResourceRecords/A.cs":                          {209, 234},
                "DNS/ResourceRecords/AAAA.cs":                       {208, 233},
                "DNS/ResourceRecords/ADNSResourceRecord.cs":         {425, 440, 858, 862, 874, 1010, 1075, 1376},
                "DNS/ResourceRecords/CSYNC.cs":                      {182},
                "DNS/ResourceRecords/HTTPS.cs":                      {277, 335},
                "DNS/ResourceRecords/LOC.cs":                        {256, 487},
                "DNS/ResourceRecords/NAPTR.cs":                      {227},
                "DNS/ResourceRecords/OTP/EDNSClientSubnetOption.cs": {171},
                "DNS/ResourceRecords/OTP/EDNSCookieOption.cs":       {79},
                "DNS/ResourceRecords/RP.cs":                         {222},
                "DNS/ResourceRecords/RRSIG.cs":                      {301, 307, 310},
                "DNS/ResourceRecords/SRV/DNSSRVManager.cs":          {92},
                "DNS/ResourceRecords/SRV/SRVSpec.cs":                {38, 45, 163, 168, 175, 383, 423},
                "DNS/ResourceRecords/SVCB.cs":                       {371}},
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

        # The rest of the boundaries, sixth round.
        572:  "the owner name of a record it has just serialized always ends in a root label, so the walk cannot reach the end of the buffer",
        1206: "entering the loop at the end of the bitmap breaks at the window-header check two lines below",
        1209: "a window header with nothing behind it adds no types whether the loop leaves here or at the bitmap-length check",
        1222: "0x80 >> 8 is zero, so the ninth pass masks nothing and adds nothing",

        # The branches, seventh round.
        244:  "both call sites ask whether the record is null before calling, so the null check inside is one "
              "the caller has already made",
        433:  "an escape can only appear in the RDATA, and the RDATA tokens are rejoined with a single blank "
              "before any type parser sees them — so where the lexer split them survives as whitespace that "
              "every RDATA parser normalises again. In the header it would tell, and a name carrying an escape "
              "is refused before the lexer's state is ever consulted",
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

    "DNS/ResourceRecords/SVCB.cs": {
        382: "a token beginning with '=' gives either an empty key name or the whole token, and neither is a SvcParamKey",
        383: "the same token: the key name has already dropped the parameter, whatever the value is",
        439: "an empty token between two separators is yielded and then dropped for having no key name",
        446: "a trailing separator yields an empty final token, dropped for the same reason",
        518: "the '=' sits outside the conditional, so an empty value renders as 'key=' from both sides of it",
    },
    "DNS/ResourceRecords/HTTPS.cs": {
        288: "a token beginning with '=' gives either an empty key name or the whole token, and neither is a SvcParamKey",
        289: "the same token: the key name has already dropped the parameter, whatever the value is",
        345: "an empty token between two separators is yielded and then dropped for having no key name",
        352: "a trailing separator yields an empty final token, dropped for the same reason",
        424: "the '=' sits outside the conditional, so an empty value renders as 'key=' from both sides of it",
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
    "DNS/ResourceRecords/URI.cs": {
        192: "at this revision the guard was one octet loose — RFC 7553 §4.5 needs at least five — but the "
             "empty target it let through was refused by URL.Parse on the next line, and both callers treat "
             "the two refusals alike: an UnknownRecord on the wire, 'could not parse RDATA' in a zone file. "
             "The guard has since been tightened to state the rule; the behaviour is the same",
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
# so neither "killed" nor "equivalent" would be a true thing to write down.
SUPERSEDED = {
    "DNS/ResourceRecords/SIG.cs": {
        265: "finding 55 replaced this condition with a call to the reader RRSIG already had, so SIG no longer "
             "has a type-covered parser of its own to get wrong",
        266: "the same line, and the TYPE0 special case with it: type 0 has no mnemonic, so the general rule "
             "writes and reads it like any other",
    },
    "DNS/ResourceRecords/SRV/DNSSRVEndpoint.cs": {
        272: "the body of the Equals that returned false unconditionally. The boundaries round replaced it with "
             "a seven-field comparison, and the mutants of that replacement (162, 177, 192, 207) were killed there",
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
        else:
            why = SUPERSEDED.get(rel, {}).get(ln)
            if why:
                rows.append((rel, str(ln), op, "superseded", "", why))

with io.open(OUT, "w", encoding="utf-8", newline="\n") as f:
    f.write("# Gaps that are no longer gaps, keyed to the same revision as the verdicts.\n")
    f.write("# 'killed' means a mutation taken from this sweep's output now fails a test.\n")
    f.write("# 'equivalent' means the mutation is real and the program is the same either way.\n")
    f.write("# 'superseded' means the line the verdict belongs to was replaced by a fix.\n")
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
