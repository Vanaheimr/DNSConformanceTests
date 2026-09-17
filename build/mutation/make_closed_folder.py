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

    # RFC 1035 §4.1.2 and §4.1.1, and RFC 5452 §9.1: a question is a name, a type
    # and a class, all three of them, in that order — and a query that names no
    # type still asks for something. The last of the block.
    "question": {

        "DNS/DNSQuestion.cs": {190, 193, 227, 229, 230},
        "DNS/DNSPacket.cs":   {260, 372},

    },

    # RFC 6763 §4.1/§4.1.1: the Service Instance Name — an instance label, the one
    # restriction on what a person may write in it, and Net-Unicode. Fifteen of
    # the sixteen; the type had no test of its own before this round.
    "instancename": {

        "DNS/DNSServiceInstanceName.cs": {43, 50, 175, 179, 194, 197, 200, 203,
                                          342, 357, 372, 387, 455},

    },

    # RFC 1035 §5.1: the master file format, and what it refuses — the directives,
    # the owner name a line does not state, and where a backslash stops a
    # semicolon or a parenthesis from meaning what it usually means.
    "zonefile": {

        "DNS/DNSZoneFile.cs": {123, 129, 181, 215, 229, 321, 328},

    },

    # RFC 1035 §3.3/§4.1.1/§4.1.4 and §2.3.4: the helpers every message passes
    # through — reading a name and a character-string off the wire, writing a name
    # back, and the compression table a serializer leaves behind. Eleven of the
    # fifteen; the other four are real and unobservable.
    "dnstools": {

        "DNS/Helpers/DNSTools.cs": {(33, "true-to-false"), 224, 243, 314, 347,
                                    351, 368, 389, 414, 422, 550},

    },

    # RFC 1035 §2.3.1/§2.3.4/§4.1.4/§5.1 and RFC 4343: what a name is made of, how
    # long it may be, what a backslash means in it, and which two names are one.
    # Three files taken together because they answer the same rules — thirty-five
    # of their forty-one gaps, plus the line the length fix replaced, re-measured
    # where the fix put it (DomainName.cs:431, killed, and no longer a sweep row).
    "names": {

        "DNS/DNSServiceName.cs": {43, 50, (181, "true-to-false"), 194, 215, 218, 230,
                                  245, 271, 283, 311, 345, 426, 516, 531, 546, 561},

        "DNS/DomainName.cs":     {41, 48, 133, 158, 167, 378, 414, 423, 500, 561,
                                  650, 665, 680, 695},

        "DNS/IDomainName.cs":    {40, 47},

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

    "DNS/Helpers/DNSPadding.cs": {

        152:
            "RFC 7830 §4's cap, at the length where the padded message lands exactly on it. "
            "Both readings answer the same there: if MeasuredLength + octets equals MaxLength "
            "then MaxLength - MeasuredLength is octets, so the branch the mutant takes "
            "recomputes the number the original kept. The boundary is exercised — "
            "Block_Length_Arithmetic_A_Ceiling_On_The_Boundary_Does_Not_Bite pads 85 octets to "
            "468 against a ceiling of 468 — and it still cannot tell them apart",

    },

    "DNS/DNSServiceInstanceName.cs": {

        213:
            "the refusal for a label String.Normalize cannot compose. It is unreachable: every "
            "path into TryNormalizeLabels runs DNSServiceName.TryParse or .Parse first, whose "
            "TryValidateLabels counts the label's octets with a UTF8Encoding built to throw on "
            "invalid ones — and the strings the two reject are the same strings, the unpaired "
            "surrogates. The protected labels constructor would reach it, and nothing derives "
            "from this type. The guard is right to be there and no test can make it fire",

    },

    # All four are LogicalLines asking about a line that is empty at a point no
    # empty line can reach. depth only leaves zero on a line that has put a '('
    # into the builder, and the builder is only cleared where depth is back to
    # zero — so wherever these four are evaluated, the builder is non-empty and
    # the line is not blank.
    "DNS/DNSZoneFile.cs": {

        259:
            "the initial value of ownerOmitted. Every line that is not skipped passes through "
            "the branch that assigns it, and both yields are downstream of that branch, so "
            "nothing ever reads the initializer",

        275:
            "line.Length > 0 before looking at line[0]. A line that is empty after the comment "
            "is stripped is skipped several lines earlier unless the parenthesis depth is "
            "non-zero, and depth is non-zero only when the builder already holds something — "
            "which is the other branch. The guard is real and the case it guards cannot arrive",

        289:
            "complete.Length > 0 before yielding a joined line. Reaching it means at least one "
            "non-empty append, so the condition is true either way",

        294:
            "joined.Length > 0 for the group a missing ')' left open. When the builder is empty "
            "the mutant yields one more logical line, which is the empty string; the caller "
            "splits it into no tokens and moves on. No record, no error, no difference",

    },

    "DNS/Helpers/DNSTools.cs": {

        (33, "false-to-true"):
            "the first argument of UTF8Encoding decides what GetPreamble() returns, and this "
            "encoding is only ever asked for GetString. The same pair as DNSServiceName.cs:181, "
            "and the same half of it matters: the second argument is what refuses a label whose "
            "octets are not UTF-8, and a test now pins that",

        96:
            "FindLastRecordOffset refusing a message shorter than RFC 1035 §4.1.1's twelve-octet "
            "header. At exactly twelve both readings answer the same: with every count zero the "
            "walk ends where it started and returns -1, and with a count the message cannot keep "
            "the walk runs off the end, which both callers catch. TSIGSigner and SIG0Signer each "
            "check the length themselves before calling, so no caller can reach a difference",

        151:
            "the loop that reads an exact number of octets. At total == buffer.Length the mutant "
            "asks for one more read of zero octets, which returns zero and breaks out of the "
            "loop on the next line — the same octets, one wasted call",

        469:
            "ConfigureAwait(false) on the two-octet length prefix of a TCP or TLS message. It "
            "chooses which context the continuation resumes on, and a test host has no "
            "synchronization context for the two readings to differ about. It is a rule about "
            "library code, not a rule about DNS",

    },

    "DNS/DNSServiceName.cs": {

        (181, "false-to-true"):
            "the first argument of UTF8Encoding is encoderShouldEmitUTF8Identifier, which decides "
            "what GetPreamble() returns and nothing else. This encoding is only ever asked for "
            "GetByteCount and GetBytes, and neither of them emits a preamble, so both readings "
            "count and write the same octets. The second argument is the one that matters here, "
            "and a label holding an unpaired surrogate now pins it",

        397:
            "Labels.Count == 0 || Labels.All(label => label.Length == 0) — the two readings can "
            "only differ for a name that has labels and whose labels are all empty, because All "
            "is vacuously true over none. No such DNSServiceName can be built: TryParseLabels "
            "answers '.' with an empty list and refuses an empty label anywhere else, and "
            "TryValidateLabels refuses one on the FromLabels path too. DomainName reaches that "
            "state and its copy of the line was killed by the sweep; this one cannot",

    },

    "DNS/DomainName.cs": {

        462:
            "the label-length refusal cannot be reached. Every label is matched by "
            "DomainNameRegExpr first, whose label is [A-Za-z0-9] followed by at most "
            "[A-Za-z0-9-]{0,61} and a closing [A-Za-z0-9] — 63 characters at the outside — so a "
            "label of 64 is refused as a format error several lines earlier. RFC 1035 §2.3.4's "
            "rule is enforced; this is the second guard on it",

        465:
            "the hyphen check cannot be reached either, and for the same reason: the regex "
            "requires a letter or digit at both ends of every label, so no label arriving here "
            "starts or ends with one. Whether the condition is || or && makes no difference to "
            "a condition that is never true",

        468:
            "the refusal belonging to that unreachable hyphen check",

    },

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

CORE_SUPERSEDED = {

    "DNS/DomainName.cs": {
        420: "the length check the sweep measured counted characters and was one too loose; "
             "finding 57 replaced it with one that counts the wire form of RFC 1035 §3.1. The "
             "rule did not go away with the line — it was re-measured where the fix put it "
             "(line 431, greater-to-ge) and killed there by two tests",
    },

}


LEDGERS = {
    "core": (CORE_KILLED, CORE_EQUIVALENT, CORE_SUPERSEDED),
}


def listed(entries, line, operator):
    """A line may carry more than one mutation, and they need not share a verdict:
    where they do not, the entry names the operator as well."""
    return line in entries or (line, operator) in entries


def keyed(table, line, operator):
    return table.get((line, operator)) or table.get(line)


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
            if listed(files.get(rel, ()), ln, op):
                rows.append((rel, str(ln), op, "killed", round_name, ""))
                break

        else:
            why = keyed(equivalent.get(rel, {}), ln, op)
            if why:
                rows.append((rel, str(ln), op, "equivalent", "", why))
            else:
                why = keyed(superseded.get(rel, {}), ln, op)
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
