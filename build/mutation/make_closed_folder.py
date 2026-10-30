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

        270: "depth == 0 && joined.Length == 0 && line.Trim().Length == 0, the early "
             "continue for a blank line - in two of its three readings. The line below it, "
             "if (complete.Length > 0) yield return ..., already refuses to emit an empty "
             "record, so the continue is a shortcut and not a guard: a blank line that "
             "falls past it is appended, produces an empty complete, and is dropped there "
             "instead. The only state it skips setting is ownerOmitted and startedAt, and "
             "the next line that actually starts a record sets both again, because joined "
             "is empty by then. The third reading, which skips NON-blank lines, is the one "
             "that fails a test",

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

        # A ConfigureAwait entry stood here, and another in the core table. Both had
        # worked out on their own that a test host has no synchronization context
        # for the two readings to differ about, one block at a time and years
        # apart in reading order. The triage now names the whole class - see
        # host-only in classify_folder.py - so the individual arguments are gone
        # and the general one is written once.

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


# ---------------------------------------------------------------------- tsig

TSIG_KILLED = {

    # RFC 8945 §5.2.3's fudge and §4.3.1's request MAC, RFC 2931 §3.3's validity
    # bracket, and the algorithm allow-list — the four places where one comparison
    # decides whether a captured message still works. Each was already tested and
    # each test stepped over the boundary without landing on it.
    "windows": {

        "DNS/TSIG/SIG0Signer.cs":     {398},
        "DNS/TSIG/TSIGAlgorithms.cs": {86},
        "DNS/TSIG/TSIGSigner.cs":     {181, 337},

    },

    # RFC 8945 §5.1 and RFC 2931 §3/§3.2 — the front door. What the two strip
    # functions say about a message before a key is chosen: too short to be a
    # message, an ARCOUNT that lies, a record cut off, octets after the last
    # record, something at the end that is not a signature, and a SIG that covers
    # an RRset rather than this message.
    "stripping": {

        "DNS/TSIG/SIG0Signer.cs": {148, 283, 434, 439, 447, 456, 475},
        "DNS/TSIG/TSIGSigner.cs": {103, 396, 412},

    },

    # RFC 2539 §2's length-prefixed Diffie-Hellman fields and RFC 2930 §4.1's
    # XOR. Three refusals that each need their own shape of malformed RDATA to
    # reach, the one length that is well formed and zero, and the operand that
    # runs out first in every real exchange.
    "tkey": {

        "DNS/TSIG/TKEYExchange.cs": {198, 265, 290, 291, 297},

    },

}

TSIG_EQUIVALENT = {

    # The guard chains. Both strip functions set every out parameter before their
    # single 'return true' and return false on every other path, so a null output
    # alongside a true result cannot occur — which is what the second and third
    # terms of each chain test for. Whichever of the connectives is changed, the
    # expression agrees with the original on both of the two cases that can
    # actually arrive. Defensive redundancy, not a gap.
    "DNS/TSIG/DNSTransactionSecurity.cs": {
        165: "TryStripTSIG(...) && withoutTSIG is not null — the second term cannot be false "
             "when the first is true",
        192: "TryStripSIG0(...) && withoutSIG0 is not null — the same, for the other kind",
    },

    "DNS/TSIG/TSIGSigner.cs": {

        177: "now > tsig.TimeSigned, choosing which way round to subtract for the skew. At "
             "equality both readings give zero, because that is the one value where the two "
             "subtractions agree — and away from equality the condition already decides the "
             "same way",
        148: "the !TryStripTSIG(...) term of Verify's chain. With || turned into && the "
             "expression is (!Try && tsig is null) || unsigned is null, which answers as the "
             "original does for both reachable cases: a failed strip leaves both outputs null "
             "and a successful one leaves neither",
        149: "the 'tsig is null' term of the same chain, with the same argument",
        212: "the same chain again in BuildErrorResponse's sibling",
        249: "SignedRequest.Length < 12 in BuildErrorResponse. At exactly twelve octets the "
             "mutant returns null at once and the original walks one step further into "
             "TryStripTSIG, which refuses a twelve-octet message for its own reasons and "
             "returns null too",
        255: "the !TryStripTSIG(...) term of BuildErrorResponse's chain",
        256: "the 'unsigned is null' term of it",
        395: "SignedMessage.Length < 12 in TryStripTSIG. Twelve octets is a header and nothing "
             "else: with ARCOUNT zero the walk has no records to find and with ARCOUNT set the "
             "walk reads past the end and throws into the catch. Both readings answer false",
        411: "offset < 0 after FindLastRecordOffset. That method returns -1 or a position it "
             "took at the start of a record, and the first record cannot begin before octet "
             "twelve — so zero is not among its answers and <= 0 tests for a value that never "
             "arrives",

    },

    "DNS/TSIG/SIG0Signer.cs": {

        241: "the !TryStripSIG0(...) term of the multi-key Verify's chain",
        306: "TryStripSIG0(...) && withoutSIG0 is not null in CarriesBothTSIGAndSIG0",
        309: "TryStripTSIG(...) && withoutTSIG is not null in the same method",
        335: "the !TryStripSIG0(...) term of the single-key Verify's chain",
        336: "the 'sig is null' term of it",
        433: "SignedMessage.Length < 12 in TryStripSIG0 — the same argument as TSIGSigner:395",
        446: "offset < 0 in TryStripSIG0 — the same argument as TSIGSigner:411",

        527: "Request.Length > 0 before folding the request into the signed data. SIG(0) "
             "writes the request's octets and nothing else, so an empty request writes "
             "nothing under either reading. TSIGSigner's counterpart at line 337 looks "
             "identical and is not: it writes a two-octet length first, so an empty MAC puts "
             "00 00 into the digest that a peer would not have. The same guard, one of them "
             "load-bearing and one not — which is why 337 was killed by a test and this was "
             "predicted to be and was not",
    },

}

TSIG_SUPERSEDED = {

    "DNS/TSIG/SIG0Signer.cs": {
        459: "the owner.Length == 0 test in TryStripSIG0's ternary, whose true branch no "
             "caller could reach: DNSTools.ExtractName ends on String.IsNullOrEmpty(result) "
             "? \".\" : result and never hands back an empty string, so the guard answered "
             "for a case that does not arrive. The mutation was not equivalent - inverting "
             "it gave every SIG(0) the root as its owner name, and RFC 2931 section 3 "
             "allows a real one there, calling the field meaningless and the root a SHOULD. "
             "So the behaviour was pinned first, by a test that reads back a SIG(0) whose "
             "owner is not root and watches the verdict not move, and the dead branch was "
             "removed after. The line the verdict was measured on is gone and nothing "
             "mutable is left on it",
    },

}


# -------------------------------------------------------------------- dnssec
#
# Keyed to Hermod bbbf88b6, the revision the second sweep of this block
# measured. The first sweep measured 53f20591, and its ledger - sixty-five gaps
# closed by tests in twelve rounds, nine mutants declared equivalent - is kept
# as it was written: the rows in results/dnssec-53f20591/dnssec-closed.tsv, and
# the tables that produced them in this file as of b07f4c1.
#
# None of those is carried over by number, and none needs to be. A gap a test
# closed is killed by that test in the new pass 1 and never reaches the
# classification. A row that would need its old entry here is one the test no
# longer catches - and two of them did not, which MUTATION.md tells.

DNSSEC_KILLED = {

    # RFC 6672 section 5.3.1: the CNAME a server synthesizes from a DNAME "will
    # never be signed", and the validator accepts it because the signed DNAME
    # beside it produces it - and for no other reason. No test had handed the
    # validator a DNAME at all. One answer the DNAME does explain, and three it
    # does not: a target rewritten (section 5.3.4's own attack), a CNAME at the
    # DNAME's own owner name, which section 2.3 says is not redirected, and one
    # across a label boundary, which section 2.2's table says is no match.
    "dname-synthesis": {
        "DNS/DNSSEC/DNSSECValidator.cs": {684, 685, 687, 689, 693},
    },

    # RFC 4035 section 5.2, the step up from a signed answer: the DS RRset is
    # "authenticated using some DNSKEY RR in the parent's apex DNSKEY RRset", so
    # a signer that is not strictly above the child (1202, 1203) is nobody's
    # word; a proof that the DS is absent is the parent's too, and a child that
    # signs one for itself (1350) proves nothing; and that proof counts only
    # once the walk has authenticated the parent's keys above it (1178). Whether
    # a missing DS needed a proof at all is the anchors' to say (720). And
    # section 5.3.1's first condition, "the same owner name", holds for the
    # key set's own signature as well as the answer's (1854).
    "the-ds-step": {
        "DNS/DNSSEC/DNSSECValidator.cs": {720, (1178, "inequality-to-equality"), 1202, 1203, 1350, 1854},
    },

    # RFC 4035 sections 4.3 and 5.2, the walk down from the closest anchor for
    # an answer that came unsigned. It asks about the owner itself, which is the
    # delegation when the answer is at a child's apex (1572); it crosses a signed
    # zone cut on the way, and checks the DS, its signature and the child's key
    # set as it does (1681, 1692, 1713) - a DS whose signature the parent's keys
    # do not verify leads nowhere (1692, 1693); and it goes on through a name
    # of the zone that is no zone cut, an empty non-terminal included (1733).
    "the-walk-down": {
        "DNS/DNSSEC/DNSSECValidator.cs": {1572, 1681, 1692, 1693, 1713, 1733},
    },

    # What may count as the proof that a delegation is unsigned. RFC 6840
    # section 4.4: "MUST check for the presence of the NS bit", or the genuine
    # NSEC of any ordinary name spoofs a delegation there (157, 259). The NSEC
    # has to be one the zone's keys verify (1422, 1423), under the zone's own
    # name (1406). The NSEC3 forms of the same proof: a record matching a
    # delegation, read from the reference chain only (246, 247), and an opt-out
    # span (213) - believed below an ordinary closest encloser and not below an
    # "ancestor delegation", RFC 6840 section 4.1 (165, 166).
    "what-proves-a-delegation-unsigned": {
        "DNS/DNSSEC/DNSSECValidator.cs": {1406, (1422, "logical-and-to-or"), 1423},
        "DNS/DNSSEC/DenialOfExistence.cs": {157, 165, 166, 213, 246, 247, 259},
    },

    # RFC 5155 section 8.3: for a top-level domain the only ancestor is the
    # root, so in a root zone signed with NSEC3 the root's own record is the
    # closest encloser - the last candidate of both walks up, the one that reads
    # the denial (300) and the one that reads its bitmap (218).
    "the-root-as-closest-encloser": {
        "DNS/DNSSEC/DenialOfExistence.cs": {218, 300},
    },

}

# The nine mutants the first sweep argued equivalent all survived again, on
# lines whose text did not change. Each argument was read again against the new
# code rather than moved with its number, because what makes a mutation
# equivalent is usually a caller, and the callers did change. Three are the
# second sweep's own, from the round that closed its rows: 1178 and 1422, two
# operands that cannot disagree and a set that cannot add anything, and 370,
# a guard in front of a clause that is false where the guard is.
DNSSEC_EQUIVALENT = {

    "DNS/DNSSEC/DNSSECValidator.cs": {

        2152: "dotIndex < 0 in GetParentZone, which answers '.' for a zone of one label. "
              "Its one caller left is the chain walk, and it asks whether the answer is "
              "null and nothing else - while both readings return a name, '.' or what "
              "follows the first dot, for every input that gets past the line above. The "
              "first sweep's argument, that Zone.TrimEnd('.') cannot begin with a dot "
              "because a DomainName cannot hold an empty leading label, still holds and is "
              "no longer needed",

        (1178, "logical-or-to-and"):
              "proof != Insecure || provenBy is null, after ProveNoDelegationSigner - which "
              "says one thing twice. Every one of its returns pairs Insecure with the parent "
              "whose keys signed the proof, and every other verdict with null, so the two "
              "operands are true together and false together, and where two operands always "
              "agree, or and and cannot differ. The other mutation of the line, != read as "
              "==, returns Insecure before the parent's keys are authenticated, and a test "
              "kills it",

        (1422, "greater-to-ge"):
              "rrSet.Count > 0 in DenialSignedBy. Read as >= 0 it is always true, and it "
              "differs only for an RRSIG over an NSEC or NSEC3 the authority section does not "
              "hold: the mutation then asks whether that signature verifies over an empty set. "
              "Whatever the answer, verified.AddRange adds the empty set, which is nothing, and "
              "asking has no side effect - ValidateRRSig catches everything, and VerifiedByOneOf "
              "only computes. The list the proof is read from is the same. The && beside it, "
              "read as ||, adds every RRset unverified, and a test kills that",

    },

    "DNS/DNSSEC/DNSSECZoneSigner.cs": {

        381: "the belt in front of the empty-non-terminal walk, whose every escape the "
             "braces two lines below already catch. All three mutations of it were run "
             "and all three survived, and the argument is that they must. dot <= 0 "
             "differs only for a name beginning with a dot, which a DomainName cannot "
             "hold and which stripping a label cannot produce. The other two let the "
             "walk take one more step, and that step either leaves the name unchanged "
             "(no dot) or empties it (the dot is last) - after which the very next "
             "line, name == Apex or name not ending in '.' + Apex, breaks before "
             "owners.Add is reached. The set of empty non-terminals is the same under "
             "all three readings",

    },

    "DNS/DNSSEC/DenialOfExistence.cs": {

        97:  "nsecs.Length > 0 before handing the records to VerifyNSEC. The line is only "
             "reached when there is no NSEC3 either, so the mutation calls VerifyNSEC with "
             "an empty array - where the NODATA loop has nothing to iterate and every "
             "Records.Any(...) is false, the empty-non-terminal clause included, so it "
             "returns NotProven. That is the same answer as the line below, which is what "
             "runs otherwise, and it is the same for the two callers Verify has gained",

        506: "Left[i] < Right[i] ? -1 : 1, which sits inside if (Left[i] != Right[i]). The "
             "two readings differ only when the two octets are equal, and the guard one "
             "line above is exactly the statement that they are not. The same shape as 573 "
             "below, in the hash domain instead of the name domain",

        573: "comparison < 0 ? -1 : 1, inside if (comparison != 0). The same argument as "
             "506: the value that separates < from <= is the one the guard above excludes",

        450: "CompareHashes(hash, owner) > 0 in FindCover, the lower end of an NSEC3's span - and "
             "the same argument as 525 below, which is the point of listing both. A name whose "
             "hash equals an owner matches that record, and VerifyNSEC3 looks for a match before "
             "it looks for a cover, at the queried name and again at every ancestor on the way "
             "up. Nothing can be handed to FindCover whose hash equals an owner in the set, and "
             "the code added since the first sweep calls FindMatch but never FindCover",

        525: "CompareCanonical(Name, owner) > 0 in Covers, the lower end of an NSEC's span. "
             "The two readings differ only when the name equals the owner, and no caller "
             "can put that case in front of it. For the queried name, VerifyNSEC's NODATA loop "
             "returns before Covers is reached whenever any record owns it - and the "
             "empty-non-terminal clause added since the first sweep comes after that loop too. "
             "For the wildcard, the very next clause asks whether a record owns that name and "
             "answers the same way in the same iteration, so the || is true either way. The "
             "guard at the other end of the span has no such cover, and a test kills it",

        370: "queryName.Length > 0 in front of the empty-non-terminal clause. The two readings "
             "differ only for the root, whose queryName is empty, and there the clause asks "
             "whether a next name ends in '.' followed by nothing - in a dot. Every next name "
             "is compared after TrimEnd('.'), which leaves no trailing dot to find, so the "
             "clause is false for the root whether the guard lets it run or not. The guard "
             "spares the work and decides nothing",

    },

}

DNSSEC_SUPERSEDED = {
}





# ---------------------------------------------------------------------------
#  server
# ---------------------------------------------------------------------------

SERVER_KILLED = {

    # RFC 4034 section 4.1.1: the last NSEC of a zone names the apex, so a zone
    # holding nothing but its apex has one NSEC whose next name is its own
    # owner. Its span is then everything below the apex rather than an interval
    # inside it, and a reading that wants "after the owner AND before the next"
    # answers no for every name there is. The NSEC3 chain has the same shape and
    # one failure more: owner and next being the same twenty octets is the only
    # call where the hash comparison runs to the end of both arrays.
    "apex-only-zone": {
        "DNS/Server/ZoneDenialOfExistence.cs": {311, 443, 597},
    },

    # RFC 4035 section 3.2.1 gates every answer a signed zone gives, not only
    # "no such name" - the existing test walked one of the four paths an
    # authoritative server reaches it from. Section 3.1.4 wants a referral to a
    # signed child to carry "both the DS RRset and its associated RRSIG RR(s)",
    # and a referral that drops the signature works for everyone who is not
    # validating. RFC 6672 section 2.3 allows a DNAME beside an NS RRset at the
    # zone apex and nowhere else, which makes it the last candidate the walk up
    # from QNAME considers - and the only one a bound a step short can lose.
    "signed-answers-and-the-apex": {
        "DNS/Server/InMemoryDNSZone.cs": {672, 684, 718, 754, 984},
    },

    # RFC 6891 section 6.2.3 calls the advertised size "the largest UDP payload
    # that can be reassembled and delivered", so a message of exactly that many
    # octets belongs on the inside of the limit - and the limit is consulted once
    # for the whole answer and again for each shortened one on the way down.
    # Section 6.1.1 has no exception for a response that had to shed everything:
    # the OPT is not an answer record and is not what had to go. And RFC 1035
    # section 4.1.1's header is twelve octets, which is the shortest message a
    # server can answer at all, because the transaction id is in the first two.
    "sizes-and-edges": {
        "DNS/Server/DNSMessagePipeline.cs": {150, 594, 602, 623},
    },

    # RFC 9110 section 12.4.2: "a value of 0 means 'not acceptable'", so naming
    # application/dns-message with q=0 names the only media type this server has
    # in order to exclude it - a refusal written as a mention, which anything
    # comparing media types alone reads as the opposite. And a DNS message is at
    # most 65535 octets because that is what RFC 1035 section 4.2.2's length
    # prefix can count, which makes 65535 the largest one allowed rather than the
    # first one too many.
    "doh-media-type-and-size": {
        "DNS/Server/DNSOverHTTPSResource.cs": {318, 494, 495},
    },

    # RFC 9018 section 4.3: a server "SHOULD allow cookies within a 1-hour period
    # in the past and a 5-minute period into the future" - a period OF an hour, so
    # a cookie exactly that old is inside it and one exactly five minutes ahead is
    # too. Both edges belong to the window. And RFC 7873 section 4.2 gives the
    # server cookie "a variable length, from 8 to 32 octets", so every legal
    # length arrives whatever this server mints; the ones it does not mint have to
    # be turned away by their length, with a timestamp current enough that nothing
    # else turns them away first.
    "cookie-window-and-lengths": {
        "DNS/Server/DNSCookies.cs": {159, 181, 182},
    },

    # RFC 2931 section 3 identifies the whole mechanism by one field: a SIG(0) is
    # "identified by having a 'type covered' field of zero". A SIG record with any
    # other value is an ordinary RFC 2535 signature over an RRset that happens to
    # travel in the additional section - it authenticates nothing about the
    # request, so the request is unsigned and has to be served as one.
    #
    # The line carries the same operator twice and the two mutants disagree. The
    # first connective guards a null TryStripSIG0 cannot produce and stays; the
    # second drops the type-covered test itself, and that one now fails a test.
    # The ledger keys on (file, line, operator) and cannot say "one of two", so
    # the line is recorded here and MUTATION.md carries which half is which.
    "the-sig-that-is-not-a-signature": {
        "DNS/Server/DNSMessagePipeline.cs": {419},
    },

}


SERVER_EQUIVALENT = {

    "DNS/Server/ZoneDenialOfExistence.cs": {

        # The two branches compute the same value.
        445: "Left[i] < Right[i] ? -1 : 1, under an if that has already established "
             "Left[i] != Right[i]. Less-than and less-or-equal cannot disagree where "
             "equality is excluded",
        565: "Skip >= Labels.Length ? \".\" : String.Join('.', Labels.Skip(Skip)) + \".\". "
             "At equality the other branch joins nothing and appends the dot, which is "
             "the same dot the first branch returns",

        # Guards against a state no caller produces. Every call of CoveringNSEC and
        # CoveringNSEC3 passes a name that does not exist in the zone - that is what
        # the callers are for - so a name equal to an owner or to a next name never
        # arrives, and the strictness of the comparison is never consulted. RFC 4034
        # section 4.1.3 wants it strict: a name equal to an owner is matched rather
        # than covered, and proving it absent would be proving a lie. The guard is
        # right and unreachable, which is the same category as the eighteen in the
        # tsig block.
        306: "above = CompareCanonical(Name, owner) > 0, where Name is a name the zone "
             "does not hold and owner is one it does",
        307: "below = CompareCanonical(Name, next) < 0 - next is the next existing name, "
             "so the same argument",
        369: "the NSEC3 twin of 306, over hashes",
        370: "the NSEC3 twin of 307",

        333: "Name is null || nsec3Parameters is null in MatchingNSEC3. Its three callers "
             "pass a name they have already checked, and with no parameters HashOf returns "
             "null on the next line anyway",
        352: "the same guard in CoveringNSEC3. Name can be null here - NextCloser returns "
             "null when QNAME is the encloser - but HashOf answers null for that too",
        424: "label is null || label.Length == 0 in OwnerHashOf. Split always yields at "
             "least one element, so FirstOrDefault over it is never null and only the "
             "length test can fire",
        528: "qnameLabels.Length <= encloserLabels.Length in NextCloser. The closest "
             "provable encloser is an ancestor of QNAME and never QNAME itself, because "
             "a name with a matching NSEC3 is a name that exists",

        # The mutation removes a path whose answer another path supplies.
        466: "the bound of ClosestEncloser's walk. Stopping one candidate short loses "
             "exactly the apex, and the return below the loop is the apex",
        371: "the NSEC3 wrap, and NOT for the reason its NSEC twin at 311 dies. The two "
             "readings differ only when owner and next are the same hash, which needs a "
             "chain of one record - and every NSEC3 proof that asks for a covering record "
             "has already asked for a matching one, which in such a zone is that same "
             "record. Collect drops the duplicate, so the response is identical whichever "
             "way the comparison reads. The NSEC branch has no matching call to fall back "
             "on, which is why the same mutation is a gap there and not here",

    },

    "DNS/Server/InMemoryDNSZone.cs": {

        489: "signingKeys is null || !SignaturesExpireAt.HasValue. The two are assigned "
             "once each, six lines apart in Sign and with no path between them that can "
             "fail, so they are null together and set together - and where the two "
             "operands always agree, or and and cannot",
        894: "return Records.Length > 0 in TryGetRecords. Add never creates an empty "
             "list, and Remove drops the key as soon as its list empties, so a "
             "TryGetValue that succeeded has found records",

    },

    "DNS/Server/AuthoritativeDNSRequestHandler.cs": {

        188: "the return false of HasValidServerCookie when no cookie secret is set. Its "
             "one caller opens with DNSCookieSecret is not null, so the method never runs "
             "in the state this line answers for",
        237: "the CNAME-and-ANY guard of FollowCanonicalNames, which is called only where "
             "the store answered NoData - and a node holding a CNAME answers Found to a "
             "query for CNAME or for ANY. The guard is right, says why in its own comment, "
             "and cannot be reached",

    },

    "DNS/Server/DNSMessagePipeline.cs": {

        # The guard chains, as in the tsig block - checked again for these call
        # sites rather than carried over. TryStripTSIG and TryStripSIG0 each have
        # exactly one `return true`, with every out parameter set above it, and
        # return false with both null on every other path. So a null output beside
        # a true result cannot arise, which is what the second and third terms of
        # each chain test for, and the expression agrees with the original on both
        # of the two cases that can actually happen.
        349: "!TryStripTSIG(...) || unsigned is null - the second term cannot be true "
             "when the first is false",
        350: "unsigned is null || tsig is null, the same chain one term along",
        418: "!TryStripSIG0(...) || unsigned is null - the same, for the other kind",

        374: "result.Error == BADTIME ? key : null, and equivalent only because of what "
             "BuildErrorResponse does with that key: nothing. It builds every refusal with "
             "MAC: [] and OtherData: [], so the argument reaches the record owner name and "
             "stops there - and when it is null the fallback makes an equivalent key out of "
             "the request TSIG, so both readings emit the same bytes. THIS ENTRY EXPIRES "
             "WITH FINDING 58: once a BADTIME reply is signed as RFC 8945 section 5.2.3 "
             "requires, the two readings differ and the test written for that finding kills "
             "this mutation",

        471: "the twelve-octet floor of BuildNotAuthorizedResponse. It answers a request "
             "whose signature did not verify, so the request carried a TSIG or a SIG(0) "
             "and is an order of magnitude longer than the header it is measured against",

    },

    "DNS/Server/DNSOverHTTPSResource.cs": {

        312: "queryBytes is null || queryBytes.Length == 0 for a POST body. The HTTP layer "
             "hands an empty array and never a null, so the first term is dead; and the "
             "second is redundant with the parser below, which refuses a nought-octet "
             "message anyway. Both readings answer 400, by different routes",
        556: "soa.Minimum < soa.TimeToLive ? soa.Minimum : soa.TimeToLive. Where the two are "
             "equal the branches return the same number, which is the only case the "
             "comparison could be changed about",

    },

    "DNS/Server/DNSOverHTTPSServer.cs": {

        313: "Request.HTTPMethod == POST, guarding the body read. The comment above it warns "
             "that asking a GET for its body would wait for octets never promised - and it "
             "would not: with no Content-Length the read returns at once, and for a POST the "
             "body is already materialised by the time this runs. The guard is belt and "
             "braces against a hazard this stack does not have",

    },

    "DNS/Server/DNSServer.cs": {

        1062: "length > sharedBuffer.Length, guarding the framed TCP read. The buffer comes "
              "from ArrayPool.Shared.Rent(UInt16.MaxValue), which allocates at least that "
              "much and in practice the next power of two, while length is a UInt16 and "
              "cannot exceed 65535. The comparison is never true, and the mutant is true "
              "only where the buffer is exactly 65535 - a size the shared pool's buckets do "
              "not produce. A guard that cannot fire either way",

        428:  "listener.Client.DualMode = false on the UDP side. Its own comment says why: "
              "with the IPv4 listener actually bound, IPv4 datagrams go to the IPv4 socket "
              "and the flag is never consulted. It states the intent and guards the degraded "
              "case where the second bind is removed",
        719:  "the same flag on the TCP side, for the same reason",

        378:  "bound.Count < endPoints.Count && !portChosenBySystem, which guards a "
              "logger.LogWarning and nothing else. Both mutations of the line change which "
              "runs are logged about, and nothing that reaches a socket",

    },

    "DNS/Server/DNSCookies.cs": {

        160: "ClientCookie.Length != 8 || ServerCookie[0] != Version, the second connective "
             "of the validator's guard chain. The version octet is inside the eight octets "
             "the keyed hash is computed over, so a cookie whose version is wrong has a MAC "
             "that cannot match - the explicit check decides nothing the comparison below "
             "does not decide again, and nobody without the secret can make the two disagree",

    },

    "DNS/Server/DNSOverHTTP2Server.cs": {

        463: "IsHEAD: false on the 'not an HTTP method this server knows' reply. HTTPMethod."
             "TryParse returns null only for a name that violates RFC 9110 section 9.1's "
             "token syntax - an unknown but well-formed name becomes a new HTTPMethod - and "
             "a :method pseudo-header that breaks the token rules is refused by the client "
             "stack before it reaches a socket",
        470: "target.IndexOf('?') is var mark && mark >= 0. The two readings differ only for "
             "a :path that begins with the question mark, and HTTP/2 origin-form requires it "
             "to begin with a slash",
        531: "IsHEAD: false on the 500. Reaching it needs the handler to throw, which a "
             "well-formed request cannot arrange from outside",

    },

}


SERVER_SUPERSEDED = {}



CLIENT_KILLED = {

    # The cache, driven directly rather than through the wire. CacheExpiryTests
    # records in its own comments why the scripted-server route cannot reach
    # these: the cache filters expired records on read AND sweeps them on a
    # timer, either of which produces the same answer from outside, so a mutation
    # of one is covered by the other. A cache built with an hour between sweeps
    # leaves the filter as the only thing that can reply.
    #
    # RFC 8198 §5.1 asked without a zone, the cache tries every ancestor of the
    # name; the root is an ancestor of everything and is where the whole idea
    # earns its keep, since the root zone is NSEC-signed. RFC 4034 §4.1.1: one
    # NSEC whose next name is its own owner is a zone holding nothing but its
    # apex, and that equality is the only place "wraps" is decided by one.
    # RFC 1035 §3.2.1 gives the TTL to the record rather than to whatever it is
    # stored beside, in the answer section and the authority section alike.
    #
    # All six were planted and watched to fail before being written down here.
    #
    # Line 671 is the one this entry closes on two different grounds, because the
    # ledger keys on (file, line) and cannot say "one of the two". Its
    # logical-or-to-and is what the replacement test kills: with `&&` an entry is
    # dropped only when it is expired AND carries the same owner, so a refetched
    # NSEC joins its predecessor instead of replacing it, and the wider stale gap
    # goes on denying names that now exist. Its le-to-less is a different thing
    # and no test reaches it: `e.Expiry <= now` against `<` differs only when a
    # stored expiry equals, to the tick, a Timestamp.Now read at a later call than
    # the one that computed it. Killed and unreachable, on one line. MUTATION.md
    # carries which half is which.
    "the-cache-read-by-itself": {
        "DNS/Client/Cache/DNSCache.cs": {518, 519, 671, 702, 745},
    },

    # Following an alias, and how often a client asks again. DNameFollowingTests
    # covered the DNAME half of the chase in detail; the CNAME half had nothing.
    #
    # RFC 1035 section 7.2 leaves the retry count to the implementation, so what
    # is asserted is that the setting is the thing deciding it: the loop runs
    # while attempts <= MaxRetries, which is MaxRetries + 1 questions, and the
    # count is taken at two different settings because one number is equally
    # consistent with a loop that ignores the setting and agrees at the default.
    # SERVFAIL is an answer rather than silence, so nothing at the transport
    # retransmits and every datagram counted was a decision by that loop.
    #
    # RFC 1034 section 3.6.2 keeps a CNAME alone at its name and section 4.3.2
    # has the resolver restart on the new name; RFC 2308 section 2.1 describes
    # the NXDOMAIN that carries the CNAMEs which led to the absent name, which is
    # a denial showing its working rather than an invitation to take another step.
    #
    # Every mutant on each of these lines is killed, not just one of them: 980
    # carries two and both fail. That is worth saying because this ledger keys on
    # (file, line) and would close the others silently if they were not.
    "following-an-alias-and-asking-again": {
        "DNS/Client/DNSClient.cs": {889, 890, 901, 980, 1549},
    },

    # Three places in DNSClient hand back a DNSInfo that no server sent: no
    # servers configured, a cached NSEC already proving the name absent
    # (RFC 8198), and every server query having thrown. Each writes the header
    # fields by hand, and the sweep reported all eighteen of them surviving -
    # which is the same observation as "nobody has ever read what these answers
    # say".
    #
    # RFC 1035 section 4.1.1 settles two of the six wherever the message came
    # from. AA "specifies that the responding name server is an authority for
    # the domain name in question section", RA "denotes whether recursive query
    # support is available in the name server", and no name server responded, so
    # there is nothing to be an authority and nothing to offer recursion.
    #
    # Ten of twelve at the two reachable sites. The two that stay open are the
    # RecursionDesired literals on 521 and 673: they are finding 60, the test for
    # them is red, and a KnownIssue test is excluded from the sweep and therefore
    # closes nothing. Recording them here would be recording the fix rather than
    # the measurement.
    #
    # The third site (1040-1049) is not reachable from a black-box test at all:
    # it needs every server query to throw rather than time out, and a timeout
    # produces a DNSInfo. Its six stay open with that reason.
    "answers-no-server-sent": {
        "DNS/Client/DNSClient.cs": {519, 520, 522, 527, 528, 671, 672, 674, 679, 680},
    },

    # Which DoH responses a client may read. RFC 8484 section 4.2.1 ties a DNS
    # response to the status class rather than to one code - "A successful HTTP
    # response with a 2xx status code [...] is used for any valid DNS response,
    # regardless of the DNS response code" - so one sentence carries two rules,
    # and a client can break them in opposite directions. Both edges are tested:
    # a 300 carrying a perfectly good answer must be refused on the status alone,
    # and a 203 must not be, which is why the sentence says 2xx and not 200.
    #
    # Line 834 carries three mutants and only one of them fails a test. The other
    # two do not survive either: QueryHTTPMultiTypeJSONAsync calls QueryHTTP once
    # per type, and QueryHTTP is the method holding this guard, so a guard that
    # fires on a single type recurses without bound. Both `>= 1` and `||` make a
    # one-type JSON query fan out to itself; the stack overflows and the test host
    # dies. That is recorded here rather than left open because a program that does
    # not terminate is caught by any test at all - but it is worth saying that the
    # mechanism is a dead process and not a failed assertion, because the sweep
    # reads a dead process as PARSE-ERROR and would call it unmeasured forever.
    "what-a-doh-client-may-read": {
        "DNS/Client/DNSHTTPSClient.cs": {834, 958},
    },

    # Which datagrams a UDP client may act on, and what it says when it never
    # asked. UdpClientBehaviorTests already covered the spoofing case RFC 5452
    # section 4.2 is written for; these cover the empty query, the five fields of
    # the answer it synthesizes, and how the question section is written.
    #
    # 266/267/269/274/275 are five of the six fields at the empty-name site. The
    # sixth is 268, RecursionDesired, which stays open as part of finding 60 - the
    # same literal as the three sites in DNSClient, and this file's other
    # synthesis site writes the opposite literal for the same field.
    #
    # 317 is Serialize(ms, UseCompression: false). Two types at one name make two
    # questions, so the second name is a candidate for the pointer RFC 1035
    # section 4.1.4 describes - legal on paper, and nothing sends it. Whether the
    # flag reached the question section at all was unknown until the mutant was
    # planted: it does, and the test catches it.
    #
    # 282 was on the open list and is not here: the current suite already kills it
    # (16 of 117 tests fail when `Count == 0` becomes `!= 0`, because every query
    # with explicit types turns into an ANY query). It is recorded below rather
    # than in this round, because no test was written for it - the sweep's verdict
    # simply predates the tests that catch it.
    "which-datagrams-a-udp-client-may-act-on": {
        "DNS/Client/DNSUDPClient.cs": {266, 267, 269, 274, 275, 282, 317},
    },

    # The two stream transports, whose query paths are near-identical line for
    # line. TcpFallbackAndFramingTests covered the framing - the two-octet prefix
    # of RFC 7766 section 8, reassembly, connection reuse, a server closing the
    # connection - and nothing covered the message inside the frame.
    #
    # Every rule is asserted twice, once per transport, because DNSTCPClient and
    # DNSTLSClient are separate classes with no common type to test through and the
    # sweep reports them as separate lines. A rule proved for one of two parallel
    # implementations says nothing about the other.
    #
    # RFC 1035 section 4.1.1 on RD: "this bit may be set in a query and is copied
    # into the response". It is the difference between a stub and something walking
    # the delegation chain itself, so it has to follow the caller rather than a
    # constant: 286/192 are the constructor's default, 432/245 the per-query
    # fallback behind it - reachable only by putting the property back to null,
    # since the constructor's own `?? true` means it never is otherwise.
    #
    # 423/236 are the substitution of ANY for a caller who named no types, which
    # must not happen to a caller who named some. 605/258 are Serialize's
    # UseCompression: two types at one name make two questions, so the second name
    # is a candidate for the RFC 1035 section 4.1.4 pointer - legal on paper and
    # sent by nothing.
    "inside-the-frame": {
        "DNS/Client/DNSTLSClient.cs": {286, 423, 432, 605},
        "DNS/Client/DNSTCPClient.cs": {192, 236, 245, 258},
    },

    # What the cache says about answers it made itself, and what its sweep may
    # remove. All twenty-nine of the remaining rows were planted before a line of
    # test was written; twenty died, and the nine that did not are one argument
    # rather than nine, recorded below.
    #
    # Three sites build a DNSInfo by hand and the sweep reported all eighteen of
    # their fields surviving. Two are the preseeded names. RFC 6761 section 6.3.3:
    # "Name resolution APIs and libraries SHOULD recognize localhost names as
    # special and SHOULD always return the IP loopback address for address
    # queries", and SHOULD NOT send such queries onward at all - the cache keeps
    # that promise by having the entry before anything is asked. AA is true there,
    # and it is the one field the RFC argues *for*: section 4.1.1 makes AA a claim
    # that the responder is an authority for the name, and for localhost the
    # library is, because the answer comes from the specification rather than from
    # a zone anybody could contradict. "loopback." is not a name any RFC makes
    # special and is asserted as this library's own convenience; what is pinned
    # there is that it does not drift from its neighbour, two entries with the same
    # six fields written twenty lines apart being exactly the arrangement in which
    # one quietly does. The third site is the opposite case: a record handed to the
    # cache comes back unauthoritative, because there is no responding name server
    # behind it any more.
    #
    # 777 carries two mutants and only one of them fails a test, so this entry
    # closes it on two grounds. Its logical-and-to-or is what the sweep test kills:
    # the sweep removes an entry only when the entry is past its end of life AND
    # every answer in it has expired, and the entry half alone is always the weaker
    # one, since an entry's lifetime is the smallest TTL it holds. With || a
    # mixed-TTL entry is thrown away while most of it is still good, and RFC 1035
    # section 3.2.1 gives the TTL to the record. Its less-to-less-or-equal belongs
    # to the clock family below and no test reaches it.
    #
    # 804 drops a zone from the NSEC range cache when its list has emptied; with !=
    # it drops zones whose lists have not, throwing away every range they still
    # hold, which is RFC 8198's entire saving.
    "answers-the-cache-made-itself": {
        "DNS/Client/Cache/DNSCache.cs": {129, 130, 131, 132, 140, 141,
                                          172, 173, 174, 175, 183, 184,
                                          346, 347, 348, 349, 354, 355,
                                          777, 804},
    },

    # What a client is, and what it asks for, when the caller says nothing. Every
    # default here is written twice - once as the parameter's own default on the
    # declaration, once as the fallback the body reaches for when the parameter
    # arrives as null - and the second is unreachable while the first is a non-null
    # literal. Several of these tests therefore pass null deliberately, which is the
    # only way to ask what the fallback decides.
    #
    # The reason the whole family went unwatched is in the rest of this suite: every
    # other client test spells its arguments out, `UseQueryCache: false` most of all,
    # because a test about the wire wants no cache in the way. A default nobody takes
    # is a default nobody checks.
    #
    # RFC 1035 section 3.2.3 defines QTYPE 255 as "A request for all records" and
    # section 4.1.2 gives every question exactly one QTYPE, so a caller who names no
    # type has still asked something and 255 is the only choice that does not narrow
    # it. Section 4.1.1 makes RD a request the querier makes.
    #
    # Two of these were already dead when the round began and are recorded because
    # the ledger keys on the line rather than on who killed it: 290 and 539, the
    # second by seventeen tests at once. That is what planting before writing is for.
    #
    # 311 and 320 are closed by a test that states what it needs from the machine it
    # runs on and declines to judge what that machine cannot settle - per address
    # family, because on Windows the IPv6 side is routinely unanswerable while the
    # IPv4 side is not. 322 is the one it cannot close here, and MUTATION.md carries
    # why.
    "what-a-client-is-when-nothing-is-said": {
        "DNS/Client/DNSClient.cs": {197, 230, 260, 261, 262, 290, 291, 292,
                                     301, 303, 309, 311, 320,
                                     467, 496, 539, 586},
    },

    # The third of the three places DNSClient answers without asking anyone, and the
    # one the other two hid. It is reached only when every configured server failed
    # before a response existed - not when they refused or timed out, since a
    # transport that does either returns a DNSInfo of its own and this site is
    # skipped. A server named without an address is the way in, and DNSServerConfig
    # says so itself: "what a DNS-over-HTTPS or DNS-over-TLS endpoint is before its
    # socket connects". AddressOf raises for one rather than returning null.
    #
    # RFC 1035 section 4.1.1 constrains two of the fields whatever the message's
    # provenance: AA is a statement that the responding name server is an authority,
    # RA a statement about recursion support in the name server, and no name server
    # responded. Section 4.1.2 gives every question a QNAME, which is what 511's
    # other half is about - a query with no name is not a query, and the guard that
    # refuses one shares its condition with the guard that refuses a client with no
    # servers. Only the name half can tell the two readings apart: joined the wrong
    # way round, a server-less client still reaches the same name error from the
    # third site, which is why the test that was already there could not see it.
    #
    # 1042 is not here. It is finding 60, and a KnownIssue test closes nothing.
    "answers-nobody-sent-at-all": {
        "DNS/Client/DNSClient.cs": {511, 1040, 1041, 1043, 1048, 1049},
    },

    # Several record types at one name are several queries - RFC 1035 section 4.1.2
    # gives a question one QTYPE - and the answers then have to become one. The
    # response code of that one comes from whichever query is allowed to speak for
    # the whole, and they may disagree: a name can have an A record and no TXT
    # record, or an A record while the server fails on TXT.
    #
    # Taking it from the failure produces a pair that contradicts itself on its face:
    # an answer section with a record in it under a header saying, per section 4.1.1,
    # that the name does not exist.
    "which-of-several-answers-speaks-for-the-whole": {
        "DNS/Client/DNSClient.cs": {1261},
    },

    # The EDNS options a query leaves with, once the per-server cookie has been added
    # to whatever the caller configured. CookieProtocolTests covers the cookie; what
    # nothing covered is the list it lands in.
    #
    # RFC 7873 section 5.1 has a client always offer one, so every query gains an
    # option it was not configured with and the configured ones have to survive that.
    # RFC 5001 section 2.1 - "The resolver MUST NOT include any NSID payload data in
    # the query message" - makes NSID an option code and nothing else, which is why
    # it is the one used here.
    #
    # RFC 6891 section 6.1.2 is what makes a duplicate wrong rather than untidy: "The
    # order of appearance of option tuples is not defined", so a query carrying two
    # COOKIE options has no answer to which one a responder reads. UDP clients are
    # built per query and start empty, so appending is harmless there; TCP, TLS and
    # HTTPS clients are pooled, and appending to those accumulates.
    #
    # Two configured options rather than one, which is not padding. With three codes
    # in play, "replace the option with this code" and "replace an option without it"
    # stop agreeing. With two they agree: a search for the wrong code finds the only
    # other entry, each assignment writes over the other's slot, and the list ends up
    # holding one of each in the opposite order - which section 6.1.2 makes
    # indistinguishable. That gap was found in the test before it was written down.
    "the-options-a-query-leaves-with": {
        "DNS/Client/DNSClient.cs": {1391, 1398, 1412, 1431, 1432},
    },

    # How often, and how soon, a client asks again. RFC 1035 section 7.1 is the
    # anchor: "The amount of work which a resolver will do in response to a client
    # request must be limited", by a counter decremented on every action,
    # "retransmission timeout, retransmission, etc.".
    #
    # 1489 is a retry: a response whose cookie fails RFC 7873 section 5.3 is
    # discarded, and discarding it leaves the query unanswered rather than answered
    # badly. An attacker who wins one race needs the client to give up. The test that
    # was already there forges every time and therefore cannot see whether a second
    # attempt was made at all; this one forges once.
    #
    # 1504 is a bound rather than a retry. The BADCOOKIE retry is gated by a flag
    # that latches instead of by the counter, so nothing else stops it: a peer that
    # keeps answering BADCOOKIE with a fresh cookie would be asked forever. The peer
    # in the test falls silent from the third query on, so a client that does ask
    # again ends the test by timing out rather than hanging it.
    #
    # 1535 is neither. `if (attempts <= MaxRetries)` sits fourteen lines above
    # `while (attempts <= MaxRetries)` and guards only a log line and a 200 ms pause -
    # remove its condition and the same two datagrams go out, back to back. So the
    # count test cannot reach it and a second test times the gap instead, as a lower
    # bound, which is the direction that holds under load: a scheduled delay can be
    # late but never early. The rule is worth having on its own. SERVFAIL is what a
    # name server answers when it is in trouble, and the answer to trouble is not the
    # same question arriving in the same millisecond.
    "how-often-and-how-soon-a-client-asks-again": {
        "DNS/Client/DNSClient.cs": {1489, 1504, 1535},
    },

    # Killed by not terminating, which is the one verdict in this ledger that no
    # assertion produced. `while (allDNSServerRequests.Count > 0)` against `>= 0`
    # leaves the loop calling Task.WhenAny on an empty list, which throws into the
    # generic catch eight lines above and goes round again forever. Every test that
    # queries through DNSClient hangs, so the suite does not fail - it does not
    # finish.
    #
    # Measured twice and hung twice: the original sweep recorded it among the six
    # lines that got no verdict, and the round that closed this file wedged on it for
    # twenty-one hours because the verify script had its own subprocess runner instead
    # of the harness's kill_tree. MUTATION.md carries that second measurement, which
    # is about the tooling rather than about Hermod.
    "a-race-that-does-not-end": {
        "DNS/Client/DNSClient.cs": {870},
    },

}


CLIENT_EQUIVALENT = {

    # The three shapes below repeat across both stream transports, so each reason is
    # written once and referred to twice. All three are conditions this code decides
    # twice over, which is why their mutants survive: the second decision has the
    # same effect as the first.

    "DNS/Client/DNSTLSClient.cs": {

        709: "responseLength < 12 on a framed response. RFC 7766 section 8 puts a two-octet "
             "length in front, so a response can declare exactly twelve octets and be "
             "internally consistent - RFC 1035 section 4.1.1 makes the header that long. It "
             "is still not an answer to this query: QDCOUNT is zero, and RFC 5452 section "
             "9.1 matches a response on 'Query ID, Query name, Query type, Query class', "
             "three of which are absent rather than wrong. Both readings refuse it, one at "
             "the length and one at the question, and the object that reaches the caller is "
             "the same either way. FramedTransportQueryTests asserts the outcome both "
             "produce. The same argument closes DNSHTTPSClient 1027",

        434: "EDNSOptions.Count > 0 ? EDNSOptions : null. The mutant makes the condition "
             "always true, so an empty list is passed where null was - and OPT's constructor "
             "does `this.Options = Options ?? []`, which makes the two the same object state "
             "before anything is written. Serialisation sums over Options for the RDLENGTH "
             "and writes nothing for an empty one, so the octets are identical. The OPT "
             "record itself is not at stake: it exists because UDPPayloadSize > 0, not "
             "because the option list is non-null",

        455: "!IsConnected || tcpClient is null, the pre-emptive reconnect. The mutant's && "
             "means a disconnected-but-non-null client is not reconnected before the write - "
             "and the write then throws, into a `catch (IOException)` eight lines below that "
             "reconnects and retries the whole exchange. Same answer, one failed round trip "
             "later. TcpFallbackAndFramingTests already exercises a server closing the "
             "connection and passes with the mutant planted, which is what pointed at the "
             "second recovery rather than at a missing test",

    },

    "DNS/Client/DNSTCPClient.cs": {

        473: "responseLength < 12 on a framed response - see DNSTLSClient 709, the same line "
             "in the same shape",

        247: "EDNSOptions.Count > 0 ? EDNSOptions : null - see DNSTLSClient 434",

        276: "!IsConnected || tcpClient is null - see DNSTLSClient 455. This is the file the "
             "`catch (IOException)` was read in",

    },

    "DNS/Client/DNSUDPClient.cs": {

        386: "received < 2 || ((data[0] << 8) | data[1]) != dnsQuery.TransactionId, the "
             "RFC 5452 section 4.2 pre-filter on an incoming datagram. Both of its mutants "
             "survive, and for one reason: the transaction id is checked twice and both "
             "checks react the same way. Whatever gets past this guard reaches "
             "DNSInfo.ReadResponse, which compares the id again and returns Invalid when it "
             "differs - and the caller answers `if (!response.IsValid) continue;`, which is "
             "the same `continue` this guard would have taken. Turning the || into && makes "
             "the pre-filter a no-op for any datagram of two octets or more, and moving the "
             "< to <= changes only where a two-octet datagram is dropped. Neither changes "
             "what the client does or how long it waits; the difference is one parse and one "
             "log line. Written as a property worth having rather than a redundancy: the "
             "file's own comment says the check and the reaction have to be decided "
             "together, and it decides them twice the same way. "
             "UdpDatagramAcceptanceTests asserts the behaviour both readings produce",

    },

    "DNS/Client/DNSHTTPSClient.cs": {

        1027: "body.Length < 12, the minimum-length guard on a DoH response body. RFC 1035 "
              "section 4.1.1 makes the header exactly twelve octets, so twelve is the "
              "smallest whole message and the guard is written correctly - but its boundary "
              "cannot be reached from outside, because a stricter rule sits behind it. A "
              "twelve-octet body has QDCOUNT zero, and RFC 5452 section 9.1 has a resolver "
              "match a response to 'Query ID, Query name, Query type, Query class': with no "
              "question section there is nothing to match, so the response is refused either "
              "way. The two readings differ only in which branch refuses it - Invalid rather "
              "than Failed - and those two carry the same response code, the same IsValid, "
              "the same IsTimeout and the same empty sections. The test for the rule that "
              "makes it unreachable is in DohResponseAcceptanceTests; it was first written "
              "the other way round, asserting that twelve octets are read, and being "
              "well-formed turned out not to be the same as being an answer to this question",

    },

    # Nine rows of DNSCache are one argument, not nine. Each compares a stored
    # moment against a clock read at the moment of comparison, and each mutant moves
    # the comparison across the single point where the two are equal: 463 and 729 on
    # an entry's or a range's expiry, 506 and 510 on a record's, 619 on a NODATA
    # entry's, 777 and 778 and 792 and 803 inside the periodic sweep.
    #
    # That point is not hard to reach, it is not reachable. Every stored moment here
    # is `Timestamp.Now + TTL` evaluated when the thing was stored, and every `now`
    # is `Timestamp.Now` read later, when it is looked at. For the two to be equal
    # the second reading would have to land on the same tick as the first plus the
    # TTL - a DateTimeOffset tick, a hundred nanoseconds - and nothing a test can do
    # arranges that. A zero TTL comes closest and still misses: it makes the stored
    # moment the construction instant, which is already behind any later reading, so
    # both readings of the comparison agree that it has passed.
    #
    # CacheBoundaryTests asserts what both readings produce, on both sides of each
    # comparison, which is the most a black-box test can say here: that a record
    # which may not be cached is not served, and that one with time left is.
    "DNS/Client/Cache/DNSCache.cs": {

        463: "dnsCacheEntry.EndOfLife <= Timestamp.Now, the negative entry's own lifetime",
        506: "rr.EndOfLife > now, filtering the answer section on read",
        510: "rr.EndOfLife > now, and the authority section beside it",
        619: "endOfLife > Timestamp.Now in IsNoData",
        729: "expiry <= now, skipping an NSEC range that has run out",
        778: "rr.EndOfLife <= now, the second half of the sweep's condition",
        792: "entry.Value < now, the NODATA entries the sweep removes",
        803: "e.Expiry < now, the NSEC ranges it removes",

        572: "soa.Minimum < soa.TimeToLive ? soa.Minimum : soa.TimeToLive, which is a "
             "minimum written as a conditional. RFC 2308 section 5 asks for exactly that: "
             "the negative TTL comes from 'the minimum of the MINIMUM field of the SOA "
             "record and the TTL of the SOA itself'. The mutant moves the comparison to "
             "<=, which changes only the case where the two fields are equal - and there "
             "both arms return the same value. Not a boundary that is hard to reach: a "
             "boundary on which the two programs compute the same number. The test for "
             "the rule is in CacheBoundaryTests and checks it from both sides, which is "
             "worth having and is not what closes this line",

    },

    # Twelve rows, and eight of them are conditions this file decides twice over -
    # the pattern that has now turned up in five separate places in this block. The
    # other four are values the code computes and then discards, which is the same
    # observation arriving from the other side.
    "DNS/Client/DNSClient.cs": {

        405: "DomainName.IsNullOrEmpty() || DNSInformation is null, the guard on AddToCache. "
             "All four call sites were read: the name is either the query name, which the "
             "guard at the top of Query has already proved non-empty, or a parsed record's "
             "owner name, which is never null and is '.' at its shortest since "
             "ToPresentationName returns a dot for zero labels; and the response is non-null "
             "at each site by the condition that leads there. Both operands are already "
             "false wherever this runs, so || and && do the same nothing",

        621: "FirstOrDefault(rr => rr.Type == CNAME), the record that gates the rest of a "
             "cache hit. The mutant picks the first non-CNAME answer instead, and the gate "
             "then tests that record's TTL - but every record in hand is live already. "
             "DNSCache.TryGetDNSInfo calls FilterExpiredRecords first, which drops every "
             "answer whose EndOfLife has passed and returns null when none is left, so an "
             "expired CNAME is gone before DNSClient sees it. Negative entries skip the "
             "filter, and they return from this method twenty lines earlier. Whichever "
             "record is chosen, the gate passes",

        625: "resourceRecord.EndOfLife > now, the per-record TTL check on a cache hit - see "
             "621. The check is a second reading of one the cache has already made, and the "
             "boundary between them is a Timestamp.Now read microseconds after the one that "
             "did the filtering",

        626: "cnameRecord.EndOfLife > now, the gate's own TTL check - see 621 and 625",

        696: "EDNSOptions.Count > 0 ? EDNSOptions : null. The same line in DNSTLSClient and "
             "DNSTCPClient is equivalent because [] and null serialise to the same octets. "
             "Here the reason is stronger and has nothing to do with serialisation: the query "
             "this builds never reaches the wire. QueryDNSServerAsync assigns `effectiveQuery "
             "= DNSQuery`, rebuilds it with the per-server cookie, and then never reads it - "
             "every use is of DNSQuery, and only of its Questions and its RecursionDesired. "
             "The options reach the wire by the other path, the transfer onto "
             "transportClient.EDNSOptions. Two mechanisms for one job, one of them inert",

        765: "nsecRecords.Count > 0, feeding the RFC 8198 denial cache. The block is guarded "
             "by firstResponse?.DNSSECStatus == DNSSECValidationResult.Secure, and "
             "DNSSECStatus is assigned nowhere in Hermod/DNS - it is a settable property the "
             "caller fills in after the fact, and the object read here was created inside "
             "this call. The code above it says as much: 'DNSSECStatus is normally null here "
             "and this path stays dormant. It is meant to'. Dead by design, so the mutant "
             "cannot be reached",

        1467: "the `false` handed to transportClient.Query as its ForceUpdate. Grepped across "
              "the whole client folder: DNSClient.cs:586 is the only line in it that reads "
              "ForceUpdate. Every transport declares the parameter and forwards it onward - "
              "DNSHTTPSClient passes it from QueryHTTP to QueryHTTPMultiTypeJSONAsync and "
              "back to QueryHTTP - and none of them acts on it. No cache to bypass, so "
              "nothing to ask for",

        1740: "disposedValue = true, the flag that makes Dispose idempotent. The body it "
              "guards already is: DNSCache.Dispose() is `cleanUpTimer.Dispose()` and Timer "
              "tolerates being disposed twice, transportClients is cleared on the first pass "
              "so the second finds nothing, and no exception is possible either way. A second "
              "Dispose with the flag never set does the same nothing the flag prevents",

    },

}


CLIENT_SUPERSEDED = {

    # Thirty-seven rows that the six fixes closed by moving or removing the line the
    # sweep had measured. CORE_SUPERSEDED's finding-57 entry sets the shape: a fix does
    # not let a row off, it relocates the rule, and the rule is re-measured where the fix
    # put it.
    #
    # Twenty-nine of the thirty-seven are the same parameter default in six files. The
    # argument for all of them is written once, at IDNSClient.cs:64.
    #
    # DNSClient.cs:917 is the one worth reading twice. It was recorded equivalent because
    # no chain could make the counter bind, and that was true: the chase took its next hop
    # by calling Query again, so the counter counted one call rather than the descent. The
    # unreachable mutant was the evidence for finding 61 - and then the first attempt at
    # that fix handed the budget down by value, which bounded the recursion and not the
    # work, at 2^8 = 256 queries for a chain of eight names. The test written for this row
    # is what said so, which is the whole argument for writing it.

    "DNS/Client/DNSClient.cs": {

         466: "Boolean? RecursionDesired = true, a parameter default - see IDNSClient.cs:64",
         495: "see IDNSClient.cs:64",

         521: "RecursionDesired: true at the refusal to ask - finding 60",
         673: "RecursionDesired: true at the NSEC denial - finding 60",
        1042: "RecursionDesired: true when nothing answered - finding 60",

         695: "this.RecursionDesired ?? RecursionDesired ?? true, the RD the outgoing query was "
              "built with. Hoisted to line 581, where one resolution now serves the query and "
              "the three answers this method builds itself, and killed there by "
              "ClientDefaultsTests - findings 60 and 63",

         917: "for (var hop = 0; hop < MaxCNAMEFollows; hop++). The bound is now a counter on "
              "an AliasChase shared by the whole descent, at line 1014, and killed there by a "
              "chain of distinct names longer than the limit - finding 61",

    },

    "DNS/Client/DNSUDPClient.cs": {

        229: "see IDNSClient.cs:64",
        249: "see IDNSClient.cs:64",

        268: "RecursionDesired: true for an empty query name - finding 60",
        475: "RecursionDesired: false for a socket the host refused - finding 60, and the "
             "literal that disagreed with 268's. One of the two was wrong for every call and "
             "there was no call for which both were right, which is what made the pair the "
             "clearest evidence in the finding",

        291: "this.RecursionDesired ?? RecursionDesired ?? true, hoisted to line 262 and killed "
             "there by ClientQueryConstructionTests - findings 60 and 63. It needed a test that "
             "drives the UDP client directly: through a DNSClient the transport is built fresh "
             "per query and handed an already-resolved value, so its own fallback is never "
             "reached from there",

    },

    "DNS/Client/IDNSClient.cs": {

        64:  "Boolean? RecursionDesired = true, a parameter default - finding 63. All twenty-nine "
             "of these now read `= null`, and nothing mutable is left on any of them. The change "
             "was not cosmetic: with the default at true the argument is never absent, so the "
             "client-wide field could never be consulted and `client.RecursionDesired = false` "
             "did nothing at all. Swapping the resolution order alone would not have helped. The "
             "rule these twenty-nine stood for - what a caller who says nothing gets - is "
             "re-measured where the fix put it, at the one expression each call now resolves to "
             "(DNSClient.cs:581 and DNSUDPClient.cs:262, true-to-false), and killed there",

        94:  "see 64",
        126: "see 64",
        150: "see 64",
        174: "see 64",
        195: "see 64",
        216: "see 64",
        253: "see 64",
        274: "see 64",
        295: "see 64",
        330: "see 64",
        361: "see 64",
        392: "see 64",
        432: "see 64",
        456: "see 64",
        485: "see 64",
        496: "see 64",

    },

    "DNS/Client/DNSHTTPSClient.cs": {
        752: "see IDNSClient.cs:64",
        771: "see IDNSClient.cs:64",
        795: "see IDNSClient.cs:64",
        813: "see IDNSClient.cs:64",
    },

    "DNS/Client/DNSTCPClient.cs": {
        207: "see IDNSClient.cs:64",
        227: "see IDNSClient.cs:64",
    },

    "DNS/Client/DNSTLSClient.cs": {
        394: "see IDNSClient.cs:64",
        414: "see IDNSClient.cs:64",
    },

}


# ---------------------------------------------------------------------------
#  multicast
# ---------------------------------------------------------------------------

# Line numbers are the sweep's own: Hermod 925c80d5, judged in pass 1 by the 31
# responder tests the Multicast project had then. The querier tests came after
# pass 1, and `sweep_wide_folder.py multicast --replay` planted every survivor
# again at 925c80d5 under them, and reported 72 kills.
#
# 71 of them are below. Every kill was planted a third time, on a quiet machine,
# with the failing tests named (results/multicast-replay-verified.tsv, five
# clean baselines first). 71 failed again, 70 of them exactly as many tests as
# on replay and 698 one fewer, to tests that name what the line decides. The 72nd,
# UDPMulticastDNSTransport.cs:566, failed nothing: no conformance test builds
# that transport, and the replay ran while pass 2 loaded the machine, so its one
# red test was failing for its own reasons. It stays open.
#
# Where a line keeps a survivor beside the kill, the entry names the operator,
# and on two lines the occurrence as well.

MULTICAST_KILLED = {

    # RFC 6762 §5 to §11 and §18, and RFC 6763 §4 to §6: the querier side, the
    # client and the browser, with the suite as the other host on the link. One
    # round of tests, grouped here by file; which test fails for which row is in
    # results/multicast-replay-verified.tsv.
    "querier": {

        # Whether a datagram came in over the group, which is where §6's
        # "unicast answer nobody asked for" starts.
        "DNS/Multicast/IMulticastDNSTransport.cs": {48, 49},

        # The QU bit a question goes out with, the TC bit of a query, the
        # header of a query, and reading a record's class and cache-flush bit.
        "DNS/Multicast/MulticastDNSMessage.cs": {70, 319, 325, 525, 532},

        # §6.1: an NSEC's type bitmap, read only as far as it is well-formed.
        "DNS/Multicast/MulticastDNSTypeBitmap.cs": {(105, "equality-to-inequality"),
                                                    (105, "greater-to-ge", 1), 108, 112},

        # What a querier ignores, which answer answers which question, NSEC as a
        # negative answer, the cache's expiry and its one-second grace, and the
        # query loop that waits for them.
        "DNS/Multicast/MulticastDNSClient.cs": {215, 216, 258, 440, 461, 483, 496, 540,
                                                (652, "logical-and-to-or"), 653, 654,
                                                687, 697, 698, 699, 707,
                                                731, 732, 733, 734,
                                                (777, "logical-and-to-or"),
                                                808, 816, 817, 820, 825, 875, 882, 995},

        # The browser: when it refreshes, what it lists as known, and when an
        # SRV or a TXT is news about an instance and when it is the same again.
        "DNS/Multicast/MulticastDNSBrowser.cs": {188, 375, 476, (511, "equality-to-inequality"),
                                                 661, (662, "logical-and-to-or"),
                                                 (676, "equality-to-inequality", 0),
                                                 (676, "logical-and-to-or"),
                                                 776, 778, 779, 780, 781, 782,
                                                 791, 796, 797, 800, 806, 847, 855},

    },

}

MULTICAST_EQUIVALENT = {

    "DNS/Multicast/MulticastDNSMessage.cs": {

        39: "UnicastResponseRequested = false on the record's primary constructor. Every "
            "caller passes it: the parser from the QU bit it read, the constructor at line 70 "
            "from its own parameter, and the suite's two direct callers go through that one. "
            "The default the browser's questions go out on is line 70's, and the querier "
            "tests kill it there",

    },

}

MULTICAST_SUPERSEDED = {

    # Finding 82. A cached record was listed as a known answer while it had more
    # than a second left; RFC 6762 §7.1 wants at least half its TTL. The fix
    # replaced the comparison with IsKnownAnswerAt, which no sweep has measured
    # yet. The `&&` beside it on 921 is still there, and stays open.
    "DNS/Multicast/MulticastDNSBrowser.cs": {
        (374, "greater-to-ge"): "finding 82: `ExpiresAt > now + 1 s` was the defect, and IsKnownAnswerAt replaced it",
    },

    "DNS/Multicast/MulticastDNSClient.cs": {
        (921, "greater-to-ge"): "finding 82: `ExpiresAt > now + 1 s` was the defect, and IsKnownAnswerAt replaced it",
    },

}


LEDGERS = {
    "core": (CORE_KILLED, CORE_EQUIVALENT, CORE_SUPERSEDED),
    "tsig": (TSIG_KILLED, TSIG_EQUIVALENT, TSIG_SUPERSEDED),
    "dnssec": (DNSSEC_KILLED, DNSSEC_EQUIVALENT, DNSSEC_SUPERSEDED),
    "server": (SERVER_KILLED, SERVER_EQUIVALENT, SERVER_SUPERSEDED),
    "client": (CLIENT_KILLED, CLIENT_EQUIVALENT, CLIENT_SUPERSEDED),
    "multicast": (MULTICAST_KILLED, MULTICAST_EQUIVALENT, MULTICAST_SUPERSEDED),
}



def no_duplicate_keys():
    """A dict literal with the same key twice keeps the last and says nothing.

    That is how a ledger entry disappears: written into a second block for a file
    the table already had, discarded by Python before anything could check it, and
    invisible to the stray-entry test below — which can only look at entries that
    survived. It has now happened twice. Reading this file's own source is the only
    place the two spellings are still both present.
    """

    import ast

    tree      = ast.parse(io.open(__file__, encoding="utf-8").read())
    duplicate = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            seen = set()
            for key in node.keys:
                if isinstance(key, ast.Constant):
                    if key.value in seen:
                        duplicate.append("line %d: %r" % (key.lineno, key.value))
                    seen.add(key.value)

    if duplicate:
        sys.exit("the same key appears twice in a ledger table, so Python kept only the "
                 "last of them:" + chr(10) + "  " + (chr(10) + "  ").join(duplicate))


def listed(entries, line, operator, occurrence=None):
    """A line may carry more than one mutation, and they need not share a verdict:
    where they do not, the entry names the operator as well — and where the same
    operator occurs on the line twice and the two still differ, the occurrence.

    Returns the entry that matched, the most specific first, so the caller can
    tell an entry that closed something from one that never did."""
    for entry in ((line, operator, occurrence), (line, operator), line):
        if entry in entries:
            return entry
    return None


def keyed(table, line, operator, occurrence=None):
    entry = listed(table, line, operator, occurrence)
    return (entry, table[entry]) if entry is not None else (None, None)


def main():

    if len(sys.argv) < 2 or sys.argv[1] not in BLOCKS:
        sys.exit("usage: make_closed_folder.py <%s>" % "|".join(sorted(BLOCKS)))

    no_duplicate_keys()

    name = sys.argv[1]
    if name not in LEDGERS:
        sys.exit("no ledger for block '%s' yet — add one above" % name)

    killed, equivalent, superseded = LEDGERS[name]

    classified = os.path.join(HERE, "results", "%s-classified.tsv" % name)
    out        = os.path.join(HERE, "results", "%s-closed.tsv" % name)

    if not os.path.exists(classified):
        sys.exit("no classification to read: " + classified)

    rows, used = [], set()

    for line in io.open(classified, encoding="utf-8"):

        if line.startswith("#"):
            continue

        p = line.rstrip("\n").split("\t")

        # Noise is not a gap. Neither is a line the harness never managed to
        # measure - and that one has to be skipped here rather than merely left
        # unclosed, because a ledger entry may be a bare line number and would
        # then match every operator on its line. Three of these sit on lines that
        # already carry an entry for a different operator, and would have been
        # recorded as killed by a round that never saw them.
        if (len(p) < 5
                or p[3].startswith("noise")
                or p[3].startswith("unmeasured")
                or p[3] == "host-only"):
            continue

        rel, ln, op = p[0], int(p[1]), p[2]

        # The occurrence travels with the row when the classification has one,
        # so a line whose two `>` read differently stays two rows here too.
        occ  = int(p[5]) if len(p) > 5 and p[5] != "" else None
        tail = () if occ is None else (str(occ),)

        for round_name, files in killed.items():
            entry = listed(files.get(rel, ()), ln, op, occ)
            if entry is not None:
                used.add(("killed/" + round_name, rel, entry))
                rows.append((rel, str(ln), op, "killed", round_name, "") + tail)
                break

        else:
            entry, why = keyed(equivalent.get(rel, {}), ln, op, occ)
            if why:
                used.add(("equivalent", rel, entry))
                rows.append((rel, str(ln), op, "equivalent", "", why) + tail)
            else:
                entry, why = keyed(superseded.get(rel, {}), ln, op, occ)
                if why:
                    used.add(("superseded", rel, entry))
                    rows.append((rel, str(ln), op, "superseded", "", why) + tail)

    # A table entry that matched nothing is a mistake, and a silent one: a line
    # number that no longer exists, a path spelled a shade differently, or an
    # entry lost because a dict literal had the same key twice — which Python
    # resolves by keeping the last and saying nothing. The count of what is left
    # still adds up in every one of those cases, so it has to be checked here.
    #
    # Per entry, not per line. Asking only whether something on the entry's line
    # was closed let an entry for one occurrence pass on the strength of the
    # other, which is exactly the case occurrences were added to tell apart.
    stray = []

    def shown(entry):
        return ":".join(str(x) for x in entry) if isinstance(entry, tuple) else str(entry)

    for round_name, files in killed.items():
        for rel, entries in files.items():
            for entry in entries:
                if ("killed/" + round_name, rel, entry) not in used:
                    stray.append("killed/%s %s:%s" % (round_name, rel, shown(entry)))

    for table, what in ((equivalent, "equivalent"), (superseded, "superseded")):
        for rel, entries in table.items():
            for entry in entries:
                if (what, rel, entry) not in used:
                    stray.append("%s %s:%s" % (what, rel, shown(entry)))

    if stray:
        sys.exit("these ledger entries match no gap in %s-classified.tsv:" % name
                 + chr(10) + "  " + (chr(10) + "  ").join(sorted(stray)))


    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write("# Gaps of the '%s' block that are no longer gaps, keyed to the same\n" % name)
        f.write("# revision as the verdicts.\n")
        f.write("# 'killed' means a mutation taken from this sweep's output now fails a test.\n")
        f.write("# 'equivalent' means the mutation is real and the program is the same either way.\n")
        f.write("# 'superseded' means the line the verdict belongs to was replaced by a fix.\n")
        if any(len(r) > 6 for r in rows):
            f.write("# file\tline\toperator\tstate\tround\twhy\toccurrence\n")
        else:
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
