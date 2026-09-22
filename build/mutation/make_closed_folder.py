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

DNSSEC_KILLED = {

    # RFC 4034 section 3.1.5: the validity window is a check of its own, and not
    # a property of the cryptography. Turning the or into an and makes the
    # condition unsatisfiable, so every expired signature is accepted - which
    # only a signature that still verifies can show.
    # RFC 4034 section 3.1.5: the validity window is a check of its own and not a
    # property of the cryptography. All three mutations of the answer-section
    # check fall now - the or that makes the condition unsatisfiable, and the two
    # comparisons that move a boundary by one second. The first needed a
    # signature that still verifies; the other two needed the validator to be
    # told when "now" is, which is the seam its two siblings already had.
    "windows": {
        "DNS/DNSSEC/DNSSECValidator.cs": {452},
    },

    # RFC 4034 section 4.1.3 and RFC 4035 section 5.4: the span an NSEC covers is
    # open at both ends, and the last record of a zone wraps. Four of the five;
    # the fifth is below.
    "nsec-coverage": {
        "DNS/DNSSEC/DenialOfExistence.cs": {354, 357, 358, 359},
    },

    # RFC 5155 sections 7.2 and 8.4: the same span arithmetic a second time, in
    # the hash domain. Four of its five, the same four - and 332 with them, the
    # loop in CompareHashes, which reads one octet past the end of the shorter
    # hash as soon as anything compares two of equal length.
    "nsec3-coverage": {
        "DNS/DNSSEC/DenialOfExistence.cs": {279, 284, 286, 287, 332},
    },

    # RFC 4035 section 5.3.1 and RFC 4034 section 5.1: the key tag is a checksum
    # and not an identifier, so a signature and a trust anchor each name their key
    # by tag *and* algorithm. The tag covers the DNSKEY's flags, which is what
    # makes it possible to offer a validator a key that will verify a signature
    # and is not the one the signature named.
    "key-identity": {
        "DNS/DNSSEC/DNSSECValidator.cs": {469, 871, 872, 896},
    },

    # RFC 5011 sections 2.1 and 2.4.1: which keys a resolver comes to believe in
    # when nobody touches its configuration. Three of the eight are the answer the
    # probe returns rather than the anchors it holds - a caller writes its trust
    # store out when told the set changed, so a probe that reports wrongly either
    # loses a rollover or writes a file for nothing. The match at 259 and 260 is
    # the one that needed the pending set to be visible at all: on a single probe
    # both readings return the same answer and leave the same anchors, and differ
    # only in whether a hold-down was started. 293 is the boundary of the hold-down
    # itself, and it took a seam: FirstSeen is read at one probe and compared at
    # the next, so no amount of travelling puts a test on the instant the interval
    # closes. The probe now takes the same optional Now that TSIGSigner.Verify,
    # SIG0Signer.Verify and ValidateAsync take, and one reading serves the whole
    # pass. Its line was rewritten by that change, so it was re-run against the new
    # text rather than the sweep's.
    "trust-anchors": {
        "DNS/DNSSEC/DNSSECValidator.cs": {233, 237, 238, 259, 260, 293, 297, 326},
    },

    # RFC 4035 section 5.4: "the resolver MUST authenticate the NSEC RRset". The
    # denial path repeats, on the authority section, every check the answer path
    # makes on the answer section - the validity window, the key the signature
    # names, the signature, and the chain to an anchor - and none of the four was
    # watched. 577 is the twin of 452 and fell to the seam that was added for it;
    # 590 is the twin of 871/872 and fell to the same relabelled key. 597 and 607
    # are the two early returns that keep the checks independent: inverted, each
    # reports Secure the moment its own half passes, so a signature good enough
    # for records that prove nothing, or a proof from a zone nobody vouches for,
    # comes back as an authenticated denial.
    "denial-signature": {
        "DNS/DNSSEC/DNSSECValidator.cs": {577, 590, 597, 607},
    },

    # RFC 4035 section 5.2: the step from one zone to the next. Every other test in
    # the suite anchors the fixture zone with its own DS, which is the shortest
    # chain there is - the first check inside the walk succeeds and the step is
    # never taken. Anchoring one level above the fixture forces it: fetch the
    # child's DS, verify the child's KSK against it, cross into the parent, and
    # pick the parent key its DNSKEY signature names. 960 is which signature is
    # read, 963 is what an unsigned parent means (Insecure, not Bogus), and
    # 971/972 are the key it names.
    "chain-walk": {
        "DNS/DNSSEC/DNSSECValidator.cs": {960, 963, 971, 972},
    },

    # RFC 8624 section 3.1's DNSSEC Validation column, which is the half of that
    # table the suite had never read: 1 (RSAMD5), 3 (DSA) and 6 (DSA-NSEC3-SHA1)
    # are MUST NOT, and the numbers IANA has assigned nothing to are nothing at
    # all. The default arm of the algorithm switch answering true would let an
    # attacker choose the number and have any octets accepted as a signature.
    "algorithm-numbers": {
        "DNS/DNSSEC/DNSSECValidator.cs": {1042},
    },

    # RFC 4035 section 2.2 at a delegation, and RFC 4034 section 2.1.1 above it.
    # A delegation is the one place where the records present are not the zone's
    # own: the NS RRset is authoritative in the child and the glue is a copy of
    # the child's addresses, so neither is signed here, while the DS and the
    # denial record at the delegation point are the parent's and are. Every
    # existing test of the signer ran against a zone with no delegations in it.
    # The key half is the same story one level up: the SEP bit is the whole of
    # the two roles, it decides which key signs the DNSKEY RRset (RFC 4035
    # section 5.2, because that is the key a DS covers), and every other test
    # generated its key with KeySigningKey: true and stopped there. 34 is opt-out
    # as a default rather than a choice.
    "signer": {
        "DNS/DNSSEC/DNSSECZoneSigner.cs":  {34, 173, 204, 207, 208, 238},
        "DNS/DNSSEC/DNSSECSigningKey.cs":  {64, 96},
    },

    # RFC 5155 section 8.2 and RFC 4035 section 5.4: the reasoning around a span
    # rather than the span itself. 118 and 119 are the parameter set a record has
    # to share to be part of this chain at all - a zone mid re-signing publishes
    # two, and a record of the old one is hashed by a different function. 308 is
    # the difference between "no hash" and "the empty hash", which read the second
    # way makes one record cover every name in the zone. 218 is the second half of
    # an NXDOMAIN proof, without which a covered name may still be answerable by a
    # wildcard. 212 is the walk that looks for that wildcard reaching the root: a
    # one-label query has exactly one wildcard to deny and it is the root's own,
    # so a walk one step short can never prove a TLD absent.
    "denial-proofs": {
        "DNS/DNSSEC/DenialOfExistence.cs": {118, 119, 212, 218, 308},
    },

}

DNSSEC_EQUIVALENT = {

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
             "Records.Any(...) is false, so it returns NotProven. That is the same answer "
             "as the line below, which is what runs otherwise",

        334: "Left[i] < Right[i] ? -1 : 1, which sits inside if (Left[i] != Right[i]). The "
             "two readings differ only when the two octets are equal, and the guard one "
             "line above is exactly the statement that they are not. The same shape as 401 "
             "below, in the hash domain instead of the name domain",

        401: "comparison < 0 ? -1 : 1, inside if (comparison != 0). The same argument as "
             "334: the value that separates < from <= is the one the guard above excludes",

        278: "CompareHashes(hash, owner) > 0 in FindCover, the lower end of an NSEC3's span - and "
             "the same argument as 353 below, which is the point of listing both. A name whose "
             "hash equals an owner matches that record, and VerifyNSEC3 looks for a match before "
             "it looks for a cover, at the queried name and again at every ancestor on the way "
             "up. Nothing can be handed to FindCover whose hash equals an owner in the set",

        353: "CompareCanonical(Name, owner) > 0 in Covers, the lower end of an NSEC's span. "
             "The two readings differ only when the name equals the owner, and neither caller "
             "can put that case in front of it. For the queried name, VerifyNSEC's NODATA loop "
             "returns before Covers is reached whenever any record owns it. For the wildcard, "
             "the very next clause asks whether a record owns that name and answers the same "
             "way in the same iteration, so the || is true either way. The guard at the other "
             "end of the span has no such cover and was killed by a test",

    },

}

DNSSEC_SUPERSEDED = {

    "DNS/DNSSEC/DNSSECValidator.cs": {
        378: "the ConfigureAwait of the convenience overload, whose line was rewritten when "
             "ValidateAsync gained its Now parameter. The mutation was of the kind no test can "
             "observe anyway - a test host has no synchronization context for the two readings "
             "to differ about - so nothing was lost with the line",
    },

}



LEDGERS = {
    "core": (CORE_KILLED, CORE_EQUIVALENT, CORE_SUPERSEDED),
    "tsig": (TSIG_KILLED, TSIG_EQUIVALENT, TSIG_SUPERSEDED),
    "dnssec": (DNSSEC_KILLED, DNSSEC_EQUIVALENT, DNSSEC_SUPERSEDED),
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

    # A table entry that matched nothing is a mistake, and a silent one: a line
    # number that no longer exists, a path spelled a shade differently, or an
    # entry lost because a dict literal had the same key twice — which Python
    # resolves by keeping the last and saying nothing. The count of what is left
    # still adds up in every one of those cases, so it has to be checked here.
    seen  = {(r[0], int(r[1])) for r in rows}
    stray = []

    for round_name, files in killed.items():
        for rel, entries in files.items():
            for entry in entries:
                ln = entry[0] if isinstance(entry, tuple) else entry
                if (rel, ln) not in seen:
                    stray.append("killed/%s %s:%s" % (round_name, rel, ln))

    for table, what in ((equivalent, "equivalent"), (superseded, "superseded")):
        for rel, entries in table.items():
            for entry in entries:
                ln = entry[0] if isinstance(entry, tuple) else entry
                if (rel, ln) not in seen:
                    stray.append("%s %s:%s" % (what, rel, ln))

    if stray:
        sys.exit("these ledger entries match no gap in %s-classified.tsv:" % name
                 + chr(10) + "  " + (chr(10) + "  ").join(sorted(stray)))


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
