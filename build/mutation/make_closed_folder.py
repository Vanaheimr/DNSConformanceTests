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

    # What was left of the validator once the chain, the denial path and the probe
    # were done. 357 is the manual removal API, which has to mean the same by "this
    # key" as every other lookup does - tag and algorithm together, or retiring one
    # key takes every anchor sharing its algorithm. 523 is what the anchor set is
    # taken to cover, and its two mutations fail in opposite directions: one makes
    # every name covered, the other makes a root anchor cover nothing, which is the
    # one anchor a resolver actually ships with. 407 is the pair of conditions for
    # entering the denial path at all - there has to be a proof, and there has to
    # be a question to check it against. 442 is the RRset an RRSIG covers, one
    # owner name and one type rather than every record of that type in the message.
    # 1254 is the root having no parent: read otherwise, the walk asks the root for
    # its own delegation and calls the chain unsigned rather than broken.
    "validator-rest": {
        "DNS/DNSSEC/DNSSECValidator.cs": {357, 407, 442, 523, 1254},
    },

    # The three files nothing else had reached. 289 and 323 are ExportParameters
    # (false): a DNSKEY's RDATA is a public key and every reader of one holds
    # nothing else, so asking for the private half works in the signer's own
    # process and throws in every validator. 300 is RFC 3110 section 2's boundary,
    # 255 octets of exponent being the last written the short way - reachable only
    # through a key object that holds parameters and nothing else, because the
    # platform's own RSA refuses to import one and is right to. 140 is the two
    # names that both carry a labels field of zero, the root apex and the root's
    # own wildcard, which must not be reconstructed the same way. 200 is the
    # comparison loop's bound, which overruns exactly when one RDATA is a prefix
    # of another or the two are equal. 134 is RFC 8078 section 3's rollover: two
    # ordinary CDS records are the expected case, not a contradiction.
    "encoders-and-counts": {
        "DNS/DNSSEC/DNSSECSigning.cs":   {289, 300, 323},
        "DNS/DNSSEC/DNSSECCanonical.cs": {140, 200},
        "DNS/DNSSEC/CDSAcceptance.cs":   {134},
    },

}

DNSSEC_EQUIVALENT = {

    "DNS/DNSSEC/DNSSECValidator.cs": {

        1259: "dotIndex < 0 in GetParentZone, which answers '.' for a zone of one label. "
              "The two readings differ only when the first dot is at index 0, and the "
              "string tested is Zone.TrimEnd('.') - a name that begins with a dot has an "
              "empty leading label, which DomainName cannot hold and trimming the other "
              "end cannot produce. The line above it, which the same round closed, is "
              "what stops the root before this is reached at all",

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
    },

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

}


CLIENT_EQUIVALENT = {

    "DNS/Client/Cache/DNSCache.cs": {

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

}


CLIENT_SUPERSEDED = {}


LEDGERS = {
    "core": (CORE_KILLED, CORE_EQUIVALENT, CORE_SUPERSEDED),
    "tsig": (TSIG_KILLED, TSIG_EQUIVALENT, TSIG_SUPERSEDED),
    "dnssec": (DNSSEC_KILLED, DNSSEC_EQUIVALENT, DNSSEC_SUPERSEDED),
    "server": (SERVER_KILLED, SERVER_EQUIVALENT, SERVER_SUPERSEDED),
    "client": (CLIENT_KILLED, CLIENT_EQUIVALENT, CLIENT_SUPERSEDED),
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


def listed(entries, line, operator):
    """A line may carry more than one mutation, and they need not share a verdict:
    where they do not, the entry names the operator as well."""
    return line in entries or (line, operator) in entries


def keyed(table, line, operator):
    return table.get((line, operator)) or table.get(line)


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

    rows = []

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
