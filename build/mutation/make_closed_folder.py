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

Line numbers are the sweep's own — for the core block, Hermod `38f6a355`.
"""

import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from sweep_folder import BLOCKS


# ---------------------------------------------------------------------- core
#
# Keyed to Hermod 38f6a355, the revision the second sweep of this block
# measured. The first sweep measured e592b5e7, and its files are in
# results/core-e592b5e7/. Its ledger - 114 rows killed in seven rounds, 18
# equivalent, one superseded - is in this file's history, as of c5d8a39.
#
# None of the killed rows is carried over, and none needs to be: a gap a test
# closed is killed by that test in the new sweep and never reaches the
# classification, and all 114 were - eight in pass 1, 106 in pass 2. The
# superseded row is gone with its line: finding 57 replaced the length check,
# and the comparison it wrote in its place is killed in pass 1. Six commits
# changed the block since: finding 57 (3c24141d), the compression table
# (53f20591), an NSEC's next name read from the wire (9f797748), the root's
# wildcard "*." (925c80d5, finding 76), and the timeout and runtime a failed or
# refused query reports (05855f8c, 38f6a355). Their three new mutants are all
# killed.
#
# The equivalents were read again against 38f6a355 rather than moved with their
# numbers, and so was the code they lean on. All eighteen stand; four of them
# moved, the three in DomainName.cs by 48 lines and the one in DNSInfo.cs by
# two. DNSZoneFile.cs:275 was recorded killed once, "Multicast: 1 of 220", by a
# project that cannot reach the zone-file reader - only InMemoryDNSZone's
# AddZoneFile calls it, and only the Dnssec and ResourceRecords tests call that.
# Measured again on its own, nothing fails.

CORE_KILLED = {}

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

        510:
            "the label-length refusal cannot be reached. Every label is matched by a regex "
            "first - DomainNameRegExpr, or DomainNameWithUnderscoresRegExpr where underscores "
            "are allowed - and in both a label is one character that is not a hyphen, followed "
            "by at most 61 that may be and a closing one that is not: 63 characters at the "
            "outside, so a label of 64 is refused as a format error several lines earlier. "
            "Only two names skip the regex, the root and, since finding 76, the root's "
            "wildcard '*.', and their labels are the empty one and the asterisk. RFC 1035 "
            "§2.3.4's rule is enforced; this is the second guard on it",

        513:
            "the hyphen check cannot be reached either, and for the same reason: both regexes "
            "require a character other than a hyphen at both ends of every label, so no label "
            "arriving here starts or ends with one. Whether the condition is || or && makes no "
            "difference to a condition that is never true",

        516:
            "the refusal belonging to that unreachable hyphen check",

    },

    "DNS/DNSInfo.cs": {
        321: "the QR bit is read into a local that nothing reads back — it appears twice in the "
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

CORE_SUPERSEDED = {}


# ---------------------------------------------------------------------- tsig
#
# Keyed to Hermod 38f6a355, the revision the second sweep of this block
# measured. The first sweep measured 53f20591, and its files are in
# results/tsig-53f20591/. Its ledger - 20 rows killed in three rounds, 19
# equivalent, one superseded - is in this file's history, as of 445b179.
#
# None of the killed rows is carried over, and none needs to be: a gap a test
# closed is killed by that test in the new sweep and never reaches the
# classification, and all twenty were. The superseded row is gone with its
# line. Two commits changed the folder since: the dead owner-name ternary in
# TryStripSIG0 went (cc8323d5), and BuildErrorResponse signs a BADTIME refusal
# and writes the server's clock into it (7d86efd6, finding 58).
#
# The equivalents were read again against 38f6a355 rather than moved with their
# numbers, and so was the code outside the folder they lean on. TryStripTSIG
# and TryStripSIG0 still set both outputs before their single 'return true',
# and DNSTools, whose FindLastRecordOffset and ExtractName the length and
# offset arguments rest on, has not changed since 53f20591. All nineteen
# stand. Six of them moved: five in TSIGSigner.cs, by what finding 58 added
# to BuildErrorResponse in front of them, and one in SIG0Signer.cs, by the five
# lines of comment written above the line the ternary was on.

TSIG_KILLED = {

    # RFC 8945 section 5.2.1 and 5.2.2: a BADKEY and a BADSIG response "MUST be
    # unsigned as specified in Section 5.3.2", and section 5.2.3: a BADTIME one
    # "MUST be signed by the same key as the request". BuildErrorResponse
    # decides between them with Error == BADTIME && Key is not null. Hermod's
    # server hands it the key for BADTIME and for nothing else, so there the
    # two terms never disagree and either connective gives the same refusal.
    # The method is public, and its own documentation leaves the key out only
    # "when the failure was that no such key exists" - which a MAC that does not
    # verify under a key this party holds is not. Handed the key with BADSIG or
    # BADKEY, the || reading signs the refusal.
    "badtime-alone-is-signed": {
        "DNS/TSIG/TSIGSigner.cs": {(310, "logical-and-to-or")},
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
        278: "SignedRequest.Length < 12 in BuildErrorResponse. At exactly twelve octets the "
             "mutant returns null at once and the original walks one step further into "
             "TryStripTSIG, which refuses a twelve-octet message for its own reasons and "
             "returns null too",
        284: "the !TryStripTSIG(...) term of BuildErrorResponse's chain",
        285: "the 'unsigned is null' term of it",
        448: "SignedMessage.Length < 12 in TryStripTSIG. Twelve octets is a header and nothing "
             "else: with ARCOUNT zero the walk has no records to find and with ARCOUNT set the "
             "walk reads past the end and throws into the catch. Both readings answer false",
        464: "offset < 0 after FindLastRecordOffset. That method returns -1 or a position it "
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
        433: "SignedMessage.Length < 12 in TryStripSIG0 — the same argument as TSIGSigner:448",
        446: "offset < 0 in TryStripSIG0 — the same argument as TSIGSigner:464",

        532: "Request.Length > 0 before folding the request into the signed data. SIG(0) "
             "writes the request's octets and nothing else, so an empty request writes "
             "nothing under either reading. TSIGSigner's counterpart at line 390 looks "
             "identical and is not: it writes a two-octet length first, so an empty MAC puts "
             "00 00 into the digest that a peer would not have. The same guard, one of them "
             "load-bearing and one not — which is why 390 was killed by a test and this was "
             "predicted to be and was not",
    },

}

TSIG_SUPERSEDED = {}


# -------------------------------------------------------------------- dnssec
#
# Keyed to Hermod 38f6a355, the revision the third sweep of this block
# measured. The first sweep measured 53f20591 and the second bbbf88b6; their
# files are in results/dnssec-53f20591/ and results/dnssec-bbbf88b6/. The second
# ledger - 34 rows killed in rounds, 12 equivalent, one left open - is in this
# file's history, as of 7c18a49.
#
# None of the killed rows is carried over, and none needs to be: a gap a test
# closed is killed by that test in the new sweep and never reaches the
# classification, and all 34 were, in pass 1. One commit changed the folder
# since: 925c80d5, findings 76 and 77, which let the signer sign a root zone
# with NSEC3. Its one new mutant is killed.
#
# The equivalents were read again against 38f6a355 rather than moved with their
# numbers, and so was the code they lean on. All twelve stand - nine argued by
# the first sweep, and 1178, 1422 and 370 by the second's last round. One moved:
# the signer's belt, by five lines, and its argument is worded anew for the
# suffix finding 77 gave it. DenialOfExistence.cs:370 was recorded killed once, "Client:
# 1 of 262", where the argument below says nothing can tell the readings apart.
# Measured again on its own, nothing fails.
#
# The depth limit, DNSSECValidator.cs:1101, stays open, as MUTATION.md explains.

DNSSEC_KILLED = {}

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

        386: "the belt in front of the empty-non-terminal walk, whose every escape the "
             "braces below it already catch. All three mutations of it were run and all "
             "three survived, and the argument is that they must. dot <= 0 differs only "
             "for a name that begins with a dot and goes on after it, which a DomainName "
             "cannot hold and which stripping a label cannot produce; the root's own "
             "name, the dot alone, is the apex of a root zone, which the walk skips, and "
             "the other half of the condition breaks on it anywhere else. The other two "
             "let the walk take one more step, and that step either leaves the name "
             "unchanged (no dot) or empties it (the dot is last). After it, name == Apex "
             "and a name that does not end in insideTheZone break before owners.Add is "
             "reached: insideTheZone is a dot and the apex, or since finding 77 the dot "
             "alone for the root, and neither a name without a dot nor the empty name "
             "ends in either. The set of empty non-terminals is the same under all three "
             "readings",

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

DNSSEC_SUPERSEDED = {}





# ---------------------------------------------------------------------------
#  server
# ---------------------------------------------------------------------------

# Keyed to Hermod 38f6a355, the revision the second sweep of this block
# measured. The first sweep measured cc8323d5, and its files are in
# results/server-cc8323d5/. Its ledger - 19 rows killed in six rounds, 34
# equivalent - is in this file's history, as of 8c1939e.
#
# None of the killed rows is carried over, and none needs to be: a gap a test
# closed is killed by that test in the new sweep and never reaches the
# classification. Three commits changed the folder since: CA2007's
# ConfigureAwait(false) on every await (360c8e28), timers that stop when a
# server is disposed (3f5d5961), and the fix for finding 76 (925c80d5), which
# changed a comment here and the parser elsewhere.
#
# The equivalents were read again against 38f6a355 rather than moved with their
# numbers, including the code outside the folder their arguments lean on:
# TSIGSigner changed for finding 58 and TryStripTSIG in it did not; AHTTPPDU's
# body reader changed and still answers [] where there is no body stream or a
# Content-Length of zero; HTTPMethod gained a method and TryParse did not
# change. Thirty-two stand. One expired as its entry said it would: the BADTIME
# conditional, DNSMessagePipeline 374, which the test for finding 58 now kills.
# One is new, DNSMessagePipeline 490. And one was wrong from the start -
# DNSOverHTTPSResource 312, whose argument said the HTTP layer never hands a
# null body. HTTP/1.1 never does. A POST that HTTP/2 ends with its HEADERS
# frame arrives with a null one, and there the two readings answer 400 and
# 500. It is below with the test that kills it.

SERVER_KILLED = {

    # RFC 8484 section 4.1 puts a POST's query in its body, and RFC 9113 section
    # 8.1 makes the DATA frames of an HTTP/2 message "zero or more": a POST
    # without content is one HEADERS frame that ends the stream (section 8.8.1),
    # and the HTTP/2 listener hands the resource no body rather than an empty one.
    # The first sweep's ledger called this connective equivalent because HTTP/1.1
    # never hands a null, and the empty-body test sends an empty DATA frame. With
    # no content at all, the original answers 400 and the mutant reads the length
    # of a null, which the DoH/2 handler's catch turns into a 500.
    "a-post-without-content": {
        "DNS/Server/DNSOverHTTPSResource.cs": {(312, "logical-or-to-and")},
    },

    # No RFC: what DisposeAsync (3f5d5961) does with the listener. Its guard
    # against a second call, read the wrong way round, returns at once from the
    # first, so nothing is stopped and the port the server reported stays open.
    # The test connects before and after, so the open port is shown to be the
    # server's before the test asks it to be gone.
    "a-disposed-doh2-server": {
        "DNS/Server/DNSOverHTTP2Server.cs": {407},
    },

}


SERVER_EQUIVALENT = {

    "DNS/Server/ZoneDenialOfExistence.cs": {

        # The two branches compute the same value.
        447: "Left[i] < Right[i] ? -1 : 1, under an if that has already established "
             "Left[i] != Right[i]. Less-than and less-or-equal cannot disagree where "
             "equality is excluded",
        567: "Skip >= Labels.Length ? \".\" : String.Join('.', Labels.Skip(Skip)) + \".\". "
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
        426: "label is null || label.Length == 0 in OwnerHashOf. Split always yields at "
             "least one element, so FirstOrDefault over it is never null and only the "
             "length test can fire",
        530: "qnameLabels.Length <= encloserLabels.Length in NextCloser. The closest "
             "provable encloser is an ancestor of QNAME and never QNAME itself, because "
             "a name with a matching NSEC3 is a name that exists",

        # The mutation removes a path whose answer another path supplies.
        468: "the bound of ClosestEncloser's walk. Stopping one candidate short loses "
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
        # return false with the message output null on every other path. So a null
        # output beside a true result cannot arise, which is what the second and
        # third terms of each chain test for, and the expression agrees with the
        # original on both of the two cases that can actually happen.
        349: "!TryStripTSIG(...) || unsigned is null - the second term cannot be true "
             "when the first is false",
        350: "unsigned is null || tsig is null, the same chain one term along",
        418: "!TryStripSIG0(...) || unsigned is null - the same, for the other kind",
        (419, "logical-or-to-and", 0):
             "unsigned is null || sig is null, that chain one term along. The second || "
             "on the line is the type-covered test, and a test kills it",

        471: "the twelve-octet floor of BuildNotAuthorizedResponse. It answers a request "
             "whose signature did not verify, so the request carried a TSIG or a SIG(0) "
             "and is an order of magnitude longer than the header it is measured against",

        490: "end < 0 ? null : response[..end], under FindEndOfQuestions, which sets the "
             "stream to offset 12 before it reads a question and returns either its "
             "position or -1. Zero is not among its answers, so < 0 and <= 0 agree on "
             "every one. The first sweep recorded this line killed by Dnssec, one test "
             "of 326, in a pass-2 row that had come back BUILD-FAILED and was measured "
             "again by hand; nothing in the line or in the function below it has changed "
             "since, and the second sweep finds no project that fails. The kill was the "
             "re-measurement's noise",

    },

    "DNS/Server/DNSOverHTTPSResource.cs": {

        556: "soa.Minimum < soa.TimeToLive ? soa.Minimum : soa.TimeToLive. Where the two are "
             "equal the branches return the same number, which is the only case the "
             "comparison could be changed about",

    },

    "DNS/Server/DNSOverHTTPSServer.cs": {

        313: "Request.HTTPMethod == POST, guarding the body read. The comment above it warns "
             "that asking a GET for its body would wait for octets never promised - and the "
             "constructor call below asks every request for Request.HTTPBody whatever its "
             "method, whose getter runs the same reader and keeps what it read. The guard "
             "chooses only whether the read happens here, asynchronously, or there, "
             "synchronously, and either way it happens once and for every method",

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

        495: "IsHEAD: false on the 'not an HTTP method this server knows' reply. HTTPMethod."
             "TryParse returns null only for a name that violates RFC 9110 section 9.1's "
             "token syntax - an unknown but well-formed name becomes a new HTTPMethod - and "
             "a :method pseudo-header that breaks the token rules is refused by the client "
             "stack before it reaches a socket",
        502: "target.IndexOf('?') is var mark && mark >= 0. The two readings differ only for "
             "a :path that begins with the question mark, and HTTP/2 origin-form requires it "
             "to begin with a slash",
        563: "IsHEAD: false on the 500. Reaching it needs the handler to throw, which a "
             "well-formed request cannot arrange from outside",

    },

}


SERVER_SUPERSEDED = {}



# ---------------------------------------------------------------------------
#  client
# ---------------------------------------------------------------------------

# Keyed to Hermod d906af2d, the revision the second sweep of this block measured,
# without the four files the `streams` slice measures on its own (DNSTCPClient,
# DNSTLSClient, DNSStreamPipeline, DNSKeepalivePolicy). The first sweep measured
# cc8323d5 over the whole folder, and its files are in results/client-cc8323d5/.
# Its ledger - 97 rows killed in seven rounds, 29 equivalent, 41 superseded - is
# in this file's history, as of 011e346.
#
# None of the killed rows is carried over, and none needs to be: a gap a test
# closed is killed by that test in the new pass 1 and never reaches the
# classification. Two that seemed to come back had only ever been half closed.
# DNSCache 869 and 975 each carry two mutants, and the old ledger, keyed by line,
# recorded both lines killed for the one mutant a test catches - saying in a
# comment that the other belongs to the clock family. Keyed by operator now, the
# killed halves die in pass 1 and the clock halves are below with their family.
#
# The equivalents were read again against d906af2d rather than moved with their
# numbers. Of the first sweep's twenty-nine, nine were in the stream files, which
# the `streams` slice carries. Fourteen are here on their new lines, and two on
# lines a rewrite changed: DNSCache 812 and 990, the NODATA lookup and its sweep.
# Three went with the code they sat in, DNSClient's cache-hit gate, which
# e2caece9 replaced with DNSCache.TryGetAnswer. The twentieth is not here: DoH's
# `body.Length < 12`, now 1227, whose argument named the fields the two refusals
# share and left out the two they do not - DNSInfo.Invalid reports a timeout and
# a runtime of zero where DNSInfo.Failed reports the real ones. It is open until
# that is decided (MUTATION.md, "The result: the client, measured again").

CLIENT_KILLED = {

    # Killed by not terminating, as at cc8323d5, where the line was 870. `while
    # (allDNSServerRequests.Count > 0)` against `>= 0` leaves the loop calling
    # Task.WhenAny on an empty list, which throws into the generic catch above it
    # and goes round again for ever. Every test that queries through DNSClient
    # hangs, so pass 1 stopped the judge after 606 s, and pass 2's seven projects
    # never build a DNSClient that races two servers.
    "a-race-that-does-not-end": {
        "DNS/Client/DNSClient.cs": {982},
    },

    # The first round of tests at d906af2d, planted one mutant at a time under the
    # Client project's 262 tests. Three of them are red at d906af2d on purpose and
    # carry KnownIssue, so a kill here means a test outside those three failed.
    #
    # TryGetAnswer, e2caece9's cached answer: the RRset asked for, the RRSIGs that
    # cover it, and the CNAME or DNAME chain that leads to it, each link with its
    # own signature (RFC 1034 section 3.6.2, RFC 4035 sections 3.1.1 and 4.5, RFC
    # 6672 sections 3.1 and 5.3.1). CachedAliasChainTests drives the cache
    # directly: a chain through a CNAME and through a DNAME, a DNAME beside the
    # chain that leads elsewhere, an expired link, a loop, a name with nothing
    # cached, and records put in one by one rather than as a response. Each line
    # carrying two mutants loses both.
    "an-rrset-and-the-chain-that-leads-to-it": {
        "DNS/Client/Cache/DNSCache.cs": {541, 545, 603, 612, 613, 620, 621, 624,
                                          625, 626, 631, 640},
    },

    # Query_IPAddressesToConnect with RFC 8305 section 3's Resolution Delay: the
    # other family's answer within the delay is taken, past it is not waited for,
    # and a negative first answer does not end the wait (ResolutionDelayTests,
    # with a server that answers each type on its own schedule). And the
    # ForceUpdate default of each of its three overloads, which a second lookup
    # answered from the cache reads (ConvenienceLookupCacheTests).
    "the-addresses-to-connect-to": {
        "DNS/Client/IDNSClient.cs": {474, 500, 519, 520, 568},
    },

    # Which servers a client asks and what it holds open to them. A client given
    # servers and handed null for both searches asks only those (11d9076a). A
    # server listed twice is one server, and two that differ in transport, port,
    # address or name are two (0b4fee16). CloseConnection says whether there was a
    # pooled connection to close, and closes it.
    "which-servers-and-which-connection": {
        "DNS/Client/DNSClient.cs":       {339, 350, 423, 438},
        "DNS/Client/DNSServerConfig.cs": {224, 225, 226, 227},
    },

    # DoH's own defaults and endings. A query that mentions recursion nowhere still
    # asks for it, over DoH as over the other transports.
    # A server that hangs up on the request is a failure, not a timeout. An empty
    # JSON body is a failure like any other, with no header bit and with its
    # runtime. A disposed client refuses the next query and sends nothing.
    "doh-defaults-and-endings": {
        "DNS/Client/DNSHTTPSClient.cs": {996, 1183, 1584, 1971},
    },

    # Killed once Hermod 38f6a355 is pinned. 786 is the TCP retry's catch for a
    # client disposed under it, and the mutant's || takes every cancellation the
    # caller did not cause, the deadline included. At d906af2d the retry's token
    # carried the deadline, so the condition was false for it as well. From
    # 38f6a355 the deadline is the retry's own, and
    # A_Udp_Query_Whose_Tcp_Fallback_Runs_Out_Of_Time_Says_So fails. Planted at
    # 38f6a355, where the line is 801.
    "the-retry-keeps-its-deadline": {
        "DNS/Client/DNSUDPClient.cs": {786},
    },

}


CLIENT_EQUIVALENT = {

    # Fourteen rows of DNSCache are one argument and an arithmetic identity. The
    # argument: each of the thirteen compares a stored moment against a clock read
    # at the moment of comparison, and each mutant moves the comparison across the
    # single point where the two are equal. That point is not hard to reach, it is
    # not reachable. Every stored moment here is `Timestamp.Now + TTL` evaluated
    # when the thing was stored - an entry's EndOfLife (DNSCache 238, 248, 362), a
    # record's (ADNSResourceRecord 152 and 193), a NODATA entry's (772), an NSEC
    # range's expiry (860) - and every `now` is `Timestamp.Now` read later, when it
    # is looked at. For the two to be equal the later reading would have to land on
    # the tick of the earlier one plus the TTL, a hundred nanoseconds wide, and
    # nothing a test can do arranges that. A zero TTL comes closest and still
    # misses: the stored moment is the construction instant, already behind any
    # later reading, so both readings of the comparison agree that it has passed.
    #
    # Nine are the first sweep's nine, one of which - 975's clock half, then 777 - it
    # had filed under the kill of the same line. Three are new in TryGetAnswer, and
    # one is 869's clock half, which the first sweep had filed the same way.
    # CacheBoundaryTests asserts what both readings produce on both sides of each
    # comparison, which is the most a black-box test can say here.
    "DNS/Client/Cache/DNSCache.cs": {

        483: "dnsCacheEntry.EndOfLife <= Timestamp.Now, the negative entry's own lifetime",
        573: "rr.EndOfLife <= now in TryGetAnswer, an RRset with an expired member",
        587: "rr.EndOfLife > now in TryGetAnswer, the authority section beside it",
        630: "rr.EndOfLife <= now in TryGetAnswer, an expired link in the alias chain",
        679: "rr.EndOfLife > now, filtering the answer section on read",
        683: "rr.EndOfLife > now, and the authority section beside it",
        812: "entry.EndOfLife > Timestamp.Now in TryGetNoData",
        (869, "le-to-less"):
             "e.Expiry <= now, an NSEC range that has run out when a new one for the "
             "zone arrives. The line's other mutant, || to &&, is killed",
        927: "expiry <= now, skipping an NSEC range that has run out",
        (975, "less-to-less-or-equal"):
             "entry.Value.EndOfLife < now, the first half of the sweep's condition. The "
             "line's other mutant, && to ||, is killed",
        976: "rr.EndOfLife <= now, the second half of the sweep's condition",
        990: "entry.Value.EndOfLife < now, the NODATA entries the sweep removes",
        1001: "e.Expiry < now, the NSEC ranges it removes",

        745: "soa.Minimum < soa.TimeToLive ? soa.Minimum : soa.TimeToLive, which is a "
             "minimum written as a conditional. RFC 2308 section 5 asks for exactly that: "
             "the negative answer's TTL 'is taken from the minimum of the SOA.MINIMUM "
             "field and SOA's TTL'. The mutant moves the comparison to "
             "<=, which changes only the case where the two fields are equal - and there "
             "both arms return the same value. A boundary on which the two programs "
             "compute the same number. CacheBoundaryTests checks the rule from both sides",

    },

    # The first sweep's five, each read again at its new line. Four are conditions
    # decided twice or values nobody reads; the fifth is a flag guarding a body
    # that is idempotent without it.
    "DNS/Client/DNSClient.cs": {

        456: "DomainName.IsNullOrEmpty() || DNSInformation is null, the guard on AddToCache. "
             "The four call sites (908, 937, 952, 1145) were read again: the name is either "
             "the query name, which the guard at the top of Query has already proved "
             "non-empty, or a parsed record's owner name, which is never null and is '.' at "
             "its shortest; and the response is non-null at each site by the condition that "
             "leads there. Both operands are false wherever this runs, so || and && do the "
             "same nothing",

        801: "EDNSOptions.Count > 0 ? EDNSOptions : null, building the query DNSClient hands "
             "on. [] and null make the same OPT record - OPT's constructor does `Options ?? "
             "[]` (OPT.cs 183), and the record exists because UDPPayloadSize > 0 "
             "(DNSPacket 381), not because the list is non-null. Beyond that this query's "
             "options never reach the wire: QueryDNSServerAsync assigns effectiveQuery "
             "(1468), rebuilds it with the per-server cookie (1494) and never reads it "
             "again, and the transport takes the options from its own EDNSOptions",

        876: "nsecRecords.Count > 0, feeding the RFC 8198 denial cache. The block is guarded "
             "by firstResponse?.DNSSECStatus == DNSSECValidationResult.Secure, and "
             "DNSSECStatus is assigned nowhere in Hermod/DNS - it is a settable property the "
             "caller fills in after the fact, and the object read here was created inside "
             "this call. The comment above it says so: the path 'stays dormant. It is meant "
             "to'. Dead by design, so the mutant cannot be reached",

        1559: "the `false` handed to transportClient.Query as its ForceUpdate. Grepped across "
              "the client folder at d906af2d: DNSClient.cs:682 is the only line that reads "
              "ForceUpdate. The transports declare the parameter and forward it, and none "
              "of them acts on it - they have no cache to bypass",

        1832: "disposedValue = true, the flag that makes Dispose idempotent. The body it "
              "guards already is: DNSCache.Dispose() is `cleanUpTimer.Dispose()` and a "
              "Timer tolerates being disposed twice, and transportClients is cleared on the "
              "first pass, so the second finds nothing. A second Dispose with the flag never "
              "set does the same nothing the flag prevents",

    },

    "DNS/Client/DNSUDPClient.cs": {

        429: "received < 2 || ((data[0] << 8) | data[1]) != dnsQuery.TransactionId, the "
             "RFC 5452 section 4.2 pre-filter on an incoming datagram. Both of its mutants "
             "survive, and for one reason: the transaction id is checked twice and both "
             "checks react the same way. Whatever gets past this guard reaches "
             "DNSInfo.ReadResponse, which compares the id again and returns Invalid when it "
             "differs, and the caller answers `if (!response.IsValid) continue;` (476) - the "
             "`continue` this guard would have taken. || to && makes the pre-filter a no-op "
             "for any datagram of two octets or more, and < to <= moves only where a "
             "two-octet datagram is dropped. Neither changes what the client does or how "
             "long it waits. UdpDatagramAcceptanceTests asserts what both produce",

        244: "ForceUpdate = false, a parameter default nothing reads - see DNSClient 1559",
        264: "ForceUpdate = false, a parameter default - see DNSClient 1559",

        336: "EDNSOptions.Count > 0 ? EDNSOptions : null - [] and null make the same OPT "
             "record, see DNSClient 801. Here the query does reach the wire, and the octets "
             "are the same: an empty option list adds nothing to the RDLENGTH and writes "
             "nothing",

        # First recorded killed, at cc8323d5 as line 317: two types at one name made two
        # questions, and the second name was a candidate for a pointer. Since finding 86
        # every query carries one question, so nothing is left to point at.
        360: "Serialize(ms, UseCompression: false) for the UDP query. Since finding 86 a "
             "query carries exactly one question (the guard at 314 sends several types as "
             "several queries), and the only other name in it is the OPT record's owner, "
             "the root, which DNSServiceName.Serialize writes as a single zero octet before "
             "it ever looks at the offsets. With one name there is nothing a pointer could "
             "point at, so true and false write the same octets. A TSIG or SIG(0) record is "
             "appended after serialisation, by TransactionSecurity.SignQuery, and does not "
             "see the flag",
        702: "Serialize(ms, UseCompression: false) for the TCP retry - the same query, see 360",

        699: "new NetworkStream(socket, ownsSocket: false) in the TCP retry. With true the "
             "stream closes the socket when its `using` ends, at the end of the try block; "
             "the finally right after it (886) disposes the socket anyway, and Socket.Dispose "
             "is idempotent. The socket is closed a moment earlier, by the same call",

        1329: "disposedValue = true. The flag guards one call, lifetime.Cancel(), which is "
              "idempotent on a source that is never disposed - and `lifetime` is not. A "
              "second Dispose with the flag never set cancels a cancelled source again",
        1339: "Dispose(Disposing: true) from Dispose(). The parameter is read nowhere in "
              "Dispose(Boolean); true and false run the same body",
        1345: "Dispose(Disposing: true) from DisposeAsync() - see 1339",

    },

    "DNS/Client/DNSHTTPSClient.cs": {

        875: "ForceUpdate = false, a parameter default - see DNSClient 1559",
        894: "ForceUpdate = false, a parameter default - see DNSClient 1559",
        918: "ForceUpdate = false, a parameter default - see DNSClient 1559",
        936: "ForceUpdate = false, a parameter default - see DNSClient 1559",

        998: "EDNSOptions.Count > 0 ? EDNSOptions : null - see DNSUDPClient 336, the same "
             "line in the same shape",

        # The two `true`s handed to AHTTPClient's constructor after the buffer size, in
        # each of the three constructors, are ConsumeRequestChunkedTEImmediately and
        # ConsumeResponseChunkedTEImmediately (AHTTPClient 228, 229).
        377: "true as ConsumeRequestChunkedTEImmediately. AHTTPClient puts it on the request "
             "builder (298) and so on every request this client sends - and the only reader "
             "of a PDU's flag in the client is AHTTPClient 1346, which reads it on the "
             "*response*. On a request it is copied (HTTPRequest 1765) and never acted on: "
             "it decides how an incoming chunked body is read, and the client does not read "
             "its own request",
        502: "true as ConsumeRequestChunkedTEImmediately - see 377",
        625: "true as ConsumeRequestChunkedTEImmediately - see 377",

        378: "true as ConsumeResponseChunkedTEImmediately, the client's default. It is read "
             "where SendRequest is handed null for its own parameter (AHTTPClient 886 and "
             "917), and the DoH client never hands it null: both of its sends pass `true` "
             "explicitly (1121, 1141). On a DNS query the default is not consulted",
        503: "true as ConsumeResponseChunkedTEImmediately - see 378",
        626: "true as ConsumeResponseChunkedTEImmediately - see 378",

        # The object TryParseJSONResponse builds for an empty body, written into its out
        # parameter just before it returns false. The only caller (1213) takes the
        # object only when the method returns true; on false it runs on into the binary
        # path, where an empty body is shorter than twelve octets and DNSInfo.Failed is
        # what returns. Each of these mutants changes a field of an object nobody reads.
        # The `return false` itself, 1584, is not here: with true the object is returned,
        # and a test can tell.
        1570: "IsAuthoritativeAnswer: false in an object the caller discards - see the comment above",
        1571: "IsTruncated: false in an object the caller discards",
        1572: "RecursionDesired: true in an object the caller discards",
        1573: "RecursionAvailable: false in an object the caller discards",
        1578: "IsValid: false in an object the caller discards",
        1579: "IsTimeout: false in an object the caller discards",

    },

}


# The first sweep's forty-one were rows whose lines fixes had moved or removed. At
# d906af2d each such rule was measured again where its fix put it, so there is
# nothing to supersede yet.
CLIENT_SUPERSEDED = {}


# ---------------------------------------------------------------------------
#  multicast
# ---------------------------------------------------------------------------

# Line numbers are the sweep's own: Hermod 0f595ac4, the suite's pin, judged in
# pass 1 by the Multicast project's 97 tests, the responder's and the querier's.
# The first sweep measured 925c80d5 under the responder tests alone, and its
# files are in results/multicast-925c80d5/. Its ledger, 71 rows the querier
# tests killed on replay, one equivalent and two superseded, is in this file's
# history.
#
# None of the 71 is carried over, and none needs to be. 67 die in this sweep's
# pass 1 on the same text, and three sat on a condition b4f1e201 rewrote, whose
# mutants on its new line die too. The 71st, MulticastDNSMessage.cs:319, is the
# TC default of a query, which the client no longer sends a query on; it is open
# again (MUTATION.md, "The result: multicast after findings 78 to 85"). The two
# superseded rows' lines are gone.
#
# The first round of tests is for the fifteen rows the second sweep found in
# b4f1e201's new code, the one that moved, and the one that came back
# (MUTATION.md, "Fourteen of fifteen, and the one finding 93 took away"). Planted
# one at a time at c5b4ce08, the suite's pin since finding 93, under the
# Multicast project's 117 tests: fourteen fail a test, and 965 survives, because
# finding 93's fix took away the only input that reached it.

MULTICAST_KILLED = {

    # The edges of b4f1e201's new code, and two old defaults it left behind.
    #
    # §7.2's split into packets, through the client's public SendQueryAsync with
    # known answers the test builds: a packet filled to the octet (678), the
    # question counted in the first packet (671's ==), a known answer too large for
    # any packet alone after the question (683's ==, 699), and two of them in a row
    # (683's >). §7.1, at exactly half the TTL (183) and for a type the query does
    # not ask for (1048), on the test's clock. §7.3, a truncated query (412) and a
    # question that is QU or of another type, class or name (415 to 417). RFC 6763
    # §5, an SRV record expiring that the instance does not use (648), and §6.1, a
    # TXT record that empties or fills (933). And MulticastDNSMessage.cs:319, the
    # TC default of a query, which only a probe still goes out on: §18.5.
    #
    # Each was planted on its own, and each failed one to four of the new tests
    # and nothing else.
    "what-the-new-code-left-at-its-edges": {
        "DNS/Multicast/MulticastDNSClient.cs": {
            (671, "equality-to-inequality"), (678, "le-to-less"), 683,
            (699, "greater-to-ge"), (183, "ge-to-greater"), (1048, "logical-and-to-or"),
        },
        "DNS/Multicast/MulticastDNSBrowser.cs": {
            (412, "logical-or-to-and"), (415, "logical-and-to-or"), (416, "logical-and-to-or"),
            (417, "logical-and-to-or"), (648, "logical-and-to-or"), (933, "logical-and-to-or"),
        },
        "DNS/Multicast/MulticastDNSMessage.cs": {
            (319, "false-to-true"),
        },
    },

    # The responder, which every test in the block's first measurement was about and
    # which still had 37 rows open. Line numbers are the sweep's; at c5b4ce08 those
    # after 965 sit two lines further down, and those after 1510 five.
    #
    # §8.1: from the first probe on, a record of any type at the name is a conflict,
    # and before it a record of another type is nothing (199, 598, 599, 1030). A
    # publication of shared records only is not probed (573, both). §10.1: one
    # withdrawn while probing says no goodbye (690). §8.4: an update is announced as
    # often as the first announcement (720, 753), and a shared record taken out gets
    # a goodbye first (746). §5.5: a unicast query from off the link is ignored
    # (790); §18.3 and §18.11: so is one with a nonzero opcode or rcode (791). §6: an
    # answer from a unique record set goes out at once (843), one from a shared set
    # waits 20 to 120 ms (868), and a record may be multicast again at one second,
    # answer and additional alike (1139, 1145). A question of class ANY is answered,
    # and draws an NSEC for a missing type (848, 889). A negative answer to a QM
    # question is multicast (912). §17: answers too many for one packet are split
    # (1353's ||), and a record too large for one goes alone, with no empty packet
    # beside it (1353's second and third >).
    #
    # Each was planted on its own at c5b4ce08, under the Multicast project's 138
    # tests, and each failed one of the new ones.
    "the-responder-asked-and-on-its-own": {
        "DNS/Multicast/MulticastDNSResponder.cs": {
            (199, "inequality-to-equality"), (573, "logical-and-to-or"), (598, "equality-to-inequality"),
            (599, "true-to-false"), (690, "logical-and-to-or"), (720, "equality-to-inequality"),
            (746, "logical-or-to-and"), (753, "less-to-less-or-equal"), (790, "logical-or-to-and"),
            (791, "logical-or-to-and"), (843, "false-to-true"), (848, "inequality-to-equality", 1),
            (868, "true-to-false"), (889, "inequality-to-equality", 1), (912, "false-to-true"),
            (1030, "equality-to-inequality"), (1139, "ge-to-greater"), (1145, "ge-to-greater"),
            (1353, "logical-or-to-and"), (1353, "greater-to-ge", 1), (1353, "greater-to-ge", 2),
        },
    },

    # The third round, for the client's and the browser's rows: 29 of
    # MulticastDNSClient.cs and 28 of MulticastDNSBrowser.cs, open at both
    # measurements. The client's lines have not moved since the sweep; the
    # browser's after 1035 sit four lines further down at cdc03cc6.
    #
    # The client. A lookup reports an answer as authoritative, whole and not
    # recursive, whatever the header said (§18.4 to §18.7), from the link and from
    # the cache (1113 to 1116, 1121). The cache answers a lookup for what it holds,
    # through either overload, and ForceUpdate asks anyway (65, 439, 468, the three
    # of 489, 493). A record is no answer once its TTL has run out (763), and one
    # that expires on a sweep is reported expired once (999, 1000). §10.2 flushes
    # what was received more than one second ago, not exactly one (904), and lists
    # no known answer with the cache-flush bit (1050). A goodbye for a record never
    # heard costs nothing else in its packet (914's &&), and the additional records
    # of a lookup hold neither a goodbye nor the answer (956).
    #
    # The browser. A record heard again is no update (552, 958); a new address is
    # one (952, 961). An address reaches its instance while another is unresolved
    # (586), and one that expires changes only the instances on its host (664,
    # 678). An instance that was never reported goes without a report (635). A
    # record heard again for an instance known in full draws no query (574, 983),
    # and an instance without an address or a TXT record is asked about again when
    # its pointer is heard (981, 982, 983). The query at 80 % is not repeated on
    # every tick (741). An instance whose pointer was cleared from the cache goes
    # after 75 minutes, with a report and without a query (752's second ==, 760).
    #
    # Each was planted on its own at cdc03cc6, under the Multicast project's 166
    # tests, and each failed one of the new ones.
    "the-querier-and-the-browser": {
        "DNS/Multicast/MulticastDNSClient.cs": {
            (65, "true-to-false"), (439, "false-to-true"), (468, "false-to-true"),
            (489, "logical-and-to-or"), (489, "inequality-to-equality"), (489, "true-to-false"),
            (493, "logical-or-to-and"), (763, "greater-to-ge"), (904, "greater-to-ge"),
            (914, "logical-and-to-or"), (956, "logical-and-to-or"), (999, "le-to-less"),
            (1000, "le-to-less"), (1050, "false-to-true"), (1113, "true-to-false"),
            (1114, "false-to-true"), (1115, "false-to-true"), (1116, "false-to-true"),
            (1121, "true-to-false"),
        },
        "DNS/Multicast/MulticastDNSBrowser.cs": {
            (552, "false-to-true"), (574, "logical-and-to-or"), (586, "logical-and-to-or"),
            (635, "logical-and-to-or"), (664, "logical-and-to-or"), (678, "logical-and-to-or"),
            (741, "true-to-false"), (752, "equality-to-inequality", 1), (760, "greater-to-ge"),
            (952, "true-to-false"), (958, "false-to-true"), (961, "true-to-false"),
            (981, "logical-or-to-and"), (982, "logical-or-to-and"), (983, "equality-to-inequality"),
        },
    },

    # The fourth round, for the message and the files around it: 27 rows of
    # MulticastDNSMessage.cs, 8 of MulticastDNS.cs, 7 of MulticastDNSTypeBitmap.cs,
    # 7 of InMemoryMulticastDNSNetwork.cs, 6 of HybridDNSClient.cs and 5 of
    # MulticastDNSRecordExtensions.cs. MulticastDNS.cs's lines after 196 sit one
    # line further down at 3050ab75; the others have not moved.
    #
    # The message. TryParse refuses what RFC 1035 §4.1 cannot walk: a packet
    # shorter than a header, a name that runs past the end or ends with the packet,
    # a label length of 0x40, more than 128 labels, a question without type and
    # class, a record that ends in its fixed fields or its RDATA, and a broken
    # authority section with nothing after it (390, 425, 431, 468, 471, 522, 528,
    # 539, 709, 712, 740, 748). A header alone is a message (387), and AA and RD
    # are read where they are (480, 482). §18.14: compressed names are decoded
    # (733). A question matches records of its class (88). A probe's records
    # carry no cache-flush bit (114, §10.2), and an announcement no TC bit (351,
    # §18.5).
    #
    # Around it. §3 and §12: the hybrid client sends local. and the link-local
    # reverse domains to Multicast DNS and nothing else (MulticastDNS.cs's 200 to
    # 205), and leaves a cached name to the cache through either overload
    # (HybridDNSClient.cs's 122, 140). RFC 4034 §4.1.2: an NSEC bitmap has no
    # trailing zero octet (MulticastDNSTypeBitmap.cs's 65 ==). §8.2.1: the longer
    # list wins the tie-break (152), and rdata is compared uncompressed (42).
    # §10.1: a unique record taken out with its whole RRSet gets a goodbye (86,
    # 87).
    #
    # Each was planted on its own at 3050ab75, under the Multicast project's 200
    # tests, and each failed one of the new ones.
    "the-message-and-what-surrounds-it": {
        "DNS/Multicast/MulticastDNSMessage.cs": {
            (88, "equality-to-inequality"), (114, "false-to-true"), (351, "false-to-true"),
            (387, "less-to-less-or-equal"), (390, "false-to-true"), (425, "false-to-true"),
            (431, "false-to-true"), (468, "logical-or-to-and"), (471, "false-to-true"),
            (480, "inequality-to-equality"), (482, "inequality-to-equality"), (522, "false-to-true"),
            (528, "false-to-true"), (539, "false-to-true"), (709, "ge-to-greater"),
            (712, "false-to-true"), (733, "true-to-false"), (740, "false-to-true"),
            (748, "false-to-true"),
        },
        "DNS/Multicast/MulticastDNS.cs": {
            (200, "logical-or-to-and"), (200, "equality-to-inequality"), (201, "logical-or-to-and"),
            (202, "logical-or-to-and"), (203, "logical-or-to-and"), (204, "logical-or-to-and"),
            (205, "logical-or-to-and"),
        },
        "DNS/Multicast/MulticastDNSTypeBitmap.cs": {
            (65, "equality-to-inequality"),
        },
        "DNS/Multicast/HybridDNSClient.cs": {
            (122, "false-to-true"), (140, "false-to-true"),
        },
        "DNS/Multicast/MulticastDNSRecordExtensions.cs": {
            (42, "false-to-true"), (86, "logical-and-to-or"), (87, "logical-and-to-or"),
            (152, "less-to-less-or-equal"),
        },
    },

    # The fifth round is for the sixty rows of UDPMulticastDNSTransport.cs, which no
    # test reached: every other multicast test runs over the in-memory link. The
    # tests are a class of their own, MulticastSocketConformanceTests, over the
    # host's sockets on a port of their own, in the Multicast category.
    #
    # Starting at all: no interface found (199), IsRunning asked before a start
    # (136), the interface list read wrongly (539, 545, 548, 563, 665). §3: a
    # transport at its defaults hears 224.0.0.251 (40) and FF02::FB (45, 258, 287,
    # 566) on every interface that is up, and every datagram it reads (467). §15
    # and §15.1: two transports bind one port (215, 218, 262) and hear each
    # other's multicasts (66), sent without naming an interface (399). §20: a
    # transport of one family starts (304) and sends (421, both). §6.7: a legacy
    # query is answered by unicast from the socket of its family (384). §14 and
    # §6.2: a response goes out on the interface the query came in on alone (400,
    # 401, 402 with !=), and a transport named to one interface takes that one
    # (549). §11: a multicast is on the link whatever its source (609), and a
    # unicast is when its source shares a prefix with the receiving interface:
    # 127.0.0.1, 127.1.0.1 and ::1 on the loopback interface (614, 635, 643's >=,
    # 646, 647, 650, 651).
    #
    # Each was planted on its own at a12603df, under the fourteen cases of that
    # class (the in-memory tests never build the transport, and the sweep had all
    # sixty survive them), and each failed one of them.
    # Three of the transport's thirteen needed a source off the link, which one host
    # cannot send from. The WSL virtual machine is a second host behind a switch of its
    # own, and its root writes any source address into a packet through a raw socket.
    # From 198.51.100.7, on no subnet of any interface: a multicast is on the link
    # regardless of its source (625 sends it through the subnet check), and a unicast
    # is not (636 says yes to the other family's subnets, 648 to a differing octet).
    # Each was planted on its own at d906af2d under the socket class's seventeen
    # cases, and each failed one of the two new ones.
    "a-second-host": {
        "DNS/Multicast/UDPMulticastDNSTransport.cs": {
            625, 636, 648,
        },
    },

    "the-transport-on-the-hosts-sockets": {
        "DNS/Multicast/UDPMulticastDNSTransport.cs": {
            40, 45, 66, 136, 199, 215, 218, 258, 262, 287, 304, 384, 399,
            (400, "equality-to-inequality"), (401, "equality-to-inequality"), 402,
            (421, "logical-and-to-or"), 467, 539, 545, 548, 549, 563, 566, 609, 614,
            635, (643, "greater-to-ge"), 646, 647, 650, 651, 665,
        },
    },

}

MULTICAST_EQUIVALENT = {

    "DNS/Multicast/MulticastDNSMessage.cs": {

        39: "UnicastResponseRequested = false on the record's primary constructor. Every "
            "caller passes it: the parser from the QU bit it read, the constructor at line 70 "
            "from its own parameter, and the suite's two direct callers go through that one. "
            "The default the browser's questions go out on is line 70's, and the querier "
            "tests kill it there",

        (412, "false-to-true"): "new MemoryStream(buffer, false) in TryParse, writable with "
            "true. Nothing writes to the stream: DNSTools.ExtractName and "
            "DNSInfo.ReadResourceRecord only read names and records off it, and the class "
            "bits are cleared in the buffer through its span, not through the stream",

        (615, "false-to-true"): "question.Name.Serialize(stream, offset, false, null) in "
            "Serialize, compressing with true. Serialize then makes a dictionary of its own "
            "(Offsets ??= []) for each question, and compresses a name only where the whole "
            "name is in it already; one name never finds itself there before it is written, "
            "so each question is written in full, as the original writes it",

    },

    "DNS/Multicast/MulticastDNSClient.cs": {

        (170, "greater-to-ge"): "ExpiresAt > Now ? ExpiresAt - Now : TimeSpan.Zero in "
            "RemainingTimeToLive, with >=. They differ where ExpiresAt equals Now, and the "
            "mutant's ExpiresAt - Now is then TimeSpan.Zero, the original's answer",

        (182, "greater-to-ge"): "remaining > TimeSpan.Zero in IsKnownAnswerAt, with >=. "
            "RemainingTimeToLive is never negative, so the mutant's conjunct is always true. "
            "The original's is true for every entry that gets here: each caller reads the "
            "clock and then takes its entries from CachedRecords, which reads it again and "
            "keeps only those with ExpiresAt after that second reading. That is the client's "
            "KnownAnswers at 1042 and the browser's QueryNowAsync and ObserveQuery, which "
            "read it at 367 and 421. An entry with no time left at the first reading would "
            "need a clock that ran backward between two readings of one synchronous call",

        532: "remaining < interval ? remaining : interval, with <=. The two differ only where "
             "remaining and interval are equal, and then both pick the same TimeSpan; the "
             "comparison at 560 sees the same wait. The line it replaced, 490 at 925c80d5, "
             "was the same and was left open there",

        (546, "greater-to-ge"): "grace > Options.ResponseGracePeriod before a lookup's grace "
            "period, with >=. They differ where the two are equal, and the mutant then sets "
            "grace to the value it already has",

        (628, "le-to-less"): "question.ExpiresAt <= now as SendQueryAsync prunes the recent "
            "unicast questions, with <. The mutant keeps a question that expires at that very "
            "moment. Nothing reads the list but IsExpectedUnicastResponse, which prunes it "
            "again with <= at its own reading of the clock, no earlier than this one, before "
            "it looks; the catch at 641 removes only the call's own registrations",

        (671, "true-to-false"): "the `true` SizeOf hands Query as Truncated, while it measures "
            "how long a packet would be. Serialize turns Truncated into one bit of the header's "
            "third octet (MulticastDNSMessage.cs:596) and into nothing else: the header is "
            "twelve octets either way, and the sections are written alike. The packets that "
            "go out are built at 702, with a TC bit of their own",

        (691, "greater-to-ge"): "SizeOf(current) > Options.MaxQuerySize, with >=. A known answer "
            "that fills a packet to the octet is closed into a group of its own at once, where "
            "the original keeps it as the open group. Nothing can join it: every record adds "
            "octets, so the next one overflows that group at 678, and the original closes it "
            "there, as it was; if none follows, 699 closes it. The groups come out the same. "
            "The method run over abstract sizes, every list of up to five known answers drawn "
            "from nine sizes under three limits and three question sizes, 597,870 cases, gave "
            "no difference here. It gave one for each of the five survivors on 671 to 699 that "
            "stay open: 671's ==, 678, both of 683 and 699",

        (905, "greater-to-ge"): "entry.ExpiresAt > now + 1 s in §10.2's flush, with >=. They "
            "differ where an entry expires exactly one second from now, and the mutant then "
            "sets its expiry to that same time",

        (914, "greater-to-ge"): "existing.ExpiresAt > now + GoodbyeDelay in §10.1's goodbye, "
            "with >=. They differ where the record expires exactly then, and the mutant sets "
            "that same time",

    },

    "DNS/Multicast/MulticastDNSBrowser.cs": {

        (94, "logical-and-to-or"): "HostName is not null && Port.HasValue in IsResolved, with "
            "||. Both are set in one place, Apply's SRV case at 921 and 922, and always "
            "together; nothing unsets either. So they are null together or set together, "
            "and && and || agree",

        (490, "greater-to-ge"): "interval > MaxBrowseInterval as the browse interval doubles, "
            "with >=. They differ where the two are equal, and the mutant then sets the "
            "interval to the value it has",

        (570, "logical-and-to-or", 1): "changed && SRV && HostName is not null before the "
            "cached addresses of the instance's host are applied, with the second && made ||: "
            "(changed && SRV) || HostName is not null. The mutant applies them also when an "
            "unchanged SRV record or a TXT record arrives for an instance with a host, and "
            "discards what Apply returns, as the original does. Every cached address of the "
            "host is among the instance's by then: an address that arrives is applied to every "
            "instance on its host (586), a host is given its cached addresses the moment an SRV "
            "record names it (571, 650, and ApplyCached at 837), and an address leaves the "
            "instance only as it leaves the cache (664, 678). Apply adds nothing",

        (738, "greater-to-ge"): "lifetime > TimeSpan.Zero before the query at 80 %, with >=. "
            "They differ where the lifetime is zero, and the conjunct after it is then "
            "remaining < 0 * (1 - RefreshFraction), which no RemainingTimeToLive satisfies: "
            "it is never negative",

        442: "maxDelay > minDelay ? minDelay + a random share of the difference : minDelay, "
             "with >=. They differ where the two are equal, and the share is then of a zero "
             "difference, FromTicks((Int64) (x * 0)): minDelay either way. The draw the mutant "
             "adds comes from Random.Shared, which is not seeded, so nothing that draws after "
             "it can tell",

        446: "if (delay > TimeSpan.Zero) around the first query's delay, with >=. They differ "
             "at a delay of zero, which the mutant awaits. Task.Delay(TimeSpan, TimeProvider, "
             "CancellationToken) answers a cancelled token with a cancelled task and a delay "
             "of zero with a completed one, and creates no timer for either. The first ends "
             "the loop at the catch's return, where the original ends it at the while's test "
             "of the same token. The second goes on at once, as the original does",

        (965, "false-to-true"): "Apply's return false for a record none of its cases match, "
            "with true, since finding 93's fix (c5b4ce08). Every caller that reads the result "
            "hands Apply records chosen by the comparison its case then makes again: an SRV or "
            "TXT record by the instance key at 559, the preferred SRV record from the cache by "
            "the instance's name at 565 and 648, an address by SameName at 587. The key and "
            "SameName fold as DNSServiceName.Equals does now, so each record meets its case. "
            "The callers that hand it anything else, ApplyCached at 832 and 835 and the address "
            "loops at 571 and 848, discard the result. At 0f595ac4 the key folded É to é, and "
            "two instance names that differ in its case reached the line; the planted mutant "
            "survives the Multicast project's 117 tests at c5b4ce08",

    },

    # Line numbers are the sweep's, as above; at c5b4ce08 those after 965 sit two
    # lines further down, and those after 1510 five.
    "DNS/Multicast/MulticastDNSResponder.cs": {

        (750, "greater-to-ge"): "if (goodbyeRecords.Length > 0) before an update's goodbye, with "
            ">=. With nothing to say goodbye to, the mutant calls SendGoodbyeAsync with an empty "
            "list, and Split yields no packet for it: the loop has nothing to run over, and the "
            "last yield asks packetAnswers.Count > 0 || packetAdditionals.Count > 0, which two "
            "empty lists answer with no. Nothing awaits on the way, so no cancellation can tell "
            "either",

        (986, "less-to-less-or-equal"): "ours.CompareLexicographically(theirs) < 0 in §8.2's tie-break, "
            "with <=. They differ where the two sets compare equal: as many records, and pairwise "
            "the same class, type and rdata. Both sets are of one name, the group's, so each of "
            "theirs is then identical to one of ours, and the check just above it has already "
            "gone on to the next name for exactly that case",

        (1164, "greater-to-ge"): "Record.TimeToLive > ttlOverride.Value, the legacy unicast cap "
            "of §6.7, with >=. They differ where a record's TTL equals the cap, ten seconds, and "
            "then the override the mutant sets is the TTL the record has. The wire carries the "
            "same ten either way",

        1377: "packetAnswers.Count > 0 || packetAdditionals.Count > 0, Split's last yield, with "
              ">= in either place. The mutant yields where both lists are empty, and they are "
              "empty there only when Split was handed two empty lists. No caller hands it any: "
              "PublishAsync and UpdateAsync refuse a publication without records, the query path "
              "returns before it when it has no answers and again when the rate limit leaves "
              "none, and an update's goodbye is sent only when it has records (750)",

        1503: "if (Max <= Min) return Min in RandomDelay, with <. They differ where the two are "
              "equal, and the mutant then returns Min plus a random share of a zero difference: "
              "Min either way. The draw comes from Random.Shared, which is not seeded",

    },

    "DNS/Multicast/MulticastDNSTypeBitmap.cs": {

        (65, "greater-to-ge"): "length > 0 && bitmap[length - 1] == 0 as Encode trims a "
            "window, with >=. A window is made only for a type in it, so its bitmap holds a "
            "set bit, and the loop stops at that bit before length reaches zero, where the "
            "mutant would read bitmap[-1]",

        (97, "le-to-less"): "offset + 2 <= TypeBitMaps.Length in Decode, with <. They differ "
            "where exactly two octets are left. The original reads them as a window and a "
            "length and stops at the next test, since no bitmap follows: a length of zero "
            "breaks, and any other runs past the end. The mutant stops before. Neither adds "
            "a type",

        (110, "less-to-less-or-equal"): "bit < 8 in Decode, with <=. The ninth pass tests "
            "0x80 >> 8, which is zero, and adds nothing",

    },

    "DNS/Multicast/MulticastDNSRecordExtensions.cs": {

        (67, "le-to-less"): "offset <= wire.Length in RData, with <. They differ where the "
            "RDATA is empty, and wire.AsMemory(offset) is then the empty memory the mutant "
            "returns",

    },

    "DNS/Multicast/UDPMulticastDNSTransport.cs": {

        222: "SetSocketOption(IP, PacketInformation, true) on the IPv4 socket, with false. "
             "Socket.ReceiveMessageFromAsync turns the option on itself before it receives: "
             "planted, the transport still reported the interface and the group as the "
             "destination of every multicast, and both come from the packet information",

        266: "SetSocketOption(IPv6, PacketInformation, true) on the IPv6 socket, with false. "
             "The same as line 222, for IPv6",

        271: "info.IPv6Addresses.Count > 0 && info.IPv6Index.HasValue, choosing the "
             "interfaces to join FF02::FB on: with || and with >= 0. SelectInterfaces asks "
             "for an interface's IPv6 index only when it has IPv6 addresses (line 583), so "
             "HasValue implies the count, and the count without the index would need "
             "GetIPv6Properties to fail for an interface that has IPv6 addresses",

        (400, "logical-or-to-and"): "info.Index == InterfaceIndex.Value || in SendAsync's "
             "filter, with &&, which binds before the || around it: (Index == X && "
             "IPv4Index == X) || IPv6Index == X. Index is IPv4Index where there is one and "
             "IPv6Index where not, so Index == X makes one of the two sides true, and either "
             "side makes the original true",

        (401, "logical-or-to-and"): "info.IPv4Index == InterfaceIndex.Value || in SendAsync's "
             "filter, with &&: Index == X || (IPv4Index == X && IPv6Index == X). It differs "
             "only for an interface whose IPv4 index is not its IPv6 index, and the "
             "operating systems .NET runs on give an interface one index for both",

        (421, "greater-to-ge"): "info.IPv6Addresses.Count > 0 before multicasting over IPv6 "
             "on an interface, with >= 0. The index that follows it has a value only where "
             "the count is above zero, as at line 271",

        580: "ipv4Addresses.Count > 0 before asking for the IPv4 index, with >= 0. An "
             "interface without IPv4 addresses then gets an IPv4 index, which is its IPv6 "
             "index, and nothing uses it: there are no IPv4 addresses to join or send "
             "from, and its subnets, all IPv6, never match an IPv4 source",

        583: "ipv6Addresses.Count > 0 before asking for the IPv6 index, with >= 0. The same "
             "as line 580, for an interface without IPv6 addresses",

        (643, "logical-or-to-and"): "PrefixLength < 0 || PrefixLength > length in bits, "
             "with &&, which is never true. The guard is for prefix lengths outside the "
             "address, and no interface reports one",

        (643, "less-to-less-or-equal"): "PrefixLength < 0, with <= 0. It differs for a "
             "prefix of length zero, which no interface address has",

        644: "return false for a prefix length outside the address, with true. No "
             "interface reports one, as at line 643",

    },

}

MULTICAST_SUPERSEDED = {}


# The 'svcparam' slice: SVCB.cs, HTTPS.cs and SVCParameterPresentation.cs swept
# a third time at 4edc4c98, the tree Hermod's master has as f11dad26, after
# Vanaheimr/Hermod#209 taught the reader to refuse a key written twice and a
# ServiceMode record that is not self-consistent (finding 90). Line numbers are
# that revision's. The sweep before, at cbdd1bb1, kept its files in
# results/svcparam-cbdd1bb1/ and its ledger in this file's history. The tests its
# round wrote were in place for this sweep's pass 1, and what they killed then
# they killed again.
#
# 16 survived pass 1 and every project of pass 2, and 4 of them are not code.
# Three more never finished, the same three as at cbdd1bb1 (MUTATION.md, "Three
# that never come back"). Of the 12 real gaps, nine are the equivalents found at
# cbdd1bb1 on their new lines, one is the port's leading zeros the RFC leaves
# open, and two are new: the ServiceMode argument #209 added. One test, in
# SvcParamFailureVectorTests; the replay that planted the 19 again under it is
# results/svcparam-replay.tsv.

SVCPARAM_KILLED = {

    "aliasmode": {

        # RFC 9460 §2.4.2: an AliasMode record's SvcParams are ignored, so the
        # self-consistency checks of §2.4.3 are ServiceMode's alone - but a key
        # is still written once (§2.1). With priority >= 0 the reader holds
        # AliasMode to ServiceMode's rules. SvcParamFailureVectorTests.
        "DNS/ResourceRecords/SVCB.cs":  {299},
        "DNS/ResourceRecords/HTTPS.cs": {209},

    },

}

SVCPARAM_EQUIVALENT = {

    "DNS/ResourceRecords/SVCParameterPresentation.cs": {

        164: "keyName.Length > 3 in the test for the unknown-key form. A name of three "
             "characters reaches the line only if TryParseKey knows it, and the one it knows "
             "is \"ech\", which does not start with \"key\"; \"key\" itself has no number and "
             "was passed over above. So the next clause is false either way",

        243: "Position >= Text.Length inside a quoted value, which is a quote that is never "
             "closed. The mutant reads one character past the end instead, and the "
             "IndexOutOfRangeException ends the read where the FormatException did: "
             "SVCB.TryParseFromJSON and HTTPS.TryParseFromJSON catch every exception, and "
             "the zone-file reader reaches them through those. The record is refused either "
             "way and the error it reports is the same",

        299: "Position + 1 >= Text.Length, a backslash at the end of the text. As at 243: "
             "the mutant indexes past the end, and the exception it throws is caught where "
             "the FormatException was",

        (307, "ge-to-greater"): "Position + 3 >= Text.Length, a decimal escape cut short by "
            "the end of the text. As at 243: the mutant indexes past the end, and the "
            "exception it throws is caught where the FormatException was",

        (307, "logical-or-to-and"): "the first || of the three-digit test. The mutant drops "
            "the check of the second digit wherever the third is in reach, and the next "
            "statement is Int32.Parse over all three - which throws a FormatException of its "
            "own for a digit, a non-digit and a digit, since the first and the last are "
            "checked. The blank after two digits, which Int32.Parse would forgive, is the "
            "third character's case and line 309's",

        (510, "ge-to-greater"): "i + 1 >= Value.Length, a backslash at the end of a list. "
            "As at 243: the mutant indexes past the end, and the exception it throws is "
            "caught where the FormatException was",

        498: "!HasValue || Value.Length == 0 in ValueList. The mutant lets an \"=\" with "
             "nothing after it through, and the loop below then finds no item at all and "
             "throws at its own end: \"the list has an empty item\". The same refusal from "
             "a line further down",

    },

    "DNS/ResourceRecords/SVCB.cs": {

        376: "Value.Length > 0 in ToString(), which is the debugging text and not the "
             "presentation format. The mutant calls EscapeValue on an empty value, which "
             "returns an empty string - what the other branch wrote",

    },

    "DNS/ResourceRecords/HTTPS.cs": {

        286: "Value.Length > 0 in ToString() - see SVCB.cs 376",

    },

}

SVCPARAM_SUPERSEDED = {}


# The 'streams' slice: DNSTCPClient.cs, DNSTLSClient.cs, DNSStreamPipeline.cs and
# DNSKeepalivePolicy.cs swept a third time at 0f595ac4, after Vanaheimr/Hermod#219
# had a stream reader close its own connection rather than the one in the field.
# Line numbers are that revision's. The two sweeps before kept their files in
# results/streams-cbdd1bb1/ and results/streams-4edc4c98/ and their ledgers in
# this file's history. The client block's own ledger is keyed to d906af2d, where
# these four files are as they were at 0f595ac4, and leaves them to this one.
#
# No round of tests: every real gap pass 2 left is equivalent, or reachable only
# through a race, or open because the RFCs are (MUTATION.md, "The result: the
# stream clients after #219").

STREAMS_KILLED = {}

STREAMS_EQUIVALENT = {

    "DNS/Client/DNSTLSClient.cs": {

        436: "ForceUpdate = false, a parameter default nothing reads. The DomainName overload "
             "forwards it to the DNSServiceName overload, and that one to its own recursion "
             "for more than one type, and nowhere else. The client ledger's DNSClient 1467 "
             "grepped the folder for a reader at cc8323d5 and found one, in DNSClient itself; "
             "the pipeline left that as it was",
        456: "ForceUpdate = false - see DNSTLSClient 436",

        497: "EDNSOptions.Count > 0 ? EDNSOptions : null, with >= in its place: the empty list "
             "goes where null went, and OPT's constructor does `this.Options = Options ?? []`, "
             "so the record is the same object state before anything is written. The client "
             "ledger's DNSTLSClient 434 is the same line at cc8323d5",

        815: "the `false` handed to Serialize as UseCompression. Since finding 86 a query "
             "carries one question, so its name is the first in the message and has nothing "
             "behind it to point to. The only other name is the OPT record's owner, the root, "
             "which OPT.Serialize writes as a single zero octet without asking. A TSIG or "
             "SIG(0) record is appended to the octets afterwards. There is nothing for "
             "compression to find",

        (898, "logical-or-to-and"): "StreamOf's `Connection != Volatile.Read(ref connection) || "
            "current is null || current.Number != Connection`, with either || made &&. "
            "`A && B || C` hands a query its connection's stream after the counter has moved "
            "past that connection, while it is still the one recorded as opened: between a "
            "reconnect's count and its record, or after a connect that failed. A connect is "
            "counted only when the field holds no TcpClient or one that is not connected, "
            "ReconnectAsync starts by closing what the field holds, and the field is emptied "
            "only by a close of the TcpClient in it. A close under the stream lock is over "
            "before the count, which needs the lock; the reader's runs without it but holding "
            "the read turn, and StreamOf is called only under that turn. So that connection's "
            "TcpClient is closed or not connected, Connected is false, and StreamOf returns "
            "null as the original does. `A || B && C` hands a query of the current number "
            "the recorded connection's stream even when the record is another number's, and "
            "a query registers on a number only after that number's connect has recorded it. "
            "Both throw where the original returns null when the record is empty and the "
            "number is current. Nothing reads with such a number: here a failed connect "
            "returns before its query registers, and in DNSTCPClient GetStream() throws first, "
            "on a TcpClient that is disposed or null",

    },

    "DNS/Client/DNSTCPClient.cs": {

        248: "ForceUpdate = false - see DNSTLSClient 436",
        268: "ForceUpdate = false - see DNSTLSClient 436",
        309: "EDNSOptions.Count > 0 ? EDNSOptions : null - see DNSTLSClient 497",
        320: "the `false` handed to Serialize as UseCompression - see DNSTLSClient 815",

        (621, "logical-or-to-and"): "StreamOf's guard - see DNSTLSClient 898",

    },

    "DNS/Client/DNSKeepalivePolicy.cs": {

        140: "IsIdle ?? (() => true), the default for a caller that passes no idleness test. "
             "Every constructor of both callers passes one, () => pipeline.Outstanding == 0: "
             "DNSTCPClient 235, DNSTLSClient 330 and 419, and nothing else constructs the "
             "policy",

    },

    "DNS/Client/DNSStreamPipeline.cs": {

        184: "if (pending.Count == 0) drained = new ..., the start of a busy period. With != "
             "the first Register of a period leaves the completed TaskCompletionSource of the "
             "last one in place, and every later Register of the period puts a fresh one "
             "there. Drained is waited on by a query that finds its connection marked by a "
             "TIMEOUT 0. If nothing is outstanding then, the original's signal is complete "
             "too. If something is, it was outstanding beside the answer that carried the 0, "
             "so the period has had two registrations and the fresh one is in place. Nothing "
             "registers while it is waited on: the waiter holds the stream lock, and Register "
             "happens only under it",

        (236, "greater-to-ge"): "ended.Count >= 0 && pending.Count == 0 adds one case, End "
            "ending nothing with nothing pending. drained is complete then: only a Register "
            "that finds nothing pending replaces it with an incomplete one, and every way back "
            "to nothing pending completes it. TrySetResult on it does nothing",

        (282, "logical-and-to-or"): "first == Exchange.Outcome.Task && !turn.IsCompleted, "
            "with || in its place. The two disagree only when the answer has arrived and the "
            "turn has been granted too. The original then takes the turn, finds the outcome "
            "complete, releases the turn and returns it; the mutant hands the granted turn to "
            "the continuation, which releases it because it ran to completion, and returns "
            "the outcome. One release of one turn either way, and the same answer",

        (420, "logical-and-to-or"): "exchange.Connection == Connection && exchange.TransactionId "
            "== transactionId, with || in its place: the message is offered to more "
            "candidates. One with another transaction ID refuses it at the first line of "
            "DNSInfo.ReadResponse, and a DoT candidate whose TSIG does not verify returns null "
            "rather than throwing, so neither is failed by it. One on another connection with "
            "the same ID is the same query asked again only after the old exchange was "
            "withdrawn, or two queries whose random IDs and questions coincide - and then the "
            "answer is an answer to the question either one asked",

    },

}

STREAMS_SUPERSEDED = {}


LEDGERS = {
    "core": (CORE_KILLED, CORE_EQUIVALENT, CORE_SUPERSEDED),
    "tsig": (TSIG_KILLED, TSIG_EQUIVALENT, TSIG_SUPERSEDED),
    "dnssec": (DNSSEC_KILLED, DNSSEC_EQUIVALENT, DNSSEC_SUPERSEDED),
    "server": (SERVER_KILLED, SERVER_EQUIVALENT, SERVER_SUPERSEDED),
    "client": (CLIENT_KILLED, CLIENT_EQUIVALENT, CLIENT_SUPERSEDED),
    "multicast": (MULTICAST_KILLED, MULTICAST_EQUIVALENT, MULTICAST_SUPERSEDED),
    "svcparam": (SVCPARAM_KILLED, SVCPARAM_EQUIVALENT, SVCPARAM_SUPERSEDED),
    "streams": (STREAMS_KILLED, STREAMS_EQUIVALENT, STREAMS_SUPERSEDED),
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
