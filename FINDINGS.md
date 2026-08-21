# Conformance Findings — Hermod DNS

What this suite caught. Forty-one RFC deviations in the Hermod DNS stack, each
with chapter and verse, the mechanism, the fix, and the test that now pins it.

Every one of them is fixed and every one is defended by a test — so this reads
as a record, not a backlog. It stays because the tests do not explain
themselves: several of them look arbitrary until you know which bug they were
shaped to catch, and that reasoning lives here.

One section is **current documentation rather than record**:
[Interpretations](#interpretations), which holds the places where the RFCs are
honestly ambiguous and the suite had to choose a reading. Coverage boundaries —
what is queued, what is out of scope — are not here at all; they live in
[README § RFC coverage](README.md#rfc-coverage).

| # | Finding | Severity | RFC | Status |
|---|---------|----------|-----|--------|
| 1 | QNAME case not preserved | Low (SHOULD) | 1035 §2.3.3 | ✅ fixed |
| 2 | TXT/SPF: only the first character-string parsed | **High** | 1035 §3.3.14 | ✅ fixed |
| 3 | URI: target emitted as DNS labels | **High** | 7553 §4.5 | ✅ fixed |
| 4 | SVCB/HTTPS: RDATA parsing overruns RDLENGTH | **High** | 1035 §4.1.3, 9460 | ✅ fixed |
| 5 | Client aborts on the first non-matching UDP response | **High** | 5452 §4.2 | ✅ fixed |
| 6 | Server omits OPT; no BADVERS | Medium | 6891 §6.1.1, §6.1.3 | ✅ fixed |
| 7 | Server never truncates oversized UDP responses | **High** | 1035 §4.2.1 | ✅ fixed |
| 8 | Unparseable requests silently dropped | Low | 1035 §4.1.1 | ✅ fixed |
| 9 | Name compression: suffix table never matched | Medium | 1035 §4.1.4 | ✅ fixed |
| 10 | Wildcard-expanded RRsets fail DNSSEC validation | **High** | 4035 §5.3.2 | ✅ fixed |
| 11 | Wildcard owner names cannot be represented | Medium | 4592 §2.1.1 | ✅ fixed |
| 12 | Revoked KSK is not removed from the trust anchors | **High** | 5011 §2.1 | ✅ fixed |
| 13 | Server ignores the CNAME rule | **High** | 1034 §4.3.2 | ✅ fixed |
| 14 | NODATA answers are never served from the cache | Medium | 2308 §5 | ✅ fixed |
| 15 | Negative TTL ignores the SOA MINIMUM | Medium | 2308 §4 | ✅ fixed |
| 16 | Any request record other than A or OPT answered FORMERR | Medium | 3597 §2 | ✅ fixed |
| 17 | Aggressive NSEC caching: unreachable, unvalidated, and mis-ordered | **High** | 8198 §3, 4034 §6.1 | ✅ fixed |
| 18 | Negative answers carried no SOA, so none of them could be cached | **High** | 2308 §3 | ✅ fixed |
| 19 | The TCP fallback dropped the query's transaction signature | **High** | 8945 §5.3, 2931 §3.1 | ✅ fixed |
| 20 | A DS query at a zone cut was answered with a referral | Medium | 4035 §3.1.4.1 | ✅ fixed |
| 21 | An unknown RR type in a response cost every record behind it | **High** | 3597 §2 | ✅ fixed |
| 22 | Names in the RDATA of post-1035 types were compressed | Medium | 3597 §4 | ✅ fixed |
| 23 | A bare decimal in a zone-file line was read as a class, not a TTL | Medium | 3597 §5 | ✅ fixed |
| 24 | The resolver's DNAME substitution matched characters, not labels | **High** | 6672 §2.2, §2.3 | ✅ fixed |
| 25 | One spoofed response replaced the client's DNS Cookie for good | **High** | 7873 §5.3 | ✅ fixed |
| 26 | A delegation the validator cannot follow was reported forged | **High** | 6840 §5.2 | ✅ fixed |
| 27 | Malformed key material threw out of validation | Medium | 4035 §5.3.3, 4033 §5 | ✅ fixed |
| 28 | The LOC parser discarded the size and both precisions | Medium | 1876 §3 | ✅ fixed |
| 29 | An unknown LOC version was rendered as if it were version 0 | Low | 1876 §2 | ✅ fixed |
| 30 | A padded query was answered unpadded | Medium | 7830 §4 | ✅ fixed |
| 31 | The DoT client announced no EDNS(0), so nothing could be padded | Medium | 8467 §4.1, 7830 §4 | ✅ fixed |
| 32 | The DoH client did the same, on a transport RFC 8467 covers without naming | Medium | 8467 §1, §4.1, 8484 §9 | ✅ fixed |
| 33 | Every DoH query carried a random ID, so no two were the same request | Low | 8484 §4.1 | ✅ fixed |
| 34 | The same literal `0` a third time, on plain TCP, where it cost the DO bit | **High** | 3225 §3, 6891 §6.2.2 | ✅ fixed |
| 35 | A DoT connection the server asked the client to stop using stayed in use | Low (SHOULD) | 7828 §3.2.2 | ✅ fixed |
| 36 | The same rule, on the transport it had just become reachable on | Low (SHOULD) | 7828 §3, §3.2.2 | ✅ fixed |
| 37 | A session outlived every timeout a server advertised | Low (SHOULD) | 7828 §3.2.2, §3 | ✅ fixed |
| 38 | A TTL with the sign bit set became a cache entry that never expired | Medium | 2181 §8 | ✅ fixed |
| 39 | The reserved CLASS wore the name of a different one | Low | 6895 §3.2, 2136 §2.4 | ✅ fixed |
| 40 | The one flag a refusal kept echoing | Low | 1035 §4.1.1, 6895 §2 | ✅ fixed |
| 41 | An authoritative "does not exist" for names it serves no zone for | **High** | 1035 §4.1.1, 8020, 1034 §4.3.2 | ✅ fixed |

The Status column is uniform by design. It says nothing today, and that is the
point — it is where a future finding lands as **open**, with its test left red
as the tracking signal ([PLAN.md §9](PLAN.md)).

The last sixteen were found *after* the first eight were already fixed, by tests
written to deepen areas the suite had reported green. That is the argument for
the queued list in the README: untested working code is where the next one will
be. Findings 21, 23, 25 and 27 make a sharper version of the same point — all
four sit in code that was already there and already believed to work. Findings
26 and 27 add another: both were found while implementing something else, by
a test written for a different purpose that happened to walk past them. So were
34 and 35, noticed while 30 to 32 were being fixed — and 34 is the sharpest
version of it yet, because two rounds had already edited the very line that
causes it, on two other transports, without either one looking at the third.

---

## A recurring theme: RDLENGTH is authoritative

Findings 2, 3 and 4 are the same mistake in three places. RFC 1035 §4.1.3 makes
RDLENGTH the definitive extent of a record's RDATA. Three parsers ignored it and
instead read until the *stream* ended, which works only when the record happens
to be last in the message — true in a unit test, false in real traffic, where an
OPT record almost always trails.

The symptom is not a mangled record. It is a mangled *message*: the over-reading
parser consumes the next record's bytes, and everything after it is lost. That
is why a live `cloudflare.com/HTTPS` query returned SERVFAIL rather than a
partly-wrong answer.

All three now derive their bounds from RDLENGTH, and the tests assert the
stream lands exactly on the RDATA end.

A fourth instance surfaced later, and it had never been reachable. Every record
type also carried a bare `X(Stream)` constructor that `DNSInfo`'s reflection
registry could not reach — it looks up `(DomainName, Stream)` and
`(DNSServiceName, Stream)`, and nothing else. Their shared base left RDLENGTH
unread and the subclasses disagreed about whose job that was: `TXT`, `DNSKEY`
and `SVCB` read it, `A`, `MX` and `SOA` did not, and would have taken the two
length octets for RDATA. Dead code deviates from nothing, so this gets no number
of its own — but it sat in all forty record files beside the correct
constructor, which is what the next record type would have been modelled on.
All forty are gone, and `RecordTypeRegistryTests` goes red if one comes back.

---

# The findings in detail

Ordered by how they were found rather than by number, so the ones that share a
root cause stay together.

## 1 — Query names were lowercased before reaching the wire

*RFC 1035 §2.3.3:* "When you receive a domain name or label, you should preserve
its case." *RFC 4343* then makes clear that preserving case must not make case
significant: the two names are still the same name.

`DomainName`, `DNSServiceName` and `DNSServiceInstanceName` all lowercased in
`TryParse`, so `MiXeD.CaSe.ExAmPlE` left as `mixed.case.example`. Harmless to
interoperability, but it makes dns-0x20 query randomization — a cheap anti-
spoofing measure that depends on the case surviving the round trip — impossible
to build on top of these types.

The reason this sat open is that it could not be fixed by deleting the
`ToLowerInvariant()` calls alone. Case was being normalized at the *front door*,
which silently papered over three things behind it:

- **`Equals` was `Ordinal` while `GetHashCode` was `OrdinalIgnoreCase`.** A
  broken contract, unreachable only because every instance was already
  lowercased. Preserving case makes it live immediately, and
  `InMemoryDNSZone` keys a `ConcurrentDictionary` on `DNSServiceName` — so a
  zone lookup would have started missing records that were definitely there.
- **`CompareTo` used `String.CompareTo`**, which is culture-sensitive.
- **`DNSCache.noDataCache`** is keyed by `"<name>|<type>"` with an ordinal
  comparer, so `EXAMPLE.com` and `example.com` would have become separate
  entries.

**Fix.** Parsing preserves case; `Equals`, `CompareTo` and the string operators
are all `OrdinalIgnoreCase`, matching the hash that was always there; the
negative cache uses a case-insensitive comparer. `DNSSECValidator` needed no
change — `SerializeCanonicalName` already lowercases explicitly, as RFC 4034
§6.2 requires for the canonical form.

Verified by `Case_Is_Preserved_On_The_Wire` (now byte-exact rather than
case-insensitive), `Names_Differing_Only_In_Case_Are_The_Same_Name`,
`Service_Names_Differing_Only_In_Case_Are_The_Same_Name`,
`Client_Puts_The_Query_Name_On_The_Wire_With_Its_Case`,
`Response_Echoing_A_Lowercased_Question_Is_Accepted` and
`Question_Case_Is_Echoed_Unchanged`. All five fail against the previous revision.

Note that the *answer's* owner name still comes back in the zone's spelling
rather than the query's. That is conformant — the case the zone data entered
with is what is preserved — and it coincides with the query's spelling once
`DNSServerOptions.UseCompression` is on, because the owner then becomes a
pointer at the QNAME.

## 9 — Name compression: the suffix table could never match

*RFC 1035 §4.1.4.*

Found while making compression case-insensitive for finding 1. Three separate
defects, which happened to cancel out:

1. **Suffix keys were stored without a trailing dot** (`example.com`) while every
   lookup used the full name *with* one (`www.example.com.`). No suffix entry
   could ever be hit, so suffix compression — the whole point of §4.1.4 — was
   dead code. Only exact repeats of a complete name compressed.
2. **The offsets were wrong anyway.** Every suffix was recorded at
   `CurrentOffset + 1 + labelLength`, measured from the start of the *name*
   rather than from a running position. That is correct for the first label and
   wrong for every one after it.
3. **`Array.IndexOf(labels, label)` resolved a repeated label to its first
   occurrence**, so in `a.b.a.example.` the suffix after the second `a` was
   computed as though it followed the first.

Fixing (1) alone would have activated (2) and (3) and started emitting pointers
into the middle of labels — corrupt messages, on the wire, for every name with a
shared suffix.

**Fix.** All three at once: a running offset advanced label by label, suffixes
built by position rather than by value, and keys case-folded so they match the
lookups. A 14-bit guard was added while there — RFC 1035 §4.1.4 gives a pointer
only 14 bits of offset, so a name at or beyond 16384 must not be recorded at
all, or the pointer silently truncates.

Verified by `Shared_Suffix_Is_Actually_Compressed` (asserts a pointer is
genuinely emitted, not merely that the message still decodes),
`Name_With_Repeated_Labels_Compresses_To_Correct_Offsets` and
`Mixed_Case_Name_Compresses_Against_Its_Lowercase_Twin` — plus the 38 WSL
interop tests, where dig, kdig, drill and BIND all still parse what Hermod
emits.

## 2 — TXT/SPF: only the first character-string was parsed

*RFC 1035 §3.3.14:* "TXT-DATA: One or more `<character-string>`s."
*RFC 7208 §3.3:* they are concatenated.

TXT's stream constructor called `ExtractCharacterString` once, so any TXT above
255 bytes was truncated on read — precisely the population (DKIM keys, long SPF
policies, DMARC) that exceeds 255 bytes. Serialization was already correct, so
Hermod could emit a record it could not read back.

`SPF` was worse: it decoded its text with `DNSTools.ExtractName`, the *domain
name* parser, so any `.` in a policy became a label boundary.

**Fix.** Added `DNSTools.ExtractCharacterStrings(Stream, RDLength)`, which reads
exactly RDLENGTH octets as a sequence of character-strings. `TXT` and `SPF` both
use it and concatenate the result.

Verified by `TXT_MultiString_Rdata_Is_Fully_Parsed`,
`TXT_MultiString_Parsing_Leaves_Stream_At_Rdata_End`, and — against real BIND
output — `Hermod_Handles_A_MultiString_Txt_From_Bind`.

## 3 — URI: target was emitted as DNS labels

*RFC 7553 §4.5:* the Target is "the remaining octets of the RDATA" — not a
domain name, not a character-string.

Both directions went through the domain-name codec, so
`https://www.example.com/path` was written as length-prefixed labels
(`0b https://www 07 example 08 com/path 00`). Every other implementation reads
garbage from that.

**Fix.** `SerializeRRData` now writes the target as raw ASCII octets after
Priority and Weight, and a new `ReadTarget` helper reads `RDLENGTH - 4` octets
back. Name compression is explicitly not applied.

Verified by `URI_Target_Is_The_Remaining_Rdata_Octets`.

## 4 — SVCB/HTTPS: SvcParam loop ran past its own RDATA

*RFC 1035 §4.1.3, RFC 9460 §2.2.*

Both records read RDLENGTH and then ignored it, looping `while (true)` over
SvcParams until the stream ended. With an OPT record trailing the answer — the
normal case — the OPT bytes were consumed as bogus SvcParams and the outer
record loop then threw, so the client surfaced SERVFAIL with zero answers for a
response `dig` renders without complaint.

**Fix.** One shared `SVCB.ParseSVCParameters(Stream, remainingRDataLength)`,
bounded by RDLENGTH and used by all four SVCB/HTTPS stream constructors. It
rejects a SvcParam that claims more bytes than remain, and trailing bytes after
the last param. The two constructors that never read RDLENGTH at all now do.

Verified by `Https_Record_Followed_By_Another_Record_Does_Not_Overrun` (offline)
and `Https_Svcb_Records_Resolve_In_The_Wild` (live against 1.1.1.1).

## 5 — A single spoofed datagram killed the pending query

*RFC 5452 §4.2:* a resolver "MUST ignore" responses that do not match the
outstanding query.

Hermod correctly *rejected* a response with a wrong transaction ID, but the
client did a single `ReceiveAsync`, so the first datagram to arrive ended the
query whether or not it was accepted. The genuine reply arriving microseconds
later was never read.

That inverts the requirement. Instead of shrugging off forged packets, any
off-path attacker who lands one datagram achieves a denial of service — cheaper
and more reliable than winning a cache-poisoning race.

**Fix.** `DNSUDPClient` now loops on receive, comparing the transaction ID in
the first two octets and discarding non-matching datagrams until a match arrives
or the existing timeout expires.

Verified by `Spoofed_Response_Does_Not_Kill_The_Pending_Query`.

## 6 — Server omitted OPT and never answered BADVERS

*RFC 6891 §6.1.1:* responders "MUST include an OPT record in their respective
responses." *§6.1.3:* an unsupported EDNS VERSION "MUST" be answered with BADVERS.

`AuthoritativeDNSRequestHandler` built every response with an empty additional
section, so a requestor could not tell whether the server spoke EDNS, could not
learn its payload size, and `dig +edns=1` got NOERROR where BADVERS was required.

**Fix.** Added `DNSResponseCodes.BadVersion = 16` and a `BuildResponseOPT`
helper that attaches an OPT to every response *when the query carried one*,
advertising the server's own payload size (default 1232, per DNS Flag Day 2020).
Options are deliberately not echoed — unknown options must be ignored (§6.1.2),
and reflecting them would make the server an amplifier.

Verified by `Response_To_Edns_Query_Contains_An_Opt_Record`,
`Unknown_Edns_Version_Yields_BADVERS`, and `Unknown_Edns_Options_Are_Not_Echoed`.

## 7 — Server never truncated oversized UDP responses

*RFC 1035 §4.2.1:* "Longer messages are truncated and the TC bit is set."
*RFC 6891 §6.2.5:* never exceed the requestor's advertised buffer.

A 600-byte TXT produced a **673-byte UDP response with TC=0**, both without EDNS
and with EDNS advertising 512. Such datagrams fragment or get dropped by
middleboxes, and because TC was clear the client was never told to retry over
TCP — the answer simply vanished.

**Fix.** `DNSServer.SerializeForUDP` computes the limit as 512 without EDNS, or
`min(advertised, MaxUDPResponseSize)` with it, then sheds answer records from the
end until the message fits and sets TC=1. The OPT record is retained so the
response stays EDNS-conformant.

Verified by `Large_Answer_Without_Edns_Is_Truncated_Or_Fits_512_Bytes` and
`Answer_Respects_The_Advertised_Edns_Payload_Size`.

## 8 — Unparseable requests were dropped instead of answered FORMERR

*RFC 1035 §4.1.1:* RCODE 1 means "the name server was unable to interpret the
query."

A request truncated mid-name produced no reply at all. A client cannot
distinguish "malformed request" from "server down", and retries blindly.

**Fix.** The UDP parse is now its own `try`; on failure the server builds a
minimal FORMERR from the first two octets and replies. Two guards keep this
safe: datagrams under 12 bytes are ignored, and anything with QR already set is
never answered, so two servers cannot ping-pong error replies.

Verified by `Truncated_Request_Does_Not_Break_The_Server`.

## 10 — Wildcard-expanded RRsets failed validation

*RFC 4035 §5.3.2:* if the RRSIG's Labels field is less than the number of labels
in the RRset's owner name, the RRset was synthesized from a wildcard, and the
validator must rebuild the signed data using `*.` followed by the rightmost
`Labels` labels — not the expanded name.

`BuildSignedData` always used `rr.DomainName.FullName`. For an answer at
`anything.wild.example.` covered by the signature over `*.wild.example.`, it
hashed a name no signer ever signed, and the result was **Bogus**.

Wildcards are not an edge case — they are how much of the DNS serves catch-all
subdomains, and a validating client would have rejected all of it. The failure
was fail-closed, so it denied rather than admitted, but it denied
correctly-signed data.

**Fix.** A `SignedOwnerName(OwnerName, Labels)` helper applies §5.3.2 and is used
for every RR's canonical owner name. Three cases are handled explicitly: the root
name (which splits into one empty label and must not be treated as a real one), a
wildcard directly at the root (`Labels = 0` → `*.`), and a Labels count that
*exceeds* the owner's — where the name is left alone so the signature check fails
on its own rather than having a name invented for it.

This needed no change to `DomainName`, because the canonical form is built from
strings by `SerializeCanonicalName`. Finding 11 therefore does not block it.

Verified by `Wildcard_Expanded_Rrset_Validates` against a signature made by
BIND's `dnssec-signzone`, with the non-wildcard path still covered by the ten
existing RSA and ECDSA RRSIG tests.

## 12 — A revoked KSK was never removed from the trust anchors

*RFC 5011 §2.1:* once a resolver sees a trust-anchor key republished with the
REVOKE bit set, it must stop treating that key as a trust anchor.

`ProbeForTrustAnchorUpdatesAsync` matched the revoked key against the stored
anchors by key tag. But the key tag is a checksum over the whole DNSKEY RDATA,
**including the Flags field** — so setting REVOKE changes it. The tag computed
from the revoked key could never equal the tag stored while the key was live, the
`RemoveAll` matched nothing, and the revocation was silently ignored.

This one failed *open*: a key the zone operator had explicitly announced as
compromised stayed trusted indefinitely — the exact scenario RFC 5011's
revocation mechanism exists to handle. It also broke the "never re-admit"
guard, which recorded the revoked key under its post-revocation identity and so
never recognized the key when it came back.

**Fix.** `ComputeKeyTag` gained a private overload taking the RDATA fields, so
the tag the key had *before* revocation can be computed. Revocation now matches
anchors on that tag (and the post-revocation one, harmlessly), and records both
identities in `revokedAnchors` so the key cannot start a fresh hold-down later.

Verified by `Revoked_Ksk_Is_Removed_From_The_Trust_Anchors`, which first asserts
the premise (`ComputeKeyTag(revoked) != ComputeKeyTag(live)`) so a future
regression cannot be mistaken for a test bug, and `Revoked_Key_Cannot_Come_Back`.

The rest of RFC 5011 was already correct: the 30-day hold-down, the refusal to
trust a key on first sight, and the continuity requirement all passed unchanged.

## 13 — The authoritative server ignored the CNAME rule

*RFC 1034 §4.3.2 step 3a:* when the queried node holds a CNAME and QTYPE is not
CNAME, the server copies the CNAME into the answer section and restarts the
query at the canonical name.

`AuthoritativeDNSRequestHandler` delegated to a zone lookup that matches on owner
**and** type, so an alias answered only a `QTYPE=CNAME` query. Asking for `A` at
a name that is a CNAME returned **NOERROR with an empty answer** — NODATA. A
resolver reads that as "this name exists and definitively has no A record" and
caches it.

Aliases therefore worked only for clients that already knew they were aliases,
which is none of them. This was the most user-visible of the findings: the zone
looks correct, `dig CNAME` confirms it, and every ordinary lookup returns nothing.

**Fix.** A `FollowCanonicalNames` step in the handler, applied on the NODATA
path. It is deliberately in the handler rather than in `InMemoryDNSZone`: the
rule is server behaviour and must hold for any `IDNSZoneStore`, and it needs only
the existing `Lookup` interface — one lookup for the CNAME, one to restart the
query at the target.

Details worth keeping:

- `QTYPE=CNAME` and `QTYPE=ANY` skip the restart. The store already answers both
  directly, and restarting would duplicate the record.
- The chase follows the whole chain while it stays in the zone, so
  `alias2 → alias → a` is answered in one round trip.
- It stops at the zone edge. When the canonical name is not held here, the CNAMEs
  gathered so far are returned and the resolver continues from them — what
  RFC 1034 expects of an authoritative server.
- Loops are caught by a visited set, not only by the depth limit. RFC 1034 §4.3.2
  warns the chain can loop; a two-element cycle would otherwise be walked sixteen
  times and each CNAME added to the answer on every pass.

Verified by `Query_For_A_At_An_Alias_Returns_The_Cname` (which now also asserts
the A record is appended, not just the CNAME),
`Unknown_Type_At_An_Alias_Still_Returns_The_Cname`,
`Chained_Alias_Resolves_Or_Refers` (both links plus the A record) and
`Cname_Loop_Does_Not_Hang_The_Server`, which serves a deliberately cyclic zone
and asserts each link appears exactly once.

RFC 2181 §10.1 was never violated — `Alias_Node_Carries_No_Data_Of_Its_Own`
passed throughout, and still does.

## 14 — NODATA answers were never served from the cache

*RFC 2308 §5:* negative answers, both NXDOMAIN and NODATA, are to be cached.

NXDOMAIN was cached correctly; NODATA was not, and two identical queries produced
two requests every time.

The cause was one condition in `DNSCache.Add`. An answer-less response was stored
only when its RCODE was `NameError` or `Refused`; a NODATA response — NOERROR
with an empty answer section — fell straight through to `return this` and was
never stored at all. Everything downstream was correct and unreachable:
`DNSClient` computed a TTL and called `AddNoData` per type, and the lookup path
checked `IsNoData`, but that check sits behind `TryGetDNSInfo`, which had nothing
to return.

**Fix.** `Add` now recognizes NODATA as negative, on one extra condition: the
response must carry an SOA in the authority section. That is what separates a
NODATA answer from a *referral*, which is also NOERROR with an empty answer
section but carries NS records instead. Caching a referral here would record
"this type does not exist" for a name whose data merely lives on another server.

Verified by `Repeated_Nodata_Query_Is_Served_From_The_Cache` and
`Referral_Is_Not_Cached_As_Nodata`, both counting datagrams that actually reached
the socket rather than asking the cache what it believes.

## 15 — The negative TTL ignored the SOA MINIMUM

*RFC 2308 §4:* the TTL of a negative answer is the minimum of the SOA's **MINIMUM
field** and the SOA record's own TTL.

Also two problems, and the second made the first untestable.

Where the SOA was consulted, `DNSClient` and `DNSCache.Add` both read
`soa.TimeToLive` — the record's TTL — and never looked at the MINIMUM field that
RFC 2308 repurposed for exactly this. Understandable, since every *other* record's
lifetime does come from its TTL.

But the entry would not have expired even with the right number: `TryGetDNSInfo`
called `FilterExpiredRecords`, which returns a negative entry unconditionally
(there are no answer records whose TTLs it could filter) and never consulted the
entry's own `EndOfLife`. A negative entry was therefore returned until the
cleanup timer happened to sweep it, whatever lifetime it had been given.

**Fix.** A shared `DNSCache.ComputeNegativeCacheTTL(response)` applies §4 —
`min(MINIMUM, SOA TTL)`, falling back to the configured default when there is no
SOA — and is used by both the NXDOMAIN and NODATA paths. `TryGetDNSInfo` now
enforces the entry's expiry for entries with no answers.

Verified by `Negative_Answer_Expires_After_The_Soa_Minimum`, which sets MINIMUM
to 1 s and the SOA's own TTL to an hour, so reading the record TTL instead — the
original mistake — still fails the test.

## 11 — Wildcard owner names could not be represented

*RFC 4592 §2.1.1:* a wildcard domain name is one whose leftmost label is a single
asterisk. It is an ordinary label as far as the wire format is concerned.

`DomainName.Parse("*.wild.example")` threw: the regex requires a label to start
with a letter or digit. Wildcard owner names do reach clients — the NSEC and
RRSIG records that prove a wildcard match carry them — so a record a signer
legitimately produced could not be read back.

**Fix.** The asterisk is validated and stripped before the hostname regex runs,
in the two places that parse owner names read from the wire:
`DomainName.ParseLenient` (via a new `AllowWildcardLabel` flag alongside the
existing `AllowUnderscoreLabels`) and `DNSServiceName.Parse`, which is already
the owner-name parser — it exists to allow `_` labels.

Two deliberate limits:

- **`DomainName.Parse` still rejects it.** A wildcard is never a hostname, and
  leniency belongs only on the path that reads names off the wire. The test
  asserts the strict parser keeps refusing.
- **Only the leftmost position is accepted.** RFC 4592 §2.1.1 is specific that
  only a leading `*` makes a wildcard; an asterisk elsewhere is an ordinary
  label that happens to contain one. `a.*.example` and `*x.example` are legal on
  the wire but stay rejected, because neither is a wildcard and accepting them
  would quietly widen what this API produces.

Verified by `Wildcard_Owner_Names_Are_Representable`, four
`Wildcard_Label_Is_Only_Accepted_Leftmost` cases, and
`Wildcard_Owner_Name_Round_Trips_Through_The_Wire`, which checks the label goes
out as the single octet 0x2A and comes back through the suite's independent
reader unchanged.

With this the suite's fixture loader no longer needs its substitute-owner
workaround: wildcard records load from the zone file like any other, and
`SignedZoneFixture.WildcardSignature` has been deleted.


## 16 — An unknown RR type in a request was answered FORMERR

*RFC 3597 §2:* an implementation must be able to handle records of a type it
does not recognise, treating their RDATA as opaque.

`DNSPacket.ParseResourceRecords` dispatched on the record type with a `switch`
expression carrying arms for `A` and `OPT` and no default. Any other type threw
a `SwitchExpressionException`, the parse failed, and the server answered
FORMERR — the very path added for finding 8, now firing on messages that were
not malformed at all.

The question section was always readable; only a record in the additional
section was not. So a query carrying anything the build had no parser for — a
TSIG, a client-side cookie in record form, any type assigned after this build —
was refused rather than served, and RFC 1035 §4.1.1's "unable to interpret the
query" was reported for a query that was perfectly interpretable.

It had gone unnoticed because well-formed queries carry no records outside the
additional section, and the only additional record Hermod had ever been sent
was OPT. Wiring up TSIG is what produced the first request with something else
in it.

**Fix.** Unknown types are read by their outer shape rather than parsed: CLASS
and TTL are stepped over, RDLENGTH is read, and the stream advances past the
RDATA, which keeps it aligned for whatever follows. The two known types keep
their existing constructors.

Verified by `A_Server_Without_Keys_Ignores_Tsig_Entirely`, which sends a
TSIG-signed query to a server that has no TSIG keys configured and asserts it is
answered normally — the record is unknown to that server, and unknown is not
malformed.

*Superseded in part.* This fix stepped over the record and discarded it, which
finding 21 later showed to be only half of §2: "opaque" describes the RDATA, not
a licence to drop the record. The request parser now keeps what it steps over.

## 17 — Aggressive NSEC caching: unreachable, unvalidated, and mis-ordered

*RFC 8198 §3, RFC 4034 §6.1.*

RFC 8198 lets a resolver answer from a cached NSEC record: one record proves a
whole *range* of names absent, so any name inside that range can be denied
without asking again. Hermod had an implementation of this, and both the README
and PLAN listed it as "implemented, currently untested". Testing it turned up
four defects, and the order in which they hid each other is the interesting part.

**It never ran.** The block that cached NSEC records sat *after* an early
`break` for `NameError` — and NXDOMAIN is precisely the response that carries
denial records. The feature was dead code for its entire purpose. This was found
by mutation: removing the validation check below changed nothing, which it
should have, and that only makes sense if the code was unreachable.

**It validated nothing.** §3 permits aggressive use only for DNSSEC-validated
records, and that condition is the whole safety argument. Hermod cached NSEC
records out of any response at all. Had the code been reachable, an off-path
attacker who lands one forged NXDOMAIN carrying a wide NSEC range would have
suppressed every name in that range for the TTL — cheaper than cache poisoning,
because there is no race to win against a specific query. The two defects
cancelled out, which is luck rather than design: fixing the reachability alone
would have opened the hole.

**It compared names as strings.** The lookup's own comment cited RFC 4034 §6.1
canonical order; the code below it called `String.Compare(…, Ordinal)`. Those
are different orders — canonical compares labels from the rightmost, ordinal
walks characters left to right. The consequence is not a missed cache hit but a
wrong denial: with an NSEC spanning `b.example.` → `d.example.`, the name
`c.z.example.` looks like it falls inside, because `c` sits between `b` and `d`.
It does not; it lives under `z.example.`, outside the span entirely. A resolver
believing that returns NXDOMAIN for a name that may well exist.

**It guessed the zone.** Both the store and the lookup derived a zone by taking
the last three labels of the query name, with `// use last 2+ labels as
approximation` written next to it. That is right for `a.example.com` and wrong
wherever the zone cut sits elsewhere.

**Fix.** The caching moves ahead of the early returns, so it sees every
response. It is gated on `DNSSECStatus == Secure`; since `DNSClient` does not
validate inline, the path is now dormant — which is the correct state for a
feature whose precondition is unmet, and strictly better than an unauthenticated
denial cache. The range check uses `DenialOfExistenceValidator.CompareCanonical`,
the comparator finding 17's sibling work already needed, rather than a second
copy. The zone comes from the SOA in the authority section when storing, and the
lookup walks the query name's ancestors instead of guessing.

Verified by `Range_Is_Judged_In_Canonical_Order_Not_String_Order`,
`Deeper_Names_Inside_The_Gap_Are_Recognised`, `The_Last_Nsec_In_A_Zone_Wraps_Around`,
`The_Zone_Is_Not_Guessed_From_The_Shape_Of_The_Name` and
`An_Unvalidated_Nsec_Never_Reaches_The_Cache`. The last one needed its own
correction: its first version used a scripted responder whose authority section
carries only an SOA, so there was no NSEC to cache and the test passed with or
without the fix. It now builds the NXDOMAIN by hand with an NSEC in it, and
fails when the validation gate is removed.

This is the entry the queued list predicted. It sat under "implemented,
currently untested" for the whole life of the suite, and every one of the four
defects was reachable by reading the code — nobody had.


---

## 18 — Negative answers carried no SOA, so none of them could be cached

*RFC 2308 §3.*

> Name servers authoritative for a zone MUST include the SOA record of the zone
> in the authority section of the response when reporting an NXDOMAIN or
> indicating that no data of the requested type exists. This is required so that
> the response may be cached.

Hermod's authoritative server answered NXDOMAIN and NODATA correctly and sent
both with an empty authority section. The RCODE was right; the record that makes
it *usable* was missing.

The consequence is not a wrong answer, which is why it survives review easily —
it is that no resolver in the path can remember the answer. Every repetition of
a query for a name that does not exist goes back to the origin, and negative
traffic is not a rounding error: a typo in a mail server's configuration, a stale
CNAME target, or a probe for a name that never existed all repeat indefinitely.
RFC 2308 exists precisely because this was a real load problem in the 1990s, and
the SOA is how the responder tells the world how long it may stop asking.

It also removes the only handle the resolver has on *how long*: finding 15 fixed
Hermod's client to compute the negative TTL as `min(SOA.MINIMUM, SOA.TTL)`, and
that code had nothing to work with when Hermod itself was the server. The two
findings are the same requirement seen from the two ends of the wire, which is
why the client side passed its tests while the server side was silently
unhelpful.

**Fix.** `InMemoryDNSZone` now knows its own apex — the owner name of the SOA it
holds — and every NXDOMAIN and NODATA it returns cites that SOA. The zone gained
the rest of RFC 1034 §4.3.2 at the same time, since all of it turns on the same
question of what the zone actually contains: empty non-terminals (a name with
descendants but no records is NODATA, not NXDOMAIN), wildcard synthesis, and
delegations answered as referrals with AA clear.

Records the store happens to hold outside its apex — an `in-addr.arpa` name
alongside a forward zone, as the standard test fixture does — are still answered
by exact name and still get no SOA. That is deliberate: there is no zone to cite
for them, and inventing one would be worse than citing none.

Verified by `Negative_Answer_Cites_The_Zone_Apex_Soa`, and by the SOA assertions
in `Wildcard_Does_Not_Reach_Past_The_Closest_Encloser`,
`Wildcard_Does_Not_Apply_To_An_Empty_Non_Terminal` and
`Nodata_Carries_The_Soa_The_Nsec_And_Both_Signatures`.


---

## 19 — The TCP fallback dropped the query's transaction signature

*RFC 8945 §5.3, RFC 2931 §3.1.*

A truncated UDP answer sends the client back over TCP (RFC 7766 §5). Hermod's
fallback built that second query from the `DNSPacket` object and wrote it
straight to the socket — correctly framed, correctly addressed, and unsigned.
The TSIG key the caller configured was applied to the first attempt and to
nothing else.

**Nothing reports this.** A server serves unsigned requests: RFC 8945 §5.2 only
governs what to do with a signature that fails, and RFC 2931 §3.1 says servers
are "not required to check a request SIG(0)" at all. So the retry is answered
normally, the answer is returned, and the caller — who asked for an
authenticated exchange and got no error — has an unauthenticated one. There is
no failed assertion anywhere in the system to notice.

**And it is not a corner case.** Truncation is what happens when the answer is
large, and the answers that are large are exactly the interesting ones: a signed
zone's NXDOMAIN with three NSEC3 records and their RSA signatures runs past
1232 octets without effort — see
`Oversized_Signed_Answer_Truncates_And_Survives_Over_Tcp`, which was written the
same week for a different reason. So the mechanism reliably switched itself off
under precisely the conditions that make it worth having.

The response side had the mirror gap: the TCP reply was parsed without checking
any signature it carried, so even a server that did sign got no benefit.

This was found while wiring SIG(0) into the same client, which is the honest
version of events. The TSIG path had been in the suite for three rounds and
looked well covered — the tests drove UDP, where the code was right, and the
fallback was a different method nobody had a reason to look at.

**Fix.** Signing and verification move into `SignQuery` and
`TryAcceptSignedResponse`, and both transports call them — one implementation,
so the next transport to be added has to opt out rather than merely forget. The
TCP retry now carries the same signature the datagram did and checks the reply
the same way.

Verified by `The_Tcp_Retry_Carries_The_Same_Signature`, which reads the retry off
a scripted TCP listener and checks the signature with the platform's own RSA
over the data RFC 2931 §3.1 defines, rather than by handing it back to the code
that made it.


---

## 20 — A DS query at a zone cut was answered with a referral

*RFC 4035 §3.1.4.1.*

> The DS RRset and its associated RRSIG RRs are authoritative data in the parent
> zone.

Every other question about a delegated name belongs to the child, so a server
that finds a zone cut on the way to QNAME stops and refers. DS is the one
exception, and Hermod's zone did not make it: `FindDelegation` began its search
at QNAME itself, so `insecure.example. DS` matched the delegation and came back
as a referral — AA clear, NS records in the authority section, no SOA.

The consequence is that the chain of trust cannot be walked. A validator asks
the *parent* for the DS precisely because the DS is what says whether the child
is signed; being told "ask the child" sends it to the one party whose answer
cannot settle the question. Every delegation becomes a dead end, and it fails in
the direction that looks like an unsigned zone rather than like an error.

It surfaced from the opt-out work rather than from review: the RFC 5155 §7.2.7
test asks for the DS at a zone cut, because that is where an opt-out proof is
carried. The referral logic had been in the suite since the wildcard round and
looked well covered — every test that reached it queried for A.

**Fix.** The delegation search starts one label further down for QTYPE=DS. A
zone cut *above* QNAME still ends the search, even for a DS: that name really is
in the child's half of the tree.

Verified by `A_Ds_Query_At_A_Zone_Cut_Is_Answered_By_The_Parent`, and — since
the opt-out fixture makes it possible — by `delv`, which now validates the
insecure delegation's proof end to end.

## 21 — An unknown RR type in a response cost every record behind it

*RFC 3597 §2:* a record of a type the implementation does not recognise is
handled as opaque data.

Finding 16 fixed this on the request path. The response path had the same shape
and a worse ending. `DNSInfo.ReadResourceRecord` consumed the owner name and the
TYPE, looked the type up in the reflection registry, and on a miss logged a
debug line and returned `null` — *without reading CLASS, TTL, RDLENGTH or the
RDATA*.

The record was therefore not merely dropped. The reader was left standing inside
it, four fields from where the caller believed it was. `ReadResponse` then called
it again for the next record, which began reading an owner name out of this
record's CLASS field and a type out of its TTL. What happened after that depended
on the RDATA: usually an exception out of a name or a record constructor, which
propagated out of response parsing and lost the whole message; occasionally
something worse, a plausible-looking record assembled from another record's
bytes.

So the cost of one unrecognised type was not that type. It was every answer
behind it, including the ones the build understood perfectly well. Which types
those are is not exotic — IPSECKEY, DHCID, HIP and APL are all deployed, all
older than this code, and none of them has a parser here.

It survived because the suite had only ever put unknown types *last*: finding
16's regression test sends a TSIG-signed query, and a TSIG is the final record
in a message by definition. Nothing had asked what happens to the record after
one.

**Fix.** `UnknownRecord` — an ordinary `ADNSResourceRecord` holding the type code
and the RDATA octets, and nothing else. `ReadResourceRecord` builds one instead
of returning `null`, so the reader always ends where the next record begins, and
`DNSPacket.ParseResourceRecords` now keeps the records it steps over rather than
discarding them. The RDATA is never interpreted on the way in or out — including
when it *reads* as something, which the fixture zone tests with RDATA that is a
valid compression pointer to offset 12.

`UnknownRecord` is deliberately outside the reflection registry: the registry
maps one type code to one class, and this class answers for every code that has
none. `RecordTypeRegistryTests.The_Fallback_Is_Not_In_The_Index` measures that
exclusion rather than assuming it.

Two things fell out of the fix for free. Wildcard synthesis works for unknown
types, because `CloneWithOwner` goes through the wire and back through
`ReadResourceRecord` — it used to throw. And RFC 3597 §5's presentation format
became implementable: `\# <length> <hex>`, `TYPEnnn`, `CLASSnn`, both read and
written, including §5's last paragraph — a *known* type written generically is
re-read as that known type, not left opaque.

Verified by `An_Unknown_Type_Does_Not_Cost_The_Records_Behind_It`, which puts the
unknown record between two A records and asserts the second one is read from its
own bytes, by the `ServerUnknownTypeTests` fixture, and by
`Message_Parser_Keeps_A_Record_It_Cannot_Read` on the request path.

## 22 — Names in the RDATA of post-1035 types were compressed

*RFC 3597 §4*, which settles a term RFC 1123 left open:

> it is hereby specified that only the RR types defined in [RFC1035] are to be
> considered "well-known".

Only those types may carry a compression pointer inside their RDATA. Eleven of
Hermod's record types passed the caller's `UseCompression` flag straight through
to the name in their RDATA, and only five of them were entitled to: SRV, NSEC,
RRSIG, DNAME, NAPTR, AFSDB, RP, SVCB, HTTPS, TKEY and TSIG all postdate RFC 1035,
and four of them are told so by their own specifications — RFC 2782 for SRV,
RFC 4034 §3.1.7 for the RRSIG signer's name, §4.1.1 for NSEC's next domain name,
RFC 9460 §2.2 for SVCB and HTTPS.

The failure is the other half of finding 21. A receiver with no parser for a type
handles its RDATA as octets, which leaves it no way to find a pointer inside, let
alone expand one — and if it stores those octets and passes them on, the pointer
now indexes into a message that no longer exists. Nothing errors; the record
simply becomes wrong.

RRSIG is the case that would have fired in practice. The signer's name is the
zone apex, and the apex is already on the wire as the question name of nearly
every signed answer — so the pointer was always available and always taken.

**Severity is Medium and it is worth saying why.** Compression is off by default
(`DNSServerOptions.UseCompression = false`, and `DNSPacket.ToByteArray` passes
false), so no shipped configuration emitted these pointers. It is a MUST
violation waiting on one option, not a live one.

**Fix.** Those eleven serialize their embedded names uncompressed regardless of
the flag, each with its governing citation at the call site. The owner name is
untouched — RFC 3597 §4 keeps it "always eligible for compression".

Verified by `RdataCompressionTests`, which hand-builds RDATA for sixteen types,
checks the hand-built layout survives an uncompressed round trip *before*
judging compression — so a wrong layout fails as a wrong layout rather than as a
false pass — and asserts the five RFC 1035 types still compress, which is what
proves the other eleven assertions are measuring anything.

## 23 — A bare decimal in a zone-file line was read as a class, not a TTL

*RFC 3597 §5*, which gives the reason for the `TYPEnnn`/`CLASSnn` convention
rather than just the syntax:

> This convention allows types and classes to be distinguished from each other
> and from TTL values, allowing the "[\<TTL\>] [\<class\>] \<type\> \<RDATA\>" and
> "[\<class\>] [\<TTL\>] \<type\> \<RDATA\>" forms of RR to both be unambiguously
> parsed.

`TryParseDNSQueryClass` tried the mnemonics, and then fell back to accepting any
bare decimal as a numeric class. That is precisely the ambiguity the convention
exists to remove. `TryParseZoneFileString` tries class before TTL, so in

```
a.example. 3600 IN A 192.0.2.1
```

`3600` was taken as class 3600, `IN` then overwrote it, and the TTL field was
never filled — the record came out with whatever `DefaultTimeToLive` the caller
had passed, or zero. The record parsed, looked right, and had the wrong TTL. The
other ordering, `a.example. IN 3600 A …`, failed outright.

`TryParseDNSResourceRecordType` had had the `TYPEnnn` half of the convention all
along and no bare-decimal fallback, so the two halves disagreed with each other.

It had gone unnoticed because the suite's zone fixtures do not use this parser.
`SignedZoneFixture` reads BIND's output with a hand-written reader — "never test
Hermod with Hermod" — and the in-memory zones are built from constructors. The
only caller is `InMemoryDNSZone.Add(String)`.

**Fix.** The bare-decimal fallback is gone and `CLASSnn` replaces it, so a bare
decimal in the header is a TTL and nothing else. `ToZoneFileString` writes
`TYPEnnn` and `CLASSnn` for values with no mnemonic, which it previously rendered
as bare numbers that nothing could read back.

Verified by `A_Bare_Decimal_Is_A_Ttl_And_Not_A_Class`, which asserts both
orderings against a deliberately different `DefaultTimeToLive` so that a lost TTL
cannot coincide with the expected one.

## 24 — The resolver's DNAME substitution matched characters, not labels

*RFC 6672 §2.2*, whose whole definition is one sentence:

> A DNAME substitution is performed by replacing the suffix labels of the name
> being sought matching the owner name of the DNAME resource record with the
> string of labels in the RDATA field.

The word carrying the requirement is **labels**. `DNSClient` compared strings:

```csharp
var ownerSuffix = dname.DomainName.ToString();
if (currentName.EndsWith(ownerSuffix, StringComparison.OrdinalIgnoreCase))
{
    var prefix  = currentName[..^ownerSuffix.Length];
    cnameTarget = prefix + dname.Target.FullName;
}
```

A domain name is a sequence of labels that happens to be written with dots
between them, and the two readings disagree exactly where a shorter name is
spelled inside a longer one. Three consequences, all measured before the fix:

**A DNAME rewrote names it had no relationship with.** `notold.example.` ends
with the characters of `old.example.` and is not below it — the boundary falls
inside a label. The comparison matched, the prefix came out as `not`, and
concatenation produced `notnew.example.`: a name in a different zone, reached by
a redirection nobody authorized. A DNAME is published by whoever controls its
owner name, and this let that publisher redirect names outside their control.

**The one name §2.3 exempts was redirected most cleanly of all.** "The owner name
of a DNAME is not redirected itself" — but a suffix comparison matches the owner
against itself with an empty prefix, so `old.example.` became the bare target.

**An oversized substitution threw.** There was no 255-octet check, so a long
target and a long prefix produced a name `DNSServiceName.Parse` refuses, and the
`ArgumentException` came out of the query rather than an answer.

The severity is High for the first of the three. The second is a correctness bug
with a visible wrong answer; the first is a trust-boundary bug, and it fails in
the direction of following a redirection rather than refusing one.

**Fix.** `DNAME.TrySubstitute` — the substitution on labels, with the length
check, returning the two failures separately because they mean opposite things
to a server: a name the DNAME does not cover is answered as if the DNAME were
not there, while a name it covers but cannot build is YXDOMAIN with the DNAME as
proof (§2.2). Both the resolver and the authoritative side call it. That
sharing is the point rather than a tidiness: a second implementation of a
label-suffix rule is a second chance to write it as a string comparison.

Verified by `DNameSubstitutionTests` on the rule itself — `notold.example.` and
the DNAME owner both among the names it must decline — and by
`DNameFollowingTests`, which drives the resolver against a scripted server
sending a DNAME with no synthesized CNAME, so the client has to perform the
substitution, and asserts on the name it asks for next. Three of those five
tests fail against the previous revision.

**What was missing rather than wrong.** The authoritative server had no DNAME
handling at all — the record type parsed, served and round-tripped, and nothing
redirected. That is a gap and not a deviation, so it gets no number, but it is
where most of this round's work went: the substitution, the synthesized CNAME
(§3.1, with the DNAME's TTL rather than RFC 2672's zero), YXDOMAIN for a name
that will not fit, occlusion of anything below the owner (§2.4), and a bound on
chains for a DNAME pointing inside its own subtree. `delv` validates the result,
including the part a server cannot fake: the DNAME carries the zone's signature
and the CNAME beside it carries none, because the server invented it while
answering.

**One thing found in passing.** `DNSResponseCodes.Reserved` was declared as
`6 | 7 | 8 | 10 | 11 | 12 | 13 | 14 | 15` — a bitwise OR, which is 15, not the
set of reserved codes it reads as. Nothing referenced it, so nothing was broken;
it is noted because it stood exactly where YXDOMAIN (6) had to go. The RCODEs
RFC 2136 §2.2 defines now have their own names.

---

## 25 — One spoofed response replaced the client's DNS Cookie for good

*RFC 7873 §5.3*, one sentence:

> A DNS client where DNS Cookies are implemented and enabled examines the
> response for DNS Cookies and MUST discard the response if it contains an
> illegal COOKIE option length or an incorrect Client Cookie value.

`DNSClient` did no comparison at all. `ExtractAndStoreCookie` took the COOKIE
option out of the response and kept it:

```csharp
if (responseCookie?.HasServerCookie == true)
    cookieStore[ServerKey] = responseCookie;
```

Two things are wrong with that, and the second is much worse than the first.

**The response was not discarded.** A cookie exists to make one claim: the client
cookie is an unpredictable value that comes back only from someone who saw the
query. A response echoing a different one is, by construction, from someone who
did not — and it was accepted and served to the caller.

**And the stored cookie included the client half.** The next query to that server
therefore carried the client cookie *from the response*. So a single spoofed
packet did not merely get through: it replaced the client's own unpredictable
value with one the attacker had chosen, for as long as the entry lived. Every
later query then advertised a cookie the attacker knew, every later spoof could
echo it, and every one of those responses passed the check that was not being
made anyway. The mechanism disabled itself, permanently, from one packet — and
the more the client used it, the more thoroughly it was disabled.

Measured before the fix: with a scripted peer answering with the client cookie
`AA…` where `A9983FAE6841C902` had been sent, the response was accepted with
NOERROR and one answer, and the next query went out carrying `AAAAAAAAAAAAAAAA`.

**Fix.** The client cookie of a response is compared with the one that was sent,
and the response is dropped when they differ. Only the *server* half of the
returned cookie is stored, joined to the client cookie the client already had —
which makes the stored value right independently of the comparison above it. And
`EDNSCookieOption.Parse` now states RFC 7873 §5.2.2's rule in one place: 8 octets,
or 16 to 40, and nothing in between.

Verified by `A_Forged_Client_Cookie_Does_Not_Replace_The_Clients_Own`, which
asserts on the *second* query rather than the first, and by
`A_Response_Echoing_A_Foreign_Client_Cookie_Is_Discarded`.

**What was missing rather than wrong.** The server had no cookie support and the
client never acted on BADCOOKIE, so the protocol of RFC 7873 §5.2 existed
nowhere: Hermod could encode a cookie and remember one, which is the part that
costs nothing and buys nothing. A server that issues no cookie can never be
returned one, and a client that treats BADCOOKIE as an error can never talk to a
server that requires them. Both halves are implemented now, with the server
cookie bound to the client cookie, the client's address and a timestamp — the
three things that separate a proof of return-routability from a bearer token.


## 26 and 27 — the validator's two wrong answers

Both came out of the CDS work, both live in `DNSSECValidator`, and they are each
other's mirror image. RFC 4033 §5 gives a validator four things it may say, and
the whole value of the mechanism is in saying the right one: **Secure** is proof,
**Bogus** is an accusation, **Insecure** is "this zone is not signed", and
**Indeterminate** is "no trust anchor covers this". Confusing any two of them
turns a working name into an outage or an outage into a working name.

### 26 — A delegation the validator cannot follow was reported forged

*RFC 6840 §5.2:*

> when determining the security status of a zone, a validator disregards any
> authenticated DS records that specify unknown or unsupported DNSKEY
> algorithms. If none are left, the zone is treated as if it were unsigned.

— and the same section extends that to unsupported *digest* algorithms.

The chain walk went straight from "no DS verified" to Bogus:

```csharp
var dsVerified = dsRecords.Any(ds => VerifyDS(ksk, ds));

if (!dsVerified)
    return DNSSECValidationResult.Bogus;
```

Nothing anywhere asked whether the DS RRset was *followable* — `VerifyDS`
computes a digest and returns false for a type it cannot compute, and false is
indistinguishable from a mismatch by the time the caller sees it.

So a delegation using an algorithm or digest this build has not learned came back
Bogus, which is not "I cannot check this" but "this is forged" — and a resolver
that believes it answers SERVFAIL. The name stops resolving for every client
behind the validator, over a zone that is very likely perfectly fine and merely
newer than the code reading it. It is the failure that arrives on the day someone
else upgrades.

RFC 8078 §4 says the same thing about algorithm 0 in particular, which is where
this surfaced: the delete sentinel gives 0 a meaning in CDS, and "must treat it
as unknown. Accordingly, the zone is treated as unsigned".

**Fix.** `HasUsableDelegationSigner` asks the question §5.2 requires, and a DS
RRset with nothing usable left is treated exactly as no DS RRset at all —
Insecure. One followable record among unusable ones is still enough, because §5.2
says to *disregard* the others rather than fail on them; a validator that stopped
at the first unreadable DS would treat every zone mid-rollover as unsigned, which
is a downgrade and the worse of the two mistakes.

Verified by `A_Delegation_Whose_Ds_Nobody_Can_Follow_Is_Insecure` and its control
`A_Delegation_With_One_Usable_Ds_Among_Unusable_Ones_Still_Validates`, both
driving the real chain walk through the stub resolver.

### 27 — Malformed key material threw out of validation

`VerifyRSA` parsed an RFC 3110 key by indexing straight into it, and `VerifyECDSA`
handed a point to `ECDsa.Create` without checking it was on the curve. Both throw
on input that is merely wrong: a DNSKEY too short to hold its own exponent-length
octet, a length prefix running past the end of the key, a point that is not a
point. The two Edwards implementations already caught their exceptions and
returned false — so six algorithms behaved one way and two the other, which is
the shape of a bug nobody chose.

The call site catches everything and returns **Indeterminate**. That is the wrong
one of the four: RFC 4033 §5 defines Indeterminate as there being no trust anchor
covering this part of the tree, and a zone that claims to be signed and presents
an unusable key has not become a zone nobody has an opinion about. The right
answer is that this key does not verify this signature — which, with no other key
working, is Bogus (RFC 4035 §5.3.3).

Every one of those keys arrives over the wire, so their contents are whatever the
far side chose to send.

**Fix.** Both verifiers now fail rather than throw, matching what the Edwards
pair already did. Indeterminate is left to mean what RFC 4033 §5 says it means.

Verified by `Malformed_Key_Material_Fails_Rather_Than_Throws`, which puts seven
malformed keys through all eight algorithms and asserts on both halves: no
exception, and no acceptance.


## 28 and 29 — LOC, where every field means something else

RFC 1876 gives the LOC record seven fields, and six of them hold something
other than the measurement they stand for. Latitude and longitude are unsigned
with 2^31 for the origin, altitude is unsigned with 100 km subtracted, and size
and the two precisions are a mantissa and an exponent packed into one octet.
Every one of those conversions lived inside `ZoneFileRData` as a local variable,
which is why the coverage note had said "only the common shape is covered": the
only way to ask what any of it meant was to read a rendered string.

### 28 — The LOC parser discarded the size and both precisions

*RFC 1876 §3* gives defaults "if omitted" — size 1 m, horizontal precision
10000 m, vertical precision 10 m. `TryParseFromJSON` applied them whether or not
the fields were there, and said so:

```csharp
// Parsing the full presentation format is complex; create a minimal record
// preserving the version=0 and default precision values.
```

So a zone file line reading `42 21 54 N 71 6 18 W -24m 30m 40m 50m` loaded as
`-24m 1m 10000m 10m`. Three values written down by hand, replaced by defaults,
with nothing anywhere to say it had happened — and the record still parsed, still
served, still round-tripped, and still rendered as a perfectly ordinary location.

Defaults are for absent values. Substituting them for present ones is a way of
discarding data that looks like a specification.

The fields that vanished are the ones that say how much to trust the two that
survived: a zone claiming its coordinates are good to 40 m loaded as one claiming
10 km.

**Fix.** The three optional fields are read when present and defaulted only when
absent. They are positional, so giving two means the third defaults, which is
what `Omitted_Fields_Take_The_Defaults_Section_Three_Gives` pins across all four
combinations.

### 29 — An unknown LOC version was rendered as if it were version 0

*RFC 1876 §2:* "Implementations are required to check this field and make no
assumptions about the format of unrecognized versions."

Nothing checked it. A LOC with VERSION 1 — whose RDATA layout is by definition
unknown — was decoded as latitude, longitude, altitude and three scaled octets,
and came out as a coordinate that looks entirely ordinary and means nothing.

The same held one field down, for the scaled octets §2 leaves undefined: "Four-bit
values greater than 9 are undefined, as are values with a base of zero and a
non-zero exponent." `0xFF` rendered as 150000000000000 m — a sphere wider than
the solar system — and `0x05` rendered as 0 m, quietly agreeing with a sender who
meant something the RFC declines to define.

**Fix.** A LOC whose version is not 0, or whose scaled octets are not values §2
assigns a meaning to, is written in RFC 3597 §5's generic form. That is not an
invention: §5 gives this exact record as its example of why the generic form
exists — "an RR type where the text format varies depending on a version ... e.g.,
a LOC RR [RFC1876] with a VERSION other than 0". The two rounds meet here.

Severity is Low because nothing in the wild publishes a version other than 0 —
but that is also why it would have stayed wrong indefinitely.

**And the semantics came out of the formatter.** `SizeInCentimetres`,
`LatitudeInMilliArcSeconds`, `AltitudeInCentimetres` and the rest are properties
now, so the conversions can be asserted as numbers. That is what let the mutation
pass reach them: reversing the latitude offset, dropping the altitude reference
and ignoring the exponent are all caught, and none of the three would have
changed a rendered string in a way a reader would notice.


---

## 30 and 31 — padding, absent from both ends of the same connection

DoT encrypts the transport, which hides the name being asked for and leaves the
length of the message behind. A query is short and its length says a great deal
about it; that is the gap RFC 7830 exists to close, and RFC 8467 §4.1 names the
block lengths — 128 octets for queries, 468 for responses.

Hermod parsed the option and could compute a block-aligned length. Nothing
called it. The two findings below are what that came to on each side, and they
compound: the client's silence puts the server in the one case where padding is
*forbidden*, so even a correct responder would have had nothing to do.

### 30 — A padded query was answered unpadded

*RFC 7830 §4:* "Responders MUST pad DNS responses when the respective DNS query
included the 'Padding' option, unless doing so would violate the maximum UDP
payload size."

Measured over DoT, with the suite's own reader rather than Hermod's:

| | |
|---|---|
| query | 128 octets, Padding option present, payload size 4096 |
| response | 81 octets, OPT record present, **options: none** |

The exception clause does not apply: 468 octets sit far below the 4096 the
requestor advertised. The server saw the option, built an OPT record for the
reply, and left the padding out of it.

**Fix.** The response is padded at the point where it is serialized for a
length-prefixed stream, which TCP and DoT share. Padding depends on the finished
length, so it cannot be decided where the response OPT is built — that runs
before the answer is assembled and the length is not yet known. The message is
therefore serialized twice: a trial run carrying an empty Padding option, then
the real one. Measuring the trial rather than adding four for the option header
keeps the header inside the number the serializer produced.

The measurement is taken *after* signing. What an observer counts is the
finished message, TSIG or SIG(0) record included, so that is the length which
has to land on the boundary; padding underneath a signature of some other length
would leave the observable length as revealing as before. Both RFCs are silent
on the combination.

Severity is Medium: no answer was wrong and nothing failed to interoperate.
What was missing is the defence the peer asked for by name.

### 31 — The DoT client announced no EDNS(0), so nothing could be padded

*RFC 8467 §4.1:* "Clients SHOULD pad queries to the closest multiple of 128
octets", with the note that "the recommendation above only applies if the DNS
transport is encrypted".

The DoT client's queries were 29 octets and carried no OPT record at all — it
passed a literal `0` as the payload size, which is `DNSPacket.Query`'s switch for
leaving EDNS(0) out. Padding lives inside the OPT record, so there was nowhere
to put it.

That is the smaller half of the consequence. The larger one is on the other side
of the connection: *RFC 7830 §4:* "Responders MUST NOT pad DNS responses when the
respective DNS query did not indicate EDNS(0) support." Hermod's own client put
Hermod's own server in exactly the case where padding is prohibited, so the two
halves agreed with each other and neither was doing what the RFCs ask.

**Fix.** The client advertises a payload size — which is also the ceiling RFC
7830 §4 puts on the reply — and pads to 128 by default, through the same
two-pass measurement as the server. Both are properties rather than constants:
`UDPPayloadSize = 0` withdraws EDNS(0) and, necessarily, padding with it, and
`PaddingBlockSize = 0` keeps EDNS(0) while sending no padding.

Severity is Medium for the same reason as 30, with the addition that this one
also disabled the other end.

**The DoH client had the same shape** — the same literal `0`, the same silence
about EDNS(0). It is finding 32 below, and it was fixed a round later.

**What the mutation pass added here.** Setting the client's default block length
to 0 survived the first run: the test helper set the property on every client it
built, so no test ever exercised the default — the one line carrying RFC 8467's
SHOULD. The helper leaves it alone now unless a test is explicitly about
overriding it.

---

## 32 — The DoH client did the same, on a transport RFC 8467 covers without naming

`DNSHTTPSClient` passed the same literal `0` payload size as the DoT client, so
it announced no EDNS(0) and padded nothing. The defect is finding 31's; what is
worth recording separately is the reasoning that deferred it, because that
reasoning was wrong.

**The correction.** The previous round left DoH alone and said why: that RFC
8467 §4.1's block lengths are stated for DoT, so applying them to an HTTP
transport would be guessing. Reading the RFC does not support that. §1 scopes
the whole document, and it scopes it by property rather than by protocol:

*RFC 8467 §1:* "Padding DNS messages is useful only when transport is encrypted
using protocols such as DNS over Transport Layer Security [RFC7858], DNS over
Datagram Transport Layer Security [RFC8094], or **other encrypted DNS transports
specified in the future**."

DoH is one of those — published the same month as RFC 8467, and named nowhere in
it. The qualifier attached to §4.1's recommendation is the same property: "Note
that the recommendation above only applies if the DNS transport is encrypted."
So 128 octets is the block length here for exactly the reason it is on DoT, and
there was never a number to guess at.

RFC 8484 says so from its own side, in *§9:* "DoH servers can also add DNS
padding [RFC7830] if the DoH client requests it in the DNS query." Requesting it
is the client's part, and it is the only part Hermod has — there is no DoH
server here for the responder's MUST to bind.

**One rule genuinely does differ, and it is the ceiling.** *RFC 8484 §6:* "DoH
servers using this media type MUST ignore the value given for the EDNS UDP
payload size in DNS requests." On DoT that field caps how far the responder may
pad; on DoH a responder is required to disregard it. What the field does here is
force the OPT record into existence, which is where the Padding option lives —
so the client still sets it, and its value is inert by design rather than by
oversight.

**Fix.** `UDPPayloadSize` and `PaddingBlockSize` on `DNSHTTPSClient`, and the
same two-pass measurement as the other transports: serialize with an empty
Padding option, measure, compute, rebuild. Measured after signing, for the same
reason as before.

**Two things called padding meet on this transport, and only one of them is
this.** RFC 8467 pads the DNS message; RFC 4648 pads a base64 encoding out to a
multiple of four characters, and *RFC 8484 §4.1* forbids the second: "Padding
characters for base64url MUST NOT be included." The first makes the second
harder to get right rather than easier. A message padded to a multiple of 128
has length ≡ 2 (mod 3), which is precisely the class where base64 appends a
single `=` — so following §4.1's recommended block puts **every** GET request
into the encoding case that has to be trimmed, where before only some were.
Measured: 128 octets encode to 171 characters, not 172. There is a test for the
combination, because the two rounds meet here.

HTTP/2's own padding is a third thing again, at a layer this does not touch —
*RFC 8484 §4.1:* "DoH clients can use HTTP/2 padding and compression [RFC7540]
in the same way that other HTTP/2 clients use (or don't use) them."

**And the line had a third copy**, on plain TCP, which neither this round nor the
one before it looked at — because neither was looking for an OPT record. That is
[finding 34](#34--the-same-literal-0-a-third-time-on-plain-tcp-where-it-cost-the-do-bit).

---

## 33 — Every DoH query carried a random ID, so no two were the same request

*RFC 8484 §4.1:* "In order to maximize HTTP cache friendliness, DoH clients
using media formats that include the ID field from the DNS message header, such
as 'application/dns-message', SHOULD use a DNS ID of 0 in every DNS request.
HTTP correlates the request and response, thus eliminating the need for the ID
in a media type such as 'application/dns-message'. **The use of a varying DNS ID
can cause semantically equivalent DNS queries to be cached separately.**"

`DNSPacket.Query` picks its transaction ID at random, and the DoH client took it
as given. Every request for the same name was therefore a different request —
different two octets, different base64url, different URI. An HTTP cache matches
on the request, so nothing ever hit.

The suite had already noticed. `Doh_Transaction_Id_Is_Reported` measured the ID
and ended in `Assert.Pass`, and PLAN.md carried the row as 📋 rather than ⬜ —
a gap that had been looked at and left, which is a better state to be in than
not knowing, and a worse one than fixed.

**Fix.** `ZeroTransactionId` on `DNSHTTPSClient`, on by default, applied through
a new `DNSPacket.WithTransactionId` — the same rebuild-rather-than-mutate shape
as `DNSPadding.WithPadding`.

**The ordering is the part that can go wrong quietly.** The ID is zeroed
*before* the query is signed. A TSIG or SIG(0) covers the message including the
header the ID sits in, so zeroing afterwards would put a query on the wire whose
own signature does not verify. There is a test that signs, checks the ID is 0,
and checks the MAC verifies, rather than leaving the order to a comment.

**What it does not give up.** A random ID is what RFC 5452 §9.2 asks of a
datagram transport, where it is one of the few things making an off-path spoof
hard. §4.1 states the reason it can be dropped here: HTTP correlates the request
and the response, so there is no second answer to tell apart from the first. The
client's own check that a response carries the query's ID stays in place — it
becomes "zero came back as zero", redundant rather than wrong, and it costs
nothing to keep. The behaviour is a property rather than a constant, because
§4.1 is a SHOULD and something upstream may want the randomness back.

**The test that matters is not the one about the ID.** Asserting the ID is 0
checks the mechanism. Asserting that two askings of the same question produce a
character-identical URI checks the property the mechanism exists to produce, and
it catches anything *else* that might vary between two equivalent queries —
which a look at the ID alone would not.

Severity is Low: nothing was incorrect, and no answer was wrong. What was lost
was every cache hit.

---

## 34 — The same literal `0` a third time, on plain TCP, where it cost the DO bit

*RFC 3225 §3:* "The mechanism chosen for the explicit notification of the ability
of the client to accept (if not understand) DNSSEC security RRs is using the most
significant bit of the Z field on the EDNS0 OPT header in the query."

*RFC 6891 §6.2.2:* "if DNSSEC or any future option using EDNS is required, no
fallback should be performed, as these options are only signaled through EDNS."

Findings 31 and 32 each removed a literal `0` payload size — from `DNSTLSClient`,
then from `DNSHTTPSClient` — and each was written up as a padding finding.
`DNSTCPClient` held the third copy of that line and neither round mentioned it,
because neither round was looking for an OPT record. Both were looking for
somewhere to put padding, and plain TCP is not encrypted, so RFC 8467 has nothing
to say about it and the file never came up.

Padding was never what the `0` withheld. `DNSPacket.Query` gates the *entire* OPT
record on `UDPPayloadSize > 0`, so what it withheld was the record — and with it
everything that can only travel inside one:

| | `DnssecOK` | caller's `EDNSOptions` | `DNSClient`'s Cookie / Client Subnet |
|---|---|---|---|
| `DNSUDPClient` (incl. its TCP retry) | on the wire | on the wire | on the wire |
| `DNSTLSClient` (since 31) | on the wire | on the wire | on the wire |
| `DNSHTTPSClient` (since 32) | on the wire | on the wire | on the wire |
| `DNSTCPClient` | **dropped** | **dropped** | **dropped** |

Those properties are not decoration. `DNSClient` assigns its own `DnssecOK` to
whichever transport client it selected, and pushes the DNS Cookie and the Client
Subnet option it manages into that client's `EDNSOptions`, immediately after
building its own query. A resolver configured for `DNSTransport.TCP` therefore
lost all three by routing decision alone — no caller had to do anything unusual,
and nothing anywhere reported it.

The DO bit is the part that does more than go missing. A query with the bit clear
is not a query that forgot to ask; it is a query that has said *do not send them*.
*RFC 3225 §3:* "The DO bit cleared (set to zero) indicates the resolver is
unprepared to handle DNSSEC security RRs and those RRs MUST NOT be returned in
the response (unless DNSSEC security RRs are explicitly queried for)." So the
failure was silent and correct-looking from both ends: the caller asked for
DNSSEC, the server obeyed a request never to send it, and the answer came back
unsigned with no error anywhere in it.

This is also what made `ServerKeepaliveTimeout` on `DNSTCPClient` unreachable
rather than merely unused. *RFC 7828 §3.3.2:* "A DNS server that receives a query
sent using TCP transport that includes an OPT RR (with or without the
edns-tcp-keepalive option) MAY include the edns-tcp-keepalive option in the
response to signal the expected idle timeout on a connection." The OPT RR, not
the option, is the server's licence — a client that asks for nothing can still be
told, but a client that sends no OPT record at all cannot.

**Fix.** The payload size `DNSTLSClient` and `DNSHTTPSClient` already carry — a
property rather than a constant, so `0` remains the caller's way to withdraw
EDNS(0) deliberately.

Padding is *not* added here, and the reason is the one finding 32 arrived at
rather than the one it discarded. RFC 8467 scopes itself by property, and this
transport does not have the property. *RFC 8467 §4.1:* "Note that the
recommendation above only applies if the DNS transport is encrypted." Plain TCP
is not, so there is nothing here for padding to hide — which is also why the same
correction that pulled DoH *into* RFC 8467's scope leaves plain TCP outside it.

Severity is **High**, above 31 and 32 despite the shared line. Those two cost a
defence the peer had asked for by name. This one silently converted "validate
this for me" into "do not send me anything to validate", and did it to a resolver
that had only chosen a transport.

Pinned by `A_TCP_Query_Carries_An_Opt_Record`, which sets `DnssecOK` and an EDNS
option on the transport client directly, and by
`A_Resolver_Routing_Over_TCP_Still_Asks_For_DNSSEC`, which comes in through
`DNSClient` instead so the finding cannot be answered with "no caller does that".
Both were red before the change and green after, and the DoH test beside them was
already green — finding 32 had reached that transport a round earlier.

---

## 35 — A DoT connection the server asked the client to stop using stayed in use

*RFC 7828 §3.2.2:* "A DNS client that receives a response that includes the
edns-tcp-keepalive option with a TIMEOUT value of 0 SHOULD send no more queries
on that connection and initiate closing the connection as soon as it has received
all outstanding responses."

A timeout of 0 is the one value that is an instruction rather than a duration.
*RFC 7828 §3.3.2:* "The DNS server SHOULD send an edns-tcp-keepalive option with
a timeout of 0 if it deems its local resources are too low to service more TCP
keepalive sessions or if it wants clients to close currently open connections."

`DNSTLSClient` holds one TLS session and reuses it across queries. It read the
option — finding 31 is why that is reachable at all — assigned
`ServerKeepaliveTimeout`, and then nothing anywhere in Hermod read the property
back. A zero arrived, was stored, and the next query went out on the same
connection. Measured as the handshake count a scripted DoT listener sees: one
handshake for two queries, where honouring the 0 costs a second.

**Fix.** Two lines where the option is already parsed: when the stored timeout is
zero, close the connection before returning the response. `CloseConnection()` is
inherited from `ATCPClient` and does the whole job, and queries on this client are
serialized by `tlsStreamLock`, so the response just read is the only outstanding
one — which is exactly the moment §3.2.2 names. Nothing else changes: every query
already begins by reconnecting when `IsConnected` is false, so the next one opens
a fresh TLS session on its own.

**The non-zero half of §3.2.2 is not this**, and is not fixed. The client
"SHOULD honour the timeout received in that response (overriding any previous
timeout) and initiate close of the connection before the timeout expires."
That needs an idle timer, which `DNSTLSClient` did not have — the session lived
until the client was disposed or the peer dropped it. It was parked as a coverage
boundary on the grounds that no test asserted it yet, which turned out to be a
description of the suite rather than of the code: once a test existed the
behaviour was a deviation, and it became [finding 37](#37--a-session-outlived-every-timeout-a-server-advertised).
The zero case was simply the crisp half — it needs no wall-clock wait to observe,
and it is the half where the server has actually said something.

Severity is **Low**, and the reason is not that it is a SHOULD. A caller could
have implemented this before the fix: both `ServerKeepaliveTimeout` and
`CloseConnection()` are public, so the capability was present and only the wiring
was missing. What made it worth fixing is that the client behaved worst exactly
when the server could least afford it — the 0 is sent under resource pressure,
and every client that ignores it keeps alive a session the server was trying to
shed.

Pinned by `A_DoT_Client_Stops_Using_A_Connection_The_Server_Asked_It_To_Close`,
which counts TLS handshakes rather than inspecting the client: two queries, and
the second one may not travel on the connection the server asked it to drop.

---

## 36 — The same rule, on the transport it had just become reachable on

*RFC 7828 §3:* "This specification does not distinguish between different types
of DNS client and server in the use of this option."

Finding 35 fixed the TIMEOUT 0 rule in `DNSTLSClient`. `DNSTCPClient` holds its
connection open the same way, parses the same option into the same property, and
did not get the same two lines — a zero arrived, was stored, and the next query
went out on the connection the server had asked to be rid of.

What makes this its own finding rather than an oversight worth a footnote is the
order the two rounds happened in. Plain TCP could not receive a keepalive option
at all until finding 34 gave it an OPT record, and finding 34 landed *in the same
sitting* as finding 35. So the transport became able to be told at the same
moment the rule for what to do when told was written — and the rule was written
on the other client. A test that had been impossible to write the day before was
merely not written.

**Fix.** Neither client carries the rule any more. Both hold a
`DNSKeepalivePolicy`, constructed with the stream lock that serializes their
queries and their own `CloseConnection`, and hand it every response. It is the
same code twice becoming the same code once — which is worth saying out loud
here, because findings 31, 32 and 34 are one literal `0` found three times in
three rounds, on the three clients that each kept their own copy of it. This file
has now watched the same shape play out twice in the same few hundred lines: the
duplicate is not the bug, but it is what turns one bug into three.

Severity is **Low**, for the reasons finding 35 gives, with the difference that
the capability was not merely present but already written and shipped a few
commits away.

Pinned by `A_TCP_Client_Stops_Using_A_Connection_The_Server_Asked_It_To_Close`,
the plain-TCP twin of finding 35's test, counting accepted connections where that
one counts TLS handshakes.

## 37 — A session outlived every timeout a server advertised

*RFC 7828 §3.2.2:* "A DNS client that receives a response using TCP transport
that includes the edns-tcp-keepalive option MAY keep the existing TCP session
open when it is idle. It SHOULD honour the timeout received in that response
(overriding any previous timeout) and initiate close of the connection before the
timeout expires."

This is the half of §3.2.2 that finding 35 named and left, and the reason it was
left is honest: it needs a clock, and a test for it looks at first like a test
that waits. Both connection-holding clients read the advertised timeout, stored
it, and then held the connection until the client was disposed or the peer gave
up on it. Every timeout a server ever sent was recorded and ignored.

The failure is quiet, and it is quiet in the direction that costs the *server*.
A resolver that advertises a 30-second idle timeout has told the client when it
intends to stop reserving the session; a client still using it at second 45 is
using something already counted as reclaimed, and finds out by having the
connection closed underneath a query. `DNSTLSClient` even has the retry that
hides it — an `IOException` reconnects and re-sends — so the cost shows up as an
occasional doubled round trip and never as an error.

**Fix.** `DNSKeepalivePolicy` restarts a timer at the end of every exchange, per
*RFC 7828 §3:* the idle timeout "should be reset when that condition is lifted,
i.e., when a client sends a message". A response that carries no option is not a
withdrawal, so the deadline in force stays in force and is simply re-armed.

The deadline is nine tenths of what the server advertised. §3.2.2 asks for the
close "before the timeout expires" and names no margin, and the margin has to be
a proportion rather than a span: TIMEOUT is a 16-bit count of 100 ms units, so a
server may legally advertise anything from 100 ms to a little under two hours,
and no fixed number of seconds is sensible at both ends.

The timer takes the client's stream lock with a zero wait before closing. A
deadline that lands mid-exchange finds the lock held, does nothing, and lets the
exchange re-arm it on the way out — where blocking on the lock instead would cut
off the query that proves the session is not idle.

Severity is **Low**: no answer is wrong either way, and the client recovers from
a connection the server reclaimed. What it cost is the cooperation the option
exists to arrange.

Pinned by four tests, and it takes all four.
`A_DoT_Session_Does_Not_Outlive_The_Timeout_The_Server_Advertised` and its
plain-TCP twin advertise 200 ms, stay silent for a second, and require a second
handshake. Those two say the session ends; they cannot say *when*, and a mutation
that closed at twice the advertised timeout left both of them green.
`A_Session_Is_Closed_Before_Its_Timeout_Expires` is the one that reads §3.2.2's
actual word: it advertises two seconds, watches `IsConnected`, and fails unless
the close lands inside them — 1828 ms, measured. And
`A_Session_Inside_Its_Timeout_Is_Reused` is what stops all of that from being
satisfied by closing after every exchange, which is the cheapest wrong fix and
the one *RFC 7858 §3.4* rules out by name: "In order to amortize TCP and TLS
connection setup costs, clients and servers SHOULD NOT immediately close a
connection after each response."

---

## 38 — A TTL with the sign bit set became a cache entry that never expired

*RFC 2181 §8:* "It is hereby specified that a TTL value is an unsigned number,
with a minimum value of 0, and a maximum value of 2147483647. That is, a maximum
of 2^31 - 1. When transmitted, this value shall be encoded in the less
significant 31 bits of the 32 bit TTL field, with the most significant, or sign,
bit set to zero. Implementations should treat TTL values received with the most
significant bit set as if the entire value received was zero."

Two rules in one paragraph, and Hermod missed both — in opposite directions.

**Receiving**, `ADNSResourceRecord`'s stream constructor read the four octets
straight into a `TimeSpan`. The line underneath it is the one that matters:
`EndOfLife = Timestamp.Now + TimeToLive`. A TTL of `0x80000001` therefore dated
the record's expiry 68 years out, and `0xFFFFFFFF` 136.

That is not a cosmetic over-read, because `EndOfLife` is exactly what
`DNSCache` expires on. The lookup path keeps `Where(rr => rr.EndOfLife > now)`,
and the sweep that clears the cache removes only entries whose `EndOfLife` has
already passed. A record admitted with the sign bit set is not merely long-lived;
it is unreachable by the eviction path for as long as the process runs. One
answer — from a misconfigured upstream, or from an attacker who won the race the
ID and port randomness of *RFC 5452 §9.2* is there to make hard — became
permanent.

**Transmitting**, both serializers capped the TTL with
`Math.Min(TimeToLive.TotalSeconds, UInt32.MaxValue)`. The intent is plainly
overflow protection, and the bound is one bit too generous: it permits exactly
the encoding §8 forbids. Anything above 2^31-1 seconds held in memory — from a
zone file, or from a caller who set a `TimeSpan` directly — went onto the wire
with the sign bit set.

**The trap, checked rather than assumed.** *RFC 6891 §6.1.3* reuses the same four
octets in an OPT record for something that is not a TTL at all: extended RCODE in
the high byte, then version, then flags. The sign bit there is RCODE bit 11, and
an extended RCODE of `0x80` — a combined RCODE of 2048, well inside the 12-bit
space — has it set. A clamp applied in the wrong place would silently erase it.
`OPT` turns out to read CLASS and TTL itself and to set `TimeToLive` to zero, so
the base constructor is never involved; the fix could go where it belongs.

**Fix.** `ReceivedTimeToLive` returns zero when the sign bit is set and the value
untouched otherwise, and the two serializers now cap at `MaximumTimeToLive`
(2147483647). The other freedom §8 grants in the next sentence — implementations
are "free to place an upper bound on any TTL received" — is a separate question
of policy and is deliberately not exercised.

Severity is **Medium**. No answer is wrong at the moment it arrives, and the
transmit half needs a TTL nobody authors by accident. What makes it more than
cosmetic is durability: the receive half turns a single bad answer into one that
outlives every mechanism meant to retire it.

**Why it stayed open, and what changed.** [README](README.md#rfc-coverage)
carried this as "receiver behavior is loosely specified — needs a defensible
reading", and the test printed the observed value while accepting either
outcome. The reading it was waiting for is that §8 says two different things and
only one of them is loose. The upper bound is genuinely a matter of taste and no
suite can judge it. The sign-bit sentence names exactly one value, zero, and the
lowercase "should" makes it a SHOULD-level finding — the same standing as
findings 35 through 37, which the suite already asserts.

Pinned by five tests, and the second one is what stops the cheapest wrong fix.
`Ttl_With_The_Sign_Bit_Set_Is_Read_As_Zero` walks four values from `0x80000000`
to `0xFFFFFFFF`; `Ttl_Below_The_Sign_Bit_Is_Read_Literally` walks five from zero
to `0x7FFFFFFF`, because "return zero always" satisfies the first table
completely. `A_Sign_Bit_Ttl_Does_Not_Become_An_Entry_That_Never_Expires` asserts
the consequence rather than the number, by looking at `EndOfLife`.
`Ttl_Is_Never_Transmitted_With_The_Sign_Bit_Set` reads the emitted field back
with RawDns and checks both that the bit is clear and that the value was capped
rather than wrapped. And
`An_Opt_Keeps_Its_Extended_Rcode_When_The_Ttl_Field_Has_The_Sign_Bit_Set` guards
the trap, so a later refactor that routes OPT through the base constructor fails
loudly instead of quietly losing an RCODE.

---

## 39 — The reserved CLASS wore the name of a different one

*RFC 6895 §3.2* is the CLASS registry. It puts QCLASS NONE at **254**, QCLASS *
at 255, and reserves **0**, which has no mnemonic at all.

`DNSQueryClasses` named 0 `NONE`. The doc comment on that line gave the game
away — "Pseudo class, used for DNS dynamic updates (RFC 2136)" describes QCLASS
NONE exactly, and *RFC 2136 §2.4* is where it is used to mean "no records of
this set". Only the number underneath it belonged to something else.

One wrong constant, two symptoms in opposite directions, both in the write half
of the presentation format:

| wire CLASS | Hermod wrote | RFC 6895 §3.2 + RFC 3597 §5 |
|---:|---|---|
| 0 | `NONE` | `CLASS0` — reserved, no mnemonic |
| 254 | `CLASS254` | `NONE` |

`ADNSResourceRecord.ClassName` asks `Enum.IsDefined`, so it faithfully reported
whatever the enum claimed: it invented a name for the reserved code point and
hid the real one behind RFC 3597 §5's generic form.

The second row is merely unidiomatic — `CLASS254` is a legal spelling of 254 and
every reader resolves it correctly. The first row is the one that leaves the
process: a zone file Hermod emitted for a class-0 record said `NONE`, and BIND,
Knot and anything else reading it get **254**. The record changes class on the
way across, silently, in the direction of a class that means something in a
dynamic update.

What kept it harmless so far is that nothing referred to it. The value had zero
uses in Hermod, and the zone-file *reader* is separately narrow — the `A` parser
accepts `IN` and rejects every other class with a typed exception, so the wrong
mnemonic never came back in. It was a loaded foot-gun rather than a wound, which
is also why it survived this long.

**Fix.** One line: `NONE` moved to 254, leaving 0 unnamed. Both symptoms are
downstream of the constant, so `Enum.IsDefined` now answers correctly in both
directions without `ClassName` being touched.

Severity is **Low**. No answer Hermod produces today is wrong, and reaching the
bug needs a caller who names the constant or a record that arrives in one of two
code points nothing sends.

**The rest of RFC 6895 was already right, and is now pinned.** The registries
are mostly a rule about what may *not* appear, so the round began by asking the
server for every interesting code point in both spaces. It answered all of them
correctly: TYPE 0, the meta-TYPEs, both obsolete mail QTYPEs and both transfer
QTYPEs each came back NOERROR with an empty answer section and the zone's SOA,
`*` was served with data records, and no response in the sweep ever carried a
Q/Meta code point as a record TYPE or CLASS. Those tests lock in behavior rather
than change it, which is worth saying plainly: only the CLASS constant moved.

Pinned by ten tests across two projects, twenty-eight cases in all. On the registry itself,
`Every_Mnemonic_Names_Its_Iana_Code_Point` checks each mnemonic against the
suite's own table rather than against the enum under test, and
`The_Class_Named_None_Is_254` and `Class_Zero_Is_Reserved_And_Carries_No_Mnemonic`
take the two rows above from the wire through `ClassName`.
`Registered_Classes_Render_As_Their_Mnemonics` and
`Unregistered_Classes_Render_Generically` are a pair on purpose: either alone is
satisfied by a `ClassName` that gives up and always answers one way, and the
mutation run confirmed it — dropping the `Enum.IsDefined` test in either
direction leaves exactly one of them green.

On the wire, `A_Qtype_Only_Code_Point_Is_Never_A_Record_Type` sweeps 251 through
255 and inspects every section,
`A_Query_For_A_Qtype_Only_Code_Point_Is_Answered_Without_Data` requires the SOA
that makes a NODATA answer meaningful, `An_Any_Query_Is_Answered_With_Data_Types`
stops the first one from being satisfied by a server that answers nothing at
all, `Type_Zero_Is_Never_Answered_With_Data` covers the code point §3.1 says must
never be allocated, and `A_Qclass_Only_Code_Point_Is_Never_A_Record_Class` does
the same for the class space.

A test whose job is to find nothing can pass by looking nowhere, so that one was
mutated too — putting SOA's code point into the forbidden list, which made
`A_Qtype_Only_Code_Point_Is_Never_A_Record_Type` fail. It reads the records.

---

## 40 — The one flag a refusal kept echoing

**The first finding this suite did not make.** It came from ISC's `genreport`,
the EDNS compliance battery behind dnsflagday, fired at Hermod from WSL — which
is the entire reason phase 7 exists. Every other entry here is Hermod measured
against *this* suite's reading of the RFCs. This one is Hermod measured against
somebody else's.

Of the roughly thirty probes in genreport's full grouping, one came back unhappy:

```
conformance.test. @… (ns1.conformance.test.): … opcodeflg=rd …
```

`opcodeflg` sends opcode 15 — unassigned — as a header-only request with every
flag bit set: AA, TC, RD, RA, AD, CD and Z. Measured directly, Hermod answered
NOTIMP, echoed the opcode, and cleared **every** one of those bits except RD.
The lone exception was deliberate: *RFC 1035 §4.1.1* says of RD that it "may be
set in a query and is copied into the response", and the copy was unconditional.

**The RFCs do not settle this, and it is worth being plain about that.** §4.1.1
attaches no opcode condition to the copy. *RFC 6895 §2* — the document that owns
the header — declines to help in either direction: the flags are "theoretically
meaningful only in queries or only in responses, depending on the bit", a
statement about direction and not about opcode, and it goes on to note that
implementations may copy query headers straight into responses. Read literally,
Hermod was right.

What decided it was everyone else. genreport's own source states the rule in a
comment — `/* RD is only defined for QUERY */` — and a survey with the same tool
found the field unanimous: ISC's own `ns1`, `ns2`, `ns3.isc.org` and
`ns.isc.afilias-nst.info` all pass the probe, so BIND clears the bit;
`nsp.dnsnode.net` fails it differently (`reset`); and every Cloudflare
nameserver tested simply drops the query. Not one echoed RD.

That last point is reproducible here rather than only observed in the wild:
BIND 9.20.26 serving the suite's own fixture zone in WSL, interrogated by the
same binary, returns `opcodeflg=ok` and an empty list under `-B`. Hermod now
matches it on every probe in the grouping.

The argument behind that consensus is the better reading. RD is defined as the
bit that "directs the name server to pursue the query recursively" — a property
of a QUERY. A response carrying NOTIMP has just said it did not understand the
request; echoing a bit whose meaning is owned by the opcode it refused claims
knowledge it does not have. And Hermod already agreed in practice, having
cleared the other six.

**Fix.** One clause where a refusal is built: RD is copied only when the opcode
is QUERY. All four refusal paths — BADVERS, NOTIMP, BADCOOKIE, FORMERR — share
that builder, and the three that keep opcode 0 are unaffected.

Severity is **Low**. Nothing is misanswered, and the bit reaches only a client
that sent an opcode no authoritative server implements.

**A guard that guarded nothing.** The pair here is
`A_Notimp_Response_Echoes_No_Flag_Of_The_Opcode_It_Rejected`, which asserts all
seven bits clear, and a counterpart that stops "never echo RD" from passing as
the fix. The counterpart was wrong on the first attempt: it sent an ordinary
query for a name that exists, which is answered on the success path and never
travels through the refusal builder at all. The mutation run caught it —
replacing the clause with a flat `false` left it green. It now asks for BADVERS
instead, by sending EDNS version 1, which is refused by *RFC 6891 §6.1.3* while
the opcode stays QUERY: the same builder, the same line, opcode 0. Both mutants
die now.

`The_Full_Battery_Diverges_Only_Where_It_Is_Known_To` kills the first mutant too,
which is the useful part: the external tool notices the regression on its own,
without being told what to look for.

---

## 41 — An authoritative "does not exist" for names it serves no zone for

The second finding from outside, and the second thing phase 7 caught that this
suite had not thought to ask. Zonemaster's report on the fixture zone
carried ten errors that are properties of a laboratory and one that is not:

```
ERROR   Nameserver ns1.conformance.test/… is a recursor.   [IS_A_RECURSOR]
```

The label is Zonemaster's inference rather than the defect. Measured directly,
Hermod does not recurse and does not offer to — `RecursionAvailable` is false
and RA stays clear. What it does is answer:

| query | RCODE | AA | authority |
|---|---|:--:|---|
| `a.conformance.test.` (served) | NOERROR | 1 | — |
| `nx.conformance.test.` (served, absent) | NXDOMAIN | 1 | SOA |
| `example.com.` | **NXDOMAIN** | **1** | **none** |
| `www.example.com.` | **NXDOMAIN** | **1** | **none** |
| `.` (the root) | **NXDOMAIN** | **1** | **none** |

For a name inside its zone the behaviour is exactly right, SOA and all. For a
name it serves no zone for, it claims authority — *RFC 1035 §4.1.1* defines AA
as denoting "that the responding name server is an authority for the domain name
in question section" — and then says the name does not exist. Zonemaster asks an
out-of-bailiwick name, sees an answer rather than a refusal, and concludes the
server answers for other people's names, which it does.

The consequence is worse than the label suggests. *RFC 8020* settles NXDOMAIN as
meaning there is nothing at that name **or beneath it**, and permits a resolver
to cache that for the whole subtree. An authoritative NXDOMAIN for
`example.com.` is therefore an assertion that example.com and everything under it
does not exist, offered with the authority bit set. The response also carries no
SOA, so it violates *RFC 2308 §3* as a negative answer besides — but that is the
lesser half.

The answer everything else gives is REFUSED. It is what BIND returns, and what
*RFC 1034 §4.3.2* leaves as the only honest outcome when step 2 finds no zone
whose apex is an ancestor of the name: there is nothing to search, so there is
nothing to report about.

**Fix.** The cause was a missing distinction rather than a wrong branch.
`DNSZoneLookupStatus` had `Found`, `NoData`, `NameError`, `Referral` and a DNAME
redirect, and no way to say "no zone here", so `InMemoryDNSZone` returned
`NameError` both for a name absent from its zone and for a name that was never
its business — and the handler mapped that one status to NXDOMAIN, rightly for
the first and not for the second. The zone already knew the difference: it tests
whether QNAME sits at or below its apex and, when it does not, used to fall
through to an exact-match search of its records. That branch now returns a new
`NotAuthoritative` status, which the handler answers REFUSED with AA clear —
but only when the store holds nothing for the name at all.

That last condition is not a nicety. `InMemoryDNSZone` is a record store with an
apex rather than a zone in the strict sense, and it will happily hold names
outside that apex; the fixtures depend on it, keeping a reverse-lookup PTR for
`42.2.0.192.in-addr.arpa.` beside a forward `conformance.test.`. Refusing every
out-of-apex name took that PTR away, and `dig` in WSL said so.

**And it very nearly broke DNAME.** The first attempt refused on the status
alone. That is wrong for a reason worth keeping: a DNAME rewrites the query into
another subtree, and the rewritten name is *supposed* to be out of bailiwick —
*RFC 6672 §2.2* has the synthesized CNAME returned and the resolver chase the
target from there. Refusing at that point turns a successful redirection into a
refusal of the question it just answered.
`A_Dname_Out_Of_The_Zone_Redirects_And_Stops` and
`A_Substitution_Of_Exactly_255_Octets_Still_Fits` both went red immediately, from
tests written for finding 24 and long before this one. REFUSED now applies only
when nothing was found at all, and the mutation that removes that condition is
killed by those same two tests.

Severity is **High**, on consequence rather than on how easily it is reached: a
resolver that ever asks this server about a name it does not serve is handed an
authoritative denial it may cache for an entire subtree.

Pinned by a pair. `A_Name_Outside_Every_Served_Zone_Is_Refused` walks
`example.com.`, `www.example.com.`, `com.` and the root, and checks the RCODE,
the AA bit, and that neither section carries anything.
`A_Name_Missing_Inside_A_Served_Zone_Is_Still_NXDOMAIN` is what stops "refuse
whatever was not found" from passing as the fix — inside the zone this server is
the authority, so an absent name is still an authoritative NXDOMAIN carrying the
SOA of *RFC 2308 §2.1*. Five mutants, all killed, and three of them by tests written for
something else entirely: one that refuses even a name the store holds is caught
by the `dig` PTR case, one that refuses on the status alone by the two DNAME
tests, and one that keeps AA set on the refusal by the AA assertion alone.

And the tag is gone from `ZonemasterUndelegatedTests`. Its recorded set is
asserted exactly, so the fix made that test fail until the entry was deleted —
which is the behaviour that list was built for.

---

## Interpretations

Current, not historical. Places where the RFC genuinely permits both readings,
so there is nothing to fix and nothing to close — the suite asserts the dominant
implementation behavior and records the choice here. Anything added to this list
stays on it.

**Forward compression pointers.** RFC 1035 §4.1.4 defines a pointer as referring
to "a prior occurrence of the same name". Hermod accepts forward pointers; the
suite's strict reference reader rejects them. Leniency on receive is a
defensible robustness choice and violates no MUST, so this is documented rather
than failed (`Forward_Pointers_Are_Not_Prior_Locations`).

**Compression is off by default.** `DNSServerOptions.UseCompression` defaults to
false. Compression is optional (RFC 1035 §4.1.4), so this is a size/CPU trade-off
rather than a conformance question — but it is the reason answer owner names come
back in the zone's capitalization rather than the query's.

**What a server answers a failed SIG(0).** RFC 2931 names no RCODE. §3.1 only
says servers are "not required to check a request SIG(0)" outside privileged
operations, and having decided to check, the specification offers nothing about
what to say when the check fails. Hermod answers NOTAUTH (9), which is what
RFC 8945 §5.2 prescribes for the same situation under TSIG and what BIND sends;
the refusal is unsigned, because a sender whose key was just rejected cannot
tell our signature from anyone else's. The tests assert this reading rather than
a requirement, and it is the one thing here another implementation could
reasonably differ on.

**RFC 8080 §6's examples carry a labels field their own owner name does not
justify.** The published RRSIG lines read `RRSIG MX 3 3600 …`, which is one field
short of the presentation format — the algorithm is missing and the 3 is the
labels. RFC 4034 §3.1.3 counts the labels of the owner name without the root,
making `example.com.` two; the signatures only reproduce with three. Since the
labels octet is inside the signed data, there is no reading under which both the
counting rule and the published signature can hold.

The suite reproduces the examples as they are rather than as they should be, and
says so at the call site. What the vectors are there to measure is the EdDSA
construction — PureEdDSA rather than the pre-hashed variant, an empty Ed448
context, the right canonical form underneath — and for that purpose the field
values only have to match whatever produced the signature. A test that "corrected"
the labels to 2 would be a different test, and a failing one.

**A message carrying both a TSIG and a SIG(0).** RFC 2931 §3.2 forbids the
combination — "either a single TSIG or one SIG(0) but not both" — and again
names no RCODE. Hermod answers FORMERR (1), reading it as a malformed message
rather than an unauthenticated one; NOTAUTH would be defensible too. What is
*not* defensible is serving it, which is why this is asserted at all: a server
that checks only the outermost record lets a sender attach a valid signature of
the kind that is checked and a decorative one of the kind that is not.

## Where the coverage ends

Capabilities Hermod does not claim are **not** findings, and they are no longer
listed here — keeping a second copy of the coverage boundary only guaranteed the
two would drift apart. One source now:
[README § RFC coverage](README.md#rfc-coverage), which says for each gap what is
missing and what is blocking it.
