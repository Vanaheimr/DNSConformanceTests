# Conformance Findings — Hermod DNS

Deviations this suite found in the Hermod DNS stack.

**Status: 15 findings — 9 fixed, 6 open.**
**281 tests · 273 pass · 8 red (each red test tracks one open finding).**

| Run | Tests | Result |
|-----|------:|-------:|
| Offline conformance | 220 | 212 ✅ / 8 ❌ tracked |
| WSL interop (dig, kdig, drill, BIND) | 38 | **38 ✅** |
| Online interop (Cloudflare, Google, Quad9) | 23 | **23 ✅** |

| # | Area | Severity | RFC | Status |
|---|------|----------|-----|--------|
| 1 | QNAME case not preserved | Low (SHOULD) | 1035 §2.3.3 | ✅ fixed |
| 2 | TXT/SPF: only the first character-string parsed | **High** | 1035 §3.3.14 | ✅ fixed |
| 3 | URI: target emitted as DNS labels | **High** | 7553 §4.5 | ✅ fixed |
| 4 | SVCB/HTTPS: RDATA parsing overruns RDLENGTH | **High** | 1035 §4.1.3, 9460 | ✅ fixed |
| 5 | Client aborts on the first non-matching UDP response | **High** | 5452 §4.2 | ✅ fixed |
| 6 | Server omits OPT; no BADVERS | Medium | 6891 §6.1.1, §6.1.3 | ✅ fixed |
| 7 | Server never truncates oversized UDP responses | **High** | 1035 §4.2.1 | ✅ fixed |
| 8 | Unparseable requests silently dropped | Low | 1035 §4.1.1 | ✅ fixed |
| 9 | Name compression: suffix table never matched | Medium | 1035 §4.1.4 | ✅ fixed |
| 10 | Wildcard-expanded RRsets fail DNSSEC validation | **High** | 4035 §5.3.2 | ❌ open |
| 11 | Wildcard owner names cannot be represented | Medium | 4592 §2 | ❌ open |
| 12 | Revoked KSK is not removed from the trust anchors | **High** | 5011 §2.1 | ❌ open |
| 13 | Server ignores the CNAME rule | **High** | 1034 §4.3.2 | ❌ open |
| 14 | NODATA answers are never served from the cache | Medium | 2308 §5 | ❌ open |
| 15 | Negative TTL ignores the SOA MINIMUM | Medium | 2308 §4 | ❌ open |

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

---

# Fixed

## 1 — Query names were lowercased before reaching the wire ✅

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

## 9 — Name compression: the suffix table could never match ✅

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

## 2 — TXT/SPF: only the first character-string was parsed ✅

*RFC 1035 §3.3.14:* "TXT-DATA: One or more `<character-string>`s."
*RFC 7208 §3.3:* they are concatenated.

`TXT(Stream)` called `ExtractCharacterString` once, so any TXT above 255 bytes
was truncated on read — precisely the population (DKIM keys, long SPF policies,
DMARC) that exceeds 255 bytes. Serialization was already correct, so Hermod
could emit a record it could not read back.

`SPF` was worse: it decoded its text with `DNSTools.ExtractName`, the *domain
name* parser, so any `.` in a policy became a label boundary.

**Fix.** Added `DNSTools.ExtractCharacterStrings(Stream, RDLength)`, which reads
exactly RDLENGTH octets as a sequence of character-strings. `TXT` and `SPF` both
use it and concatenate the result.

Verified by `TXT_MultiString_Rdata_Is_Fully_Parsed`,
`TXT_MultiString_Parsing_Leaves_Stream_At_Rdata_End`, and — against real BIND
output — `Hermod_Handles_A_MultiString_Txt_From_Bind`.

## 3 — URI: target was emitted as DNS labels ✅

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

## 4 — SVCB/HTTPS: SvcParam loop ran past its own RDATA ✅

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

## 5 — A single spoofed datagram killed the pending query ✅

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

## 6 — Server omitted OPT and never answered BADVERS ✅

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

## 7 — Server never truncated oversized UDP responses ✅

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

## 8 — Unparseable requests were dropped instead of answered FORMERR ✅

*RFC 1035 §4.1.1:* RCODE 1 means "the name server was unable to interpret the
query."

A request truncated mid-name produced no reply at all. A client cannot
distinguish "malformed request" from "server down", and retries blindly.

**Fix.** The UDP parse is now its own `try`; on failure the server builds a
minimal FORMERR from the first two octets and replies. Two guards keep this
safe: datagrams under 12 bytes are ignored, and anything with QR already set is
never answered, so two servers cannot ping-pong error replies.

Verified by `Truncated_Request_Does_Not_Break_The_Server`.

---

# Open

## 10 — Wildcard-expanded RRsets fail validation ❌

*RFC 4035 §5.3.2:* if the RRSIG's Labels field is less than the number of labels
in the RRset's owner name, the RRset was synthesized from a wildcard, and the
validator must rebuild the signed data using `*.` followed by the rightmost
`Labels` labels — not the expanded name.

`DNSSECValidator.BuildSignedData` always uses `rr.DomainName.FullName`. For an
answer at `anything.wild.example.` covered by the signature over
`*.wild.example.`, it therefore hashes a name no signer ever signed, and the
result is **Bogus**.

Wildcards are not an edge case — they are how most of the DNS serves catch-all
subdomains. A validating client would reject all of it. The failure is
fail-closed, so it denies rather than admits, but it denies correctly-signed data.

Reproduced against a signature made by BIND's `dnssec-signzone`:
`Wildcard_Expanded_Rrset_Validates`. The Labels field itself is read correctly —
`Wildcard_Rrsig_Has_Fewer_Labels_Than_Its_Owner` passes — so only the
reconstruction step is missing.

## 11 — Wildcard owner names cannot be represented ❌

*RFC 4592 §2:* `*` is an ordinary label as far as the wire format is concerned.

`DomainName.Parse("*.wild.example")` throws: the regex requires a label to start
with a letter or digit. Wildcard owner names do appear in responses — the NSEC
and RRSIG records that prove a wildcard match carry them — so a record that a
signer legitimately produced cannot be read back.

This is why the suite's fixture loader has to substitute a parseable owner to
reach the wildcard signature at all (`SignedZoneFixture.WildcardSignature`).

Pinned by `Wildcard_Owner_Names_Cannot_Be_Represented`. Note the fix belongs
only on the *owner name* path: a wildcard is never a valid hostname, so
`DomainName.Parse` should not accept it everywhere.

## 12 — A revoked KSK is never removed from the trust anchors ❌

*RFC 5011 §2.1:* once a resolver sees a trust-anchor key republished with the
REVOKE bit set, it must stop treating that key as a trust anchor.

`ProbeForTrustAnchorUpdatesAsync` matches the revoked key against the stored
anchors by key tag. But the key tag is a checksum over the whole DNSKEY RDATA,
**including the Flags field** — so setting REVOKE changes it. The tag computed
from the revoked key can never equal the tag stored when the key was live, the
`RemoveAll` matches nothing, and the revocation is silently ignored.

This one fails *open*: a key the zone operator has explicitly announced as
compromised stays trusted indefinitely. That is the exact scenario RFC 5011's
revocation mechanism exists to handle.

Reproduced by `Revoked_Ksk_Is_Removed_From_The_Trust_Anchors`, which first
asserts the premise (`ComputeKeyTag(revoked) != ComputeKeyTag(live)`) so the
cause is unambiguous. The fix is to match on the public key, or to recompute the
tag with REVOKE cleared before comparing.

The rest of RFC 5011 is correct: the 30-day hold-down, the refusal to trust a
key on first sight, and the requirement that a pending key be seen continuously
all pass.

## 13 — The authoritative server ignores the CNAME rule ❌

*RFC 1034 §4.3.2 step 3a:* when the queried node holds a CNAME and QTYPE is not
CNAME, the server copies the CNAME into the answer section and restarts the
query at the canonical name.

`AuthoritativeDNSRequestHandler` matches on owner **and** type, so an alias
answers only a `QTYPE=CNAME` query. Asking for `A` at a name that is a CNAME
returns **NOERROR with an empty answer** — NODATA. A resolver reads that as
"this name exists and definitively has no A record" and caches it.

So aliases work only for clients that already know they are aliases, which is
none of them. This is the most user-visible of the open findings: the zone looks
correct, `dig CNAME` confirms it, and ordinary lookups return nothing.

Reproduced by `Query_For_A_At_An_Alias_Returns_The_Cname`,
`Unknown_Type_At_An_Alias_Still_Returns_The_Cname` and
`Chained_Alias_Resolves_Or_Refers`. RFC 2181 §10.1 (no other data may coexist
with a CNAME) is *not* violated — `Alias_Node_Carries_No_Data_Of_Its_Own` passes.

Note this is a server-side gap only. `DNSClient` chases CNAME and DNAME chains
correctly, which is why the live interop tests against public resolvers pass.

## 14 — NODATA answers are never served from the cache ❌

*RFC 2308 §5:* negative answers, both NXDOMAIN and NODATA, are to be cached.

NXDOMAIN is cached correctly — a repeated query does not reach the wire. NODATA
is not: two identical queries produce two requests, every time.

The code path exists (`DNSClient` computes a `noDataTTL` and calls
`DNSCache.AddNoData` per type) and the SOA does arrive and parse — the test
asserts that as a precondition, so this is not the suite feeding Hermod a
malformed authority section. Something between storing and looking up the entry
does not line up; the mechanism has not been traced further.

NODATA is the common case for AAAA lookups on IPv4-only names, so this is a
steady multiplier on outbound query volume rather than a correctness bug.

Reproduced by `Repeated_Nodata_Query_Is_Served_From_The_Cache`.

## 15 — The negative TTL ignores the SOA MINIMUM ❌

*RFC 2308 §4:* the TTL of a negative answer is the SOA's **MINIMUM field**,
capped by the SOA record's own TTL.

Two problems. Where the SOA is consulted at all, `DNSClient` reads
`soa.TimeToLive` — the record's TTL — and never looks at the MINIMUM field that
RFC 2308 repurposed for exactly this. And on the NXDOMAIN path the SOA is not
consulted at all: `AddToCache` is called with the response and left to apply its
own default.

Measured: a negative answer whose SOA MINIMUM is 1 second is still cached three
seconds later.

Reproduced by `Negative_Answer_Expires_After_The_Soa_Minimum`.

---

## Interpretations

**Forward compression pointers.** RFC 1035 §4.1.4 defines a pointer as referring
to "a prior occurrence of the same name". Hermod accepts forward pointers; the
suite's strict reference reader rejects them. Leniency on receive is a
defensible robustness choice and violates no MUST, so this is documented rather
than failed (`Forward_Pointers_Are_Not_Prior_Locations`).

**TTLs with the high bit set.** RFC 2181 §8 says such a TTL "should be treated as
if the entire value received was zero". The test accepts either the clamp or the
literal value and prints what happened.

**DoH transaction IDs.** RFC 8484 §4.1 says clients SHOULD use ID 0 for cache
friendliness. Hermod uses random IDs. Measured and reported only.

**Compression is off by default.** `DNSServerOptions.UseCompression` defaults to
false. Compression is optional (RFC 1035 §4.1.4), so this is a size/CPU trade-off
rather than a conformance question — but it is the reason answer owner names come
back in the zone's capitalization rather than the query's.

## Not implemented in Hermod

Not deviations — capabilities the stack does not claim, recorded so the coverage
matrix does not imply they were tested.

- **NSEC3 hashing.** NSEC3 and NSEC3PARAM records parse and serialize, but there
  is no hash function, so RFC 5155 Appendix A's published vectors have nothing to
  measure and denial-of-existence proofs cannot be validated.
- **Ed25519/Ed448 signing fixtures.** Verification exists (algorithms 15 and 16);
  the suite has no signed fixture for them, because generating one honestly needs
  BIND support rather than a constant transcribed from RFC 8080.
- **DoH server, AXFR/IXFR, RFC 2136 dynamic update.**
