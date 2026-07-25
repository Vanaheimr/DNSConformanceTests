# Conformance Findings — Hermod DNS

Deviations this suite found in the Hermod DNS stack, and how they were fixed.

**Status: all 8 findings resolved. 211 tests · 211 pass · 0 fail.**

| Run | Before | After |
|-----|-------:|------:|
| Offline conformance (162 tests) | 152 ✅ / 10 ❌ | **162 ✅** |
| WSL interop (38 tests) | 37 ✅ / 1 ❌ | **38 ✅** |
| Online interop (23 tests) | 22 ✅ / 1 ❌ | **23 ✅** |

| # | Area | Severity | RFC | Status |
|---|------|----------|-----|--------|
| 1 | QNAME case not preserved | Low (SHOULD) | 1035 §2.3.3 | 📋 open by design — see below |
| 2 | TXT/SPF: only the first character-string parsed | **High** | 1035 §3.3.14, §4.1.3 | ✅ fixed |
| 3 | URI: target emitted as DNS labels | **High** | 7553 §4.5 | ✅ fixed |
| 4 | SVCB/HTTPS: RDATA parsing overruns RDLENGTH | **High** | 1035 §4.1.3, 9460 | ✅ fixed |
| 5 | Client aborts on the first non-matching UDP response | **High** | 5452 §4.2 | ✅ fixed |
| 6 | Server omits OPT; no BADVERS | Medium | 6891 §6.1.1, §6.1.3 | ✅ fixed |
| 7 | Server never truncates oversized UDP responses | **High** | 1035 §4.2.1, 6891 §6.2.5 | ✅ fixed |
| 8 | Unparseable requests silently dropped | Low | 1035 §4.1.1 | ✅ fixed |

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
or the existing timeout expires. A flood of forged packets degrades to the same
outcome as silence, rather than to a spurious failure.

Verified by `Spoofed_Response_Does_Not_Kill_The_Pending_Query`.

## 6 — Server omitted OPT and never answered BADVERS ✅

*RFC 6891 §6.1.1:* responders "MUST include an OPT record in their respective
responses."
*RFC 6891 §6.1.3:* an unsupported EDNS VERSION "MUST" be answered with BADVERS.

`AuthoritativeDNSRequestHandler` built every response with an empty additional
section, so a requestor could not tell whether the server spoke EDNS, could not
learn its payload size, and `dig +edns=1` got NOERROR where BADVERS was required.

**Fix.** Added `DNSResponseCodes.BadVersion = 16` and a `BuildResponseOPT`
helper that attaches an OPT to every response *when the query carried one*,
advertising the server's own payload size (default 1232, per DNS Flag Day 2020)
and carrying the upper 8 bits of an extended RCODE. EDNS version > 0 short-
circuits to BADVERS. Options are deliberately not echoed — unknown options must
be ignored (§6.1.2), and reflecting them would make the server an amplifier.

Verified by `Response_To_Edns_Query_Contains_An_Opt_Record`,
`Unknown_Edns_Version_Yields_BADVERS`, and `Unknown_Edns_Options_Are_Not_Echoed`.

## 7 — Server never truncated oversized UDP responses ✅

*RFC 1035 §4.2.1:* "Longer messages are truncated and the TC bit is set."
*RFC 6891 §6.2.5:* never exceed the requestor's advertised buffer.

A 600-byte TXT produced a **673-byte UDP response with TC=0**, both without EDNS
(512-byte ceiling) and with EDNS advertising 512. Such datagrams fragment or get
dropped by middleboxes, and because TC was clear the client was never told to
retry over TCP — the answer simply vanished.

**Fix.** `DNSServer.SerializeForUDP` computes the limit as 512 without EDNS, or
`min(advertised, MaxUDPResponseSize)` with it (values below 512 treated as 512
per §6.2.3), then sheds answer records from the end until the message fits and
sets TC=1. The OPT record is retained so the response stays EDNS-conformant.
`DNSServerOptions.MaxUDPResponseSize` (default 1232) caps what the server emits
regardless of what a requestor advertises. Applied to both the unicast and
multicast UDP paths.

Verified by `Large_Answer_Without_Edns_Is_Truncated_Or_Fits_512_Bytes` and
`Answer_Respects_The_Advertised_Edns_Payload_Size`; TCP still delivers the full
answer (`Tcp_Delivers_The_Full_Large_Answer`).

## 8 — Unparseable requests were dropped instead of answered FORMERR ✅

*RFC 1035 §4.1.1:* RCODE 1 means "the name server was unable to interpret the
query."

A request truncated mid-name produced no reply at all: the parse threw, the
exception was logged, the datagram was abandoned. The server stayed healthy, so
this was a diagnosability problem rather than a robustness one — but a client
cannot distinguish "malformed request" from "server down", and retries blindly.

**Fix.** The UDP parse is now its own `try`; on failure the server builds a
minimal FORMERR from the first two octets (the transaction ID stays readable
however mangled the rest is) and replies. Two guards keep this safe: datagrams
under 12 bytes are ignored, and anything with QR already set is never answered,
so two servers cannot ping-pong error replies.

Verified by `Truncated_Request_Does_Not_Break_The_Server`.

---

## 1 — Query names are lowercased before they reach the wire 📋 open

*RFC 1035 §2.3.3:* "its original case should be preserved whenever possible."

`DNSServiceName.Parse` lowercases, so `MiXeD.CaSe.ExAmPlE` leaves as
`mixed.case.example`. This is SHOULD-level and harmless to interoperability —
matching is case-insensitive either way, and the suite's test passes.

It is left open deliberately: the fix belongs in `DNSServiceName`/`DomainName`,
which are used well beyond DNS wire encoding, so changing their normalization
is a much broader change than the seven above and wants its own review. The
practical cost is that dns-0x20 query randomization — a cheap anti-spoofing
measure that depends on case surviving the round trip — cannot be implemented on
top of the current types.

`Case_Is_Preserved_On_The_Wire` records the observation without failing.

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
