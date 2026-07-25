# Conformance Findings — Hermod DNS

Results of the first full run of this suite (2026-07-25) against the Hermod
submodule revision checked out under `libs/Hermod`.

**211 tests · 199 pass · 12 fail.** Every failure below is a reproducible
deviation from a normative RFC requirement, not a suite defect. Each is
tagged `[Category("KnownIssue")]` so dashboards can separate "known" from
"new" red.

Filter them out with:

```bash
dotnet test DNSConformanceTests.slnx --filter "TestCategory!=KnownIssue"
```

| # | Area | Severity | RFC | Tests |
|---|------|----------|-----|-------|
| 1 | QNAME case not preserved | Low (SHOULD) | 1035 §2.3.3 | 1 (reported, not failing) |
| 2 | TXT: only the first character-string is parsed | **High** | 1035 §3.3.14, §4.1.3 | 3 |
| 3 | URI: target emitted as DNS labels | **High** | 7553 §4.5 | 1 |
| 4 | SVCB/HTTPS: RDATA parsing overruns RDLENGTH | **High** | 1035 §4.1.3, 9460 | 2 |
| 5 | Client aborts on the first non-matching UDP response | **High** | 5452 §4.2 | 1 |
| 6 | Server omits OPT; no BADVERS | Medium | 6891 §6.1.1, §6.1.3 | 2 |
| 7 | Server never truncates oversized UDP responses | **High** | 1035 §4.2.1, 6891 §6.2.5 | 2 |
| 8 | Unparseable requests silently dropped | Low | 1035 §4.1.1 | 1 |

---

## 1 — Query names are lowercased before they reach the wire

*RFC 1035 §2.3.3:* "When data enters the domain system, its original case
should be preserved whenever possible."

`DNSServiceName.Parse` lowercases, so a query for `MiXeD.CaSe.ExAmPlE`
leaves as `mixed.case.example`. SHOULD-level, so the test reports rather than
fails — but it also forecloses dns-0x20 query randomization, a cheap
anti-spoofing measure that depends on case surviving the round trip.

Test: `WireFormat.NameEncodingTests.Case_Is_Preserved_On_The_Wire` (passes,
prints the observation).

## 2 — TXT records: only the first character-string is read

*RFC 1035 §3.3.14:* "TXT-DATA: One or more `<character-string>`s."
*RFC 7208 §3.3* requires the strings be concatenated.

`TXT(Stream)` calls `DNSTools.ExtractCharacterString` **once**
([TXT.cs:112](libs/Hermod/Hermod/DNS/ResourceRecords/TXT.cs:112)), while
`SerializeRRData` correctly writes as many 255-byte chunks as needed. So
Hermod can emit a record it cannot read back.

Two consequences:

1. **Data loss** — any TXT above 255 bytes is truncated on read. This hits
   DKIM keys, long SPF policies and DMARC records, which is precisely the
   population of TXT records that exceeds 255 bytes.
2. **Stream desynchronization** — the parser consumes less than RDLENGTH, so
   every record *after* the TXT in the same message is misparsed. RFC 1035
   §4.1.3 makes RDLENGTH authoritative for the RDATA extent.

Suggested fix: read repeatedly until RDLENGTH bytes are consumed
(`DNSTools.ExtractCharacterStrings` already exists and does exactly this),
and concatenate.

Tests:
- `ResourceRecords.TextAndPolicyRecordTests.TXT_MultiString_Rdata_Is_Fully_Parsed`
- `ResourceRecords.TextAndPolicyRecordTests.TXT_MultiString_Parsing_Leaves_Stream_At_Rdata_End`
- `ExternalServers.BindServerInteropTests.Hermod_Handles_A_MultiString_Txt_From_Bind` (against real BIND)

## 3 — URI target is serialized as DNS labels

*RFC 7553 §4.5:* the Target field is "the URI of the target, enclosed in
double-quote characters … in its presentation format" and on the wire it is
simply "the remaining octets of the RDATA" — **not** a domain name, and not a
character-string.

Hermod writes it through the domain-name encoder, so
`https://www.example.com/path` becomes length-prefixed labels
(`0b https://www 07 example 08 com/path 00`) instead of the raw 28 octets.
Any other implementation reads garbage.

Test: `ResourceRecords.TextAndPolicyRecordTests.URI_Target_Is_The_Remaining_Rdata_Octets`

## 4 — SVCB/HTTPS parsing runs past the end of its own RDATA

*RFC 1035 §4.1.3:* RDLENGTH "specifies the length in octets of the RDATA
field."

`HTTPS(DomainName, Stream)` reads RDLENGTH and then ignores it, looping
`while (true)` over SvcParams until the **stream** ends
([HTTPS.cs](libs/Hermod/Hermod/DNS/ResourceRecords/HTTPS.cs)). Whenever the
record is not the last thing in the message, it swallows whatever follows.

This is not theoretical. A live query to 1.1.1.1 for `cloudflare.com/HTTPS`
returns a valid answer that `dig` renders without complaint; Hermod returns
**SERVFAIL with zero answers**, because the HTTPS record is followed by the
OPT record, whose bytes get eaten as bogus SvcParams and then blow up the
outer record loop.

The same shape applies to `SVCB`.

Suggested fix: bound the SvcParam loop by the RDLENGTH already read.

Tests:
- `ResourceRecords.SecurityAndBinaryRecordTests.Https_Record_Followed_By_Another_Record_Does_Not_Overrun` (offline reproduction)
- `PublicResolvers.PublicResolverTests.Https_Svcb_Records_Resolve_In_The_Wild` (live)

## 5 — A single spoofed datagram kills the pending query

*RFC 5452 §4.2:* a resolver "MUST ignore" responses that do not match the
outstanding query.

Hermod correctly refuses to *accept* a response whose transaction ID does not
match — `DNSInfo.ReadResponse` returns `DNSInfo.Invalid`. But "ignore" is
implemented as "give up": the client performs a single `ReceiveAsync` and
treats whatever arrives as the answer, so the first datagram to reach the
socket ends the query even when it is rejected. The genuine response that
arrives microseconds later is never read.

That inverts the intent of the requirement: instead of shrugging off forged
packets, any off-path attacker who can land one datagram achieves a denial of
service, at far lower cost than a cache-poisoning race.

Suggested fix: loop on receive until a matching response arrives or the
timeout expires, discarding non-matching datagrams.

Test: `Client.UdpClientBehaviorTests.Spoofed_Response_Does_Not_Kill_The_Pending_Query`
(the forged answer is correctly rejected; the genuine one never surfaces)

## 6 — Server: responses to EDNS queries carry no OPT, and no BADVERS

*RFC 6891 §6.1.1:* responders "MUST include an OPT record in their respective
responses."
*RFC 6891 §6.1.3:* an unsupported EDNS VERSION "MUST" be answered with
BADVERS (extended RCODE 16).

`AuthoritativeDNSRequestHandler` builds every response with an empty
additional section, so:

- an EDNS query is answered without an OPT record — the requestor cannot tell
  whether the server is EDNS-capable, cannot learn its payload size, and DO/
  extended-RCODE signalling is unavailable;
- `dig +edns=1` receives NOERROR instead of BADVERS (observed combined RCODE
  0 where 16 is required).

This is exactly the battery the DNS flag day compliance tests probe.

Tests:
- `Server.ServerEdnsAndTruncationTests.Response_To_Edns_Query_Contains_An_Opt_Record`
- `Server.ServerEdnsAndTruncationTests.Unknown_Edns_Version_Yields_BADVERS`

## 7 — Server never truncates oversized UDP responses

*RFC 1035 §4.2.1:* "Messages carried by UDP are restricted to 512 bytes …
Longer messages are truncated and the TC bit is set in the header."
*RFC 6891 §6.2.5:* a responder must not exceed the requestor's advertised
payload size.

Observed: a query for a 600-byte TXT record produces a **673-byte UDP
response with TC=0** — both without EDNS (512-byte limit) and with EDNS
advertising 512. `DNSServer` serializes the full response and sends it
regardless of size.

Consequences: datagrams above the path MTU fragment or are dropped by
middleboxes, and clients are never told to retry over TCP — the answer simply
disappears for anyone who cannot receive an oversized datagram.

Suggested fix: measure the serialized response, and when it exceeds
min(advertised payload size, 512 without EDNS), drop answer records and set
TC=1.

Tests:
- `Server.ServerEdnsAndTruncationTests.Large_Answer_Without_Edns_Is_Truncated_Or_Fits_512_Bytes`
- `Server.ServerEdnsAndTruncationTests.Answer_Respects_The_Advertised_Edns_Payload_Size`

Note the same zone *is* served correctly over TCP
(`Tcp_Delivers_The_Full_Large_Answer` passes), so only the UDP size discipline
is missing.

## 8 — Unparseable requests are dropped instead of answered FORMERR

*RFC 1035 §4.1.1:* RCODE 1 (Format error) means "the name server was unable to
interpret the query."

A request whose question section is truncated mid-name produces no reply at
all: `DNSPacket.Parse` throws, the exception is logged, and the datagram is
abandoned. The server stays healthy (verified), so this is a politeness/
diagnosability issue rather than a robustness one — but a client cannot
distinguish "malformed" from "server down", and retries pointlessly.

Test: `Server.ServerRobustnessTests.Truncated_Request_Does_Not_Break_The_Server`

---

## What passed — the notable positives

These are worth recording because they are the hard parts, and they work:

- **DNSSEC is solid.** 18/18. Key tags for both IANA root KSKs (20326, 38696)
  computed exactly; the published root DS digest reproduced; and RRSIG
  verification succeeds against a zone signed by **BIND's `dnssec-signzone`**
  across SOA/NS/A/AAAA/MX/TXT/DNSKEY RRsets, including canonical ordering
  (reversed RRsets still validate) and correct rejection of tampered RDATA and
  wrong keys. A live `cloudflare.com` SOA RRSIG validates end-to-end.
- **Cross-implementation interop is clean.** 25/25 against GNU/Linux tooling:
  `dig`, Knot's `kdig` and ldns' `drill` all parse Hermod's server output, over
  UDP and TCP, with no structural warnings, and the three tools agree on the
  answer sets. `kdig +tls` completes a full **DNS-over-TLS** exchange with
  Hermod's DoT listener.
- **DoT and DoH clients are correct.** 11/11, including RFC 8484's unpadded
  base64url `?dns=` parameter, `application/dns-message` on both directions,
  and RFC 7858 TLS session reuse (3 queries → 1 handshake) with the
  certificate-validation hook honored on rejection.
- **Wire format and EDNS options.** 41/41 and 10/10: header bit positions,
  compression decoding (including the RFC 1035 §4.1.4 worked example, pointer
  loops rejected), name limits, and the typed EDNS options (Cookie, Client
  Subnet with correct prefix truncation, Padding, Extended DNS Errors).
- **Robustness.** The server survives random garbage, absurd section counts,
  compression-pointer loops and partial TCP messages, and keeps answering
  throughout.

## Interpretations

**Forward compression pointers.** RFC 1035 §4.1.4 defines a pointer as
referring to "a prior occurrence of the same name". Hermod accepts pointers
that point forward; the suite's strict reference reader rejects them. Being
lenient on receive is a defensible robustness choice and no MUST is violated,
so this is documented rather than failed
(`WireFormat.CompressionTests.Forward_Pointers_Are_Not_Prior_Locations`).

**TTLs with the high bit set.** RFC 2181 §8 says such a TTL "should be treated
as if the entire value received was zero". The test accepts either the clamp
or the literal value and prints what happened.

**DoH transaction IDs.** RFC 8484 §4.1 says clients SHOULD use ID 0 for cache
friendliness. Hermod uses random IDs. Measured and reported only.
