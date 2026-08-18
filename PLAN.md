# Hermod DNS Conformance & Interoperability Test Suite — Plan

Goal: an independent .NET 10 test solution that measures **Vanaheimr Hermod**'s DNS
client and server implementation against the DNS RFCs, and validates it against
real-world implementations (BIND, Knot, ldns, public resolvers).

The suite lives *outside* the Hermod repository (Hermod and Styx are consumed as
git submodules under `libs/`) so it can evolve independently, act as an
unbiased referee, and be run against any Hermod revision.

---

## 1. Guiding principles

1. **Never test Hermod with Hermod.** Every conformance assertion is checked
   against an *independent reference*: a minimal hand-written wire codec
   (`RawDns` in `DNSConformance.Core`), byte vectors taken from RFC examples,
   fixtures produced by BIND's signing tools, or the behavior of well-known
   implementations (dig/kdig/delv/drill, public resolvers).
2. **Conformance failures are results, not test bugs.** When Hermod deviates
   from an RFC "MUST", the test stays red and the deviation is recorded in
   `FINDINGS.md` with RFC chapter & verse. The suite is the report.
3. **Offline by default, graceful everywhere.** Tests that need the network,
   WSL, or Docker are tagged with NUnit categories and skip with a clear
   message (`Assert.Ignore`) when the prerequisite is missing.
4. **Every test names its law.** Tests carry `[Property("RFC", "…")]` and a
   comment quoting the requirement they encode, so a failure directly cites
   the specification.

---

## 2. What Hermod implements (inventory from code review)

| Area | Implementation |
|------|----------------|
| Message model | `DNSPacket` (+`DNSResponse`), `DNSQuestion`, `DNSInfo` (client view), `DomainName`/`DNSServiceName` (63-byte label / 255-byte name limits) |
| Wire codec | `DNSPacket.Serialize/ToByteArray` (optional name compression), `DNSPacket.Parse` (server-side request parsing), `DNSInfo.ReadResponse` (client-side, reflection-based RR registry), `DNSTools` (names, compression pointers with loop detection, character-strings) |
| Resource records | ~45 types: A, AAAA, NS, CNAME, DNAME, SOA, PTR, MX, TXT, SPF, HINFO, RP, AFSDB, LOC, SRV, NAPTR, URI, CAA, EUI48/64, TLSA, SMIMEA, CERT, SSHFP, OPENPGPKEY, DS, DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, CDS, CDNSKEY, CSYNC, ZONEMD, SVCB, HTTPS, OPT, TSIG, TKEY, KEY — each with wire parse/serialize, zone-file presentation (`ToZoneFileString`, `ParseZoneFileString`), and DoH-JSON parsing |
| EDNS0 | OPT pseudo-RR (payload size, ext-RCODE, version, DO bit), typed options: Client Subnet (7871), Cookie (7873), TCP Keepalive (7828), Padding (7830), Extended DNS Errors (8914); extended-RCODE combining on receive |
| Client transports | `DNSUDPClient` (with TCP fallback on TC), `DNSTCPClient`, `DNSTLSClient` (DoT, custom cert validation), `DNSHTTPSClient` (DoH: GET base64url, POST binary, Google/Cloudflare JSON; plain-HTTP test modes) |
| Client orchestration | `DNSClient`: multi-server race, SERVFAIL retry, pooling, positive cache, NODATA negative cache (2308), aggressive NSEC cache (8198), CNAME/DNAME chasing with loop detection (6672), auto DNS Cookies, auto Client Subnet, DNSSEC validation hook |
| Server | `DNSServer`: UDP unicast + multicast, TCP, **TLS (DoT server)**; `AuthoritativeDNSRequestHandler` + `InMemoryDNSZone` (`Add/Set/Remove/AddZoneFileString`); opcode≠0 → NOTIMP, zero questions → FORMERR, NXDOMAIN vs NODATA |
| Zone | `InMemoryDNSZone` is a zone once it holds an SOA: apex-aware, RFC 1034 §4.3.2 lookup with delegations as referrals, empty non-terminals, RFC 4592 wildcard synthesis, SOA cited on every negative answer (2308 §3). Given a pre-signed zone it also serves it — RRSIGs and NSEC/NSEC3 proofs selected per RFC 4035 §3.1 and RFC 5155 §7, gated on the DO bit. It does not *sign*: `ZoneDenialOfExistence` selects, never invents |
| DNSSEC | `DNSSECValidator`: `ValidateRRSig` (RFC 4034 §3), `VerifyDS` (§5, SHA-1/256/384), `ComputeKeyTag` (App. B), chain-of-trust walk, IANA root trust anchor (KeyTag 20326), RFC 5011 rollover with hold-down. `DNSSECSigning` is the other direction — signatures and public-key encodings for algorithms 8, 10, 13 and 14 |
| Transaction security | `TSIGSigner` (RFC 8945, shared secret) and `SIG0Signer` (RFC 2931, public key) over wire bytes, both wired into `DNSServer` (UDP and TCP listeners, `TSIGKeys` / `SIG0Keys` / `SIG0ResponseKey`) and `DNSUDPClient` (query *and* TCP retry); `TKEYExchange` for the Diffie-Hellman mode of RFC 2930 |
| Not present | DoH **server** (client only), zone transfer (AXFR/IXFR), dynamic update (RFC 2136) |

### Deviations found, and their fate

The suite has confirmed twenty deviations so far, and all of them are now fixed
in Hermod. They are not restated here — [FINDINGS.md](FINDINGS.md) is the single
record, with chapter and verse, the mechanism, the change, and the test that
pins each one. The summary table at the top of that file is the fastest way in.

One review suspicion did *not* survive contact with a test: the compression-offset
bookkeeping produces messages that decode correctly under the suite's strict
reader, including multi-record shared-suffix cases
(`Compressed_Response_With_Many_Shared_Suffix_Names_Stays_Valid`).

A second one was dismissed too early, and is worth keeping as a caution. This
plan used to record that `DNSPacket.Parse` handling only A and OPT in request
sections "turned out not to matter for well-formed queries, whose question
section carries no RRs". The reasoning was sound and the conclusion was wrong:
a *query* carries no records, but a signed one does, and the first TSIG request
Hermod ever received made the parser throw and the server answer FORMERR. It
became finding 16. The lesson is not that the review was careless — it is that
"no caller does this today" is an observation about callers, not about the code.

---

## 3. Test taxonomy — four layers

### Layer 1 — Protocol conformance (offline, pure)
Byte-level checks of encoding/decoding against RFC wire formats using the
independent `RawDns` codec and RFC-published vectors. No sockets.

### Layer 2 — Behavioral conformance (offline, loopback sockets)
Hermod client ⇄ scripted fake servers (raw UDP/TCP/TLS/HTTP listeners that
replay hand-crafted bytes), and raw socket clients ⇄ real Hermod `DNSServer`.
Verifies protocol *behavior*: retries, TCP fallback, framing, RCODEs,
truncation, EDNS negotiation, robustness against malformed input.

### Layer 3 — Interoperability (WSL / network)
* GNU/Linux tools (dig, kdig, delv, drill — installed in WSL Debian) querying
  the Hermod server running on Windows.
* BIND `named` (WSL) serving fixture zones — Hermod client queries it.
* Public resolvers (Cloudflare, Google, Quad9) over Do53/DoT/DoH, DNSSEC
  domains with known validity (signed / deliberately broken).
* BIND `dnssec-signzone`-produced signed zones as DNSSEC fixtures; `delv`
  validating Hermod-served signed data against a fixture trust anchor.

### Layer 4 — External conformance suites (optional, documented)
* ISC **DNS Compliance Testing** (`genreport`) against the Hermod server —
  EDNS compliance battery (dnsflagday). Provided as a script; requires
  network build of the tool.
* **Zonemaster** in undelegated mode against a Hermod-served zone (Docker;
  currently no Docker daemon on this machine — configs are committed, tests
  skip).

---

## 4. RFC coverage matrix

Focus column = what the suite asserts. Status legend:

| | meaning |
|---|---|
| ✅ | implemented **and** verified by a passing test |
| ❌ | implemented and tested — **test fails**: a confirmed Hermod deviation, see [FINDINGS.md](FINDINGS.md) |
| 🟡 | partially covered — the basics are tested, edge cases are not yet |
| ⬜ | planned, not implemented yet |
| 📋 | tested, but reported as an observation rather than asserted (SHOULD-level or genuinely ambiguous) |

Counts as of the 2026-08-13 run: **718 tests, 705 ✅, 0 ❌, 13 skipped** — 646
offline, 23 online and 36 interop verified on that run; the 13 tests needing
BIND as a peer skip without it. All twenty-nine deviations the suite found are
fixed; see [FINDINGS.md](FINDINGS.md).

### 4.1 Core message & wire format (`DNSConformance.WireFormat.Tests`)

| RFC | Topic | Focus | Status |
|-----|-------|-------|:--:|
| 1035 §4.1.1 | Header layout | golden bytes: ID, QR, Opcode, AA, TC, RD, RA, Z, RCODE bit positions; section counts | ✅ |
| 1035 §4.1.2 | Question | QNAME/QTYPE/QCLASS encoding, round-trip | ✅ |
| 1035 §3.1 | Name encoding | root name, single/max label (63), max name (255), rejection of oversize | ✅ |
| 1035 §4.1.4 | Compression | decode pointer chains (incl. RFC's F.ISI.ARPA example layout), pointer loops rejected, forward pointers, encode-side pointer correctness (decode with RawDns) | ✅ |
| 1035 §2.3.3 | Case | original case preserved byte-exactly on the wire | ✅ |
| 4343 | Case-insensitive identity | names differing only in case are equal, hash alike and order alike | ✅ |
| 1035 §4.1.4 | Compression (encode) | shared suffixes actually emit pointers; repeated labels resolve correctly; mixed case compresses against its lowercase twin | ✅ |
| 2181 §8 | TTLs | TTL is 31-bit ✅; MSB-set TTL handling | 📋 |
| 3597 §2 | Unknown RR types | an unknown type is kept as opaque data in requests ✅ (findings 16, 21) and in responses, without costing the records behind it ✅ (finding 21) | ✅ |
| 3597 §4 | RDATA compression | the eleven post-1035 types no longer compress the names in their RDATA ✅ (finding 22); the five RFC 1035 types still do | ✅ |
| 3597 §5 | Presentation format | `\#` generic RDATA both ways, `TYPEnnn`/`CLASSnn`, a bare decimal is a TTL ✅ (finding 23), a known type written generically re-reads as that type | ✅ |
| 3597 §6 | Equality | unknown RDATA compared as octets, case sensitively | ✅ |
| 6895 | IANA registries | code points exercised throughout the RR tests; no dedicated assertion, so [README](README.md#rfc-coverage) does not list it as covered | 📋 |
| — | Robustness | empty/short/garbage messages, absurd section counts: typed failure, never a hang | ✅ |

### 4.2 Resource records (`DNSConformance.ResourceRecords.Tests`)

Per type: (a) wire round-trip through Hermod, (b) decode of a RawDns-built
golden RDATA, (c) re-encode equality, (d) zone-file presentation parse/print
round-trip where supported.

| RFC | Types | Notable edge cases | Status |
|-----|-------|--------------------|:--:|
| 1035 | A, NS, CNAME, SOA, PTR, MX, HINFO | SOA 32-bit serial/timers; MX preference; two-name and character-string RDATA | ✅ |
| 1035 §3.3.14 | TXT | multi-character-string RDATA (> 255 B), concatenated per RFC 7208 §3.3 | ✅ |
| 3596 | AAAA | full/compressed IPv6 forms | ✅ |
| 1183 | RP, AFSDB | two-name RDATA | ✅ |
| 1876 §2 | LOC | the scaled octet over all 256 values, the lat/lon 2^31 offset, the altitude reference at both extremes | ✅ |
| 1876 §2 | LOC version | an unrecognised version, or an undefined scaled octet, is written generically per RFC 3597 §5 ✅ (finding 29) | ✅ |
| 1876 §3 | LOC master file | size and both precisions survive a zone-file line ✅ (finding 28); the defaults apply only to omitted fields | ✅ |
| 2782 | SRV | priority/weight/port/target; no RDATA compression on emit | ✅ |
| 3403 | NAPTR | flags/service/regexp character-strings | ✅ |
| 4034 | DNSKEY, RRSIG, DS, NSEC | type bitmap windows (RFC 4034 §4.3 worked example, wire + zone-file), RRSIG field layout, DS digest lengths | ✅ |
| 5155 | NSEC3, NSEC3PARAM | salt, flags, iterations, next-hashed-owner | ✅ |
| 4255 | SSHFP | algorithm/fingerprint-type matrix | ✅ |
| 4398 | CERT | type/keytag/algorithm | ✅ |
| 6698/8162 | TLSA, SMIMEA | usage/selector/matching-type, underscored owner names | ✅ |
| 7043 | EUI48, EUI64 | fixed-width RDATA | ✅ |
| 7208 | SPF | as TXT-shaped record | ✅ |
| 7344 §3 | CDS, CDNSKEY | mirror the parent DS/DNSKEY formats | ✅ |
| 8078 §4 | delete sentinel | `CDS 0 0 0 0` and `CDNSKEY 0 3 0 0` built, recognised only in the mandated form, refused as a near miss, and only as an RRset of exactly one record | ✅ |
| 7344 §4.1 | parent acceptance | apex, signed by a key in *both* the current DNSKEY and DS RRsets, must not break the delegation — each refusal told apart from the others | ✅ |
| 6840 §5.2 | unfollowable delegations | a DS RRset with no usable algorithm or digest leaves the zone unsigned rather than forged ✅ (finding 26); one usable record among unusable ones still validates | ✅ |
| 4035 §5.3.3 | malformed keys | seven malformed key shapes through all eight algorithms: refused, never thrown ✅ (finding 27) | ✅ |
| 7477 | CSYNC | SOA-serial + flags + type bitmap | ✅ |
| 7553 | URI | target is raw remaining octets, **not** a domain name | ✅ |
| 7929 | OPENPGPKEY | binary blob | ✅ |
| 8659 | CAA | critical flag bit, length-prefixed tag, unprefixed value | ✅ |
| 8976 | ZONEMD | serial/scheme/hash | ✅ |
| 9460 | SVCB, HTTPS | alias mode, service mode + SvcParams, round-trip, RDLENGTH-bounded parsing | ✅ |
| 6672 §2.2 | DNAME | RDATA shape ✅; the substitution on labels, so a name that merely ends with the owner's spelling is not redirected ✅ (finding 24); the 255-octet limit told apart from "does not apply" ✅ | ✅ |
| 6891 | OPT | see EDNS project | ✅ |
| 8945 | TSIG | record shape ✅, signing and verification ✅, and both ends wired: the server verifies signed queries and signs replies, the client signs and checks (UDP/TCP) | ✅ |
| 2535 §3, 3445 | KEY | wire round-trip, protocol fixed at 3, the use bits, "no key information" distinguished from a restricted key | ✅ |
| 2539 | Diffie-Hellman in KEY | length-prefixed prime/generator/public value; well-known-group indices refused rather than read as a prime | ✅ |
| 2930 §4.1 | TKEY, Diffie-Hellman mode | the §4.1 keying material, checked against the formula applied by hand; the derived secret used as a real TSIG key | ✅ |
| 2930 §4.2 | TKEY, GSS-API mode | needs a Kerberos/SPNEGO stack | ⬜ |
| 2535 §4, 2931 | SIG, SIG(0) | record shape ✅, signing and verification ✅, and both ends wired: the server verifies signed queries and refuses what does not verify, the client signs over UDP and TCP | ✅ |

### 4.3 EDNS0 (`DNSConformance.Edns.Tests`)

| RFC | Focus | Status |
|-----|-------|:--:|
| 6891 §6.1 | OPT wire form: root owner, CLASS=payload size, TTL=extRCODE/version/flags, DO bit 0x8000 (golden bytes) | ✅ |
| 6891 §6.1.3 | extended RCODE combining (upper 8 bits from OPT) | ✅ |
| 6891 §6.1.1 | exactly one OPT, in the additional section; payload size 0 disables EDNS | ✅ |
| 6891 §6.1.2 | unknown option codes preserved as generic options; malformed option lengths survived | ✅ |
| 7871 | Client Subnet: family, prefix lengths, address truncated to the prefix | ✅ |
| 7873 §4 | Cookie option: 8-byte initial client cookie; the legal option lengths of §5.2.2 asserted on their own, not only through the FORMERR they cause | ✅ |
| 7873 §4.1 | client cookie | derived from the client address, the server address and a client secret — stable per server, different per server, and not a value that survives a change of address | ✅ |
| 7873 §5.3 | client: a response echoing a client cookie that was never sent is discarded, only the server half is stored ✅ (finding 25), BADCOOKIE retried once with the supplied cookie, a cookieless response still accepted | ✅ |
| 9018 §4 | server cookie | SipHash-2-4 over §4.4's exact input, all four Appendix A vectors reproduced byte for byte in both directions, a 128-bit key required, and §4.3's window compared with RFC 1982 serial arithmetic | ✅ |
| 7873 §5.2 | server: a server cookie bound to the client cookie, the client's address and a timestamp; BADCOOKIE with a fresh cookie when it is missing or wrong; FORMERR for illegal lengths; unchanged behaviour without a cookie or without a secret | ✅ |
| 7830 §3 | Padding option: code 12, OPTION-LENGTH is the octet count, all-zero outbound, any value accepted inbound, at most one per OPT meta-RR | ✅ |
| 8914 | Extended DNS Error: info-code + extra-text | ✅ |
| 7828 | TCP Keepalive: zero-length in queries, 2-byte 100 ms units in responses, malformed lengths rejected | ✅ |
| 8467 §4.1 | the block lengths themselves — 128 and 468 — and the arithmetic that reaches them; the *policies* that apply them are with the transport that carries them, in §4.6 | ✅ |

### 4.4 Client behavior (`DNSConformance.Client.Tests`) — vs. scripted servers

| RFC | Requirement under test | Status |
|-----|------------------------|:--:|
| 1035 §4.1.2 | query construction: QDCOUNT=1, QR=0, RD set, correct QTYPE/QCLASS | ✅ |
| 5452 §9.2 | transaction IDs vary and span the 16-bit space | ✅ |
| 5452 §4.1 | a response with a non-matching ID is never accepted as the answer | ✅ |
| 5452 §4.2 | …and the query keeps waiting for the genuine response instead of aborting | ✅ |
| 6891 §6.2.3 | client advertises EDNS0 with a payload size ≥ 512 | ✅ |
| 7766 §5 | TC=1 over UDP → retry over TCP, full answer surfaced | ✅ |
| 7766 §8 | TCP 2-byte length framing; reassembly of split prefix / dribbled bytes | ✅ |
| 7766 §6.2.1 | multiple queries on one TCP connection; recovery when the server closes | ✅ |
| 1035 §4.2.1 | UDP timeout respected; silence never hangs the caller | ✅ |
| robustness | garbage responses produce a result object, not an unhandled exception | ✅ |
| 2308 §2.1/§2.2 | NXDOMAIN vs NODATA reported distinctly; per-(name,type) keying | ✅ |
| 2308 §5 | NXDOMAIN served from the negative cache | ✅ |
| 2308 §5 | NODATA served from the negative cache; a referral is not mistaken for one | ✅ |
| 2308 §4 | negative TTL is min(SOA MINIMUM, SOA TTL), and the entry actually expires | ✅ |
| 6672 §2.2 | the resolver performs the substitution itself when a server sends a DNAME without the synthesized CNAME, and declines the names it does not cover ✅ (finding 24); loop protection | ✅ |
| 2931 §3.1 | the client signs its query, and signs the TCP retry too — finding 19 was that the retry went out unsigned and nothing reported it | ✅ |
| 2931 §3.2 | a response signature that does not verify is discarded; one that cannot be checked is ignored without error | ✅ |
| 8945, 2931 (transports) | both mechanisms over DoT and DoH: the message read back out of the TLS framing and out of a `?dns=` parameter, signature present, last, and verifying; an unconfigured client signs nothing | ✅ |

### 4.5 Server behavior (`DNSConformance.Server.Tests`) — raw sockets vs. `DNSServer`

| RFC | Requirement under test | Status |
|-----|------------------------|:--:|
| 1035 §4.1.1 | response: QR=1, ID echoed, question echoed, AA set, Z zero, no trailing bytes | ✅ |
| 1035 §2.3.3 | mixed-case QNAME still matches (case-insensitive lookup) | ✅ |
| 1035 §4.1.1 | RCODEs: NOERROR, NXDOMAIN, NOTIMP for an unsupported opcode | ✅ |
| 2308 §2.2 | known name + missing type → NODATA (NOERROR, empty answer) | ✅ |
| 1035 §3.3.9/2782 | multi-record answers, MX and SRV RDATA well-formed on the wire | ✅ |
| 7766 §6.2.1 | several queries on one TCP connection; partial message survived | ✅ |
| 3597 §2/§3 | an unassigned TYPE is stored, answered, told apart from the other types at the same name, synthesized from a wildcard, and served with its RDATA untouched — including RDATA that reads as a compression pointer | ✅ |
| 6672 §2.2/§3.1 | a name below a DNAME is redirected, the DNAME and a synthesized CNAME carrying the DNAME's TTL go into the answer, and the query restarts at the rewritten name | ✅ |
| 6672 §2.2 | an oversized substitution is YXDOMAIN with the DNAME as proof, and the 255-octet boundary is pinned from both sides | ✅ |
| 6672 §2.3 | the DNAME owner is not redirected: its own data answers, a DNAME query returns the record, a missing type is NODATA | ✅ |
| 6672 §2.4 | a record below the owner is occluded rather than served | ✅ |
| 6672 §3.1 | signed zone: the DNAME travels with the zone's RRSIG, the synthesized CNAME with none — confirmed by `delv` | ✅ |
| robustness | garbage, absurd counts, pointer loops: server stays healthy | ✅ |
| 7858 | DoT server: TLS 1.2/1.3, framing, multiple queries per session | ✅ |
| 1035 §4.2.1 | >512 B UDP answer without EDNS → TC=1 + truncation | ✅ |
| 6891 §6.2.5 | answer respects the advertised EDNS payload size | ✅ |
| 6891 §6.1.1 | OPT record present in responses to EDNS queries | ✅ |
| 6891 §6.1.3 | EDNS version > 0 → BADVERS | ✅ |
| 1035 §4.1.1 | unparseable request → FORMERR rather than silence | ✅ |
| 2181 §10.1 | no non-CNAME data is owned by an alias | ✅ |
| 1034 §4.3.2 | a CNAME answers queries of every type at that name; chains are followed within the zone and cycles terminate | ✅ |
| 4592 §3.3.1 | wildcard matching: synthesis at the closest encloser only, beaten by an exact match, blocked by an empty non-terminal, covering more than one label, NODATA for a type the wildcard lacks — and the answer carrying the queried name | ✅ |
| 4592 §2.2.2 | an empty non-terminal exists: NODATA rather than NXDOMAIN, and no wildcard applies to it | ✅ |
| 1034 §4.3.2 | a zone cut ends the search: NS records in the authority section, in-subtree glue in the additional section, AA clear — while the apex's own NS records are not a delegation | ✅ |
| 2308 §3 | every NXDOMAIN and NODATA cites the zone's SOA, so the answer can be cached | ✅ |
| 2931 §3.1 | SIG(0): a signed query verified before it is served, a bad one refused NOTAUTH, an unsigned one still served, over UDP and TCP alike | ✅ |
| 2931 §3.2 | a signed query ignored without error when no key is configured; a message carrying both a TSIG and a SIG(0) refused | ✅ |

### 4.6 Secure transports (`DNSConformance.SecureTransports.Tests`)

| RFC | Focus | Status |
|-----|-------|:--:|
| 7858 §3.3 | DoT client: RFC 7766 framing over TLS | ✅ |
| 7858 §3.4 | TLS session reuse: 3 queries → 1 handshake | ✅ |
| 8310 §8.1 | a rejecting certificate validator means no query is sent at all | ✅ |
| 7858 §3.3 | DoT **server**: raw-TLS probe answers correctly, multiple queries per session | ✅ |
| 8484 §4.1 | DoH GET: `?dns=` base64url **without padding**, no `+`/`/`/`%` | ✅ |
| 8484 §4.1 | DoH GET: `accept: application/dns-message` | ✅ |
| 8484 §4.1 | DoH POST: `content-type: application/dns-message`, body = raw message | ✅ |
| 8484 §4.1 | the encoded payload is a valid DNS query with no trailing bytes | ✅ |
| 8484 §4.2.1 | HTTP error status never reaches the wire parser | ✅ |
| 8484 §4.1 | DoH ID SHOULD be 0 (cache friendliness) | 📋 |
| 7830 §4 | responder MUST pad when the query carried the option, MUST NOT when it announced no EDNS(0), and the requestor's payload size caps the result | ✅ |
| 8467 §4.1 | client pads queries to 128, responder pads to 468, each at the first boundary that holds the message | ✅ |
| 8467 §1, 8484 §9 | padding on DoH: §1 scopes the document to encrypted transports rather than to named protocols, so the 128-octet query block applies; the client requests padding, which is the only half Hermod has | ✅ |
| 8484 §6 | the payload-size ceiling does *not* apply on DoH — a responder MUST ignore the advertised size, so the field only forces the OPT record the option lives in | ✅ |
| 8484 §4.1 + 8467 §4.1 | the two paddings do not collide: a message on a 128-octet block is ≡ 2 (mod 3), the one class where base64url would append `=`, and it still must not | ✅ |
| JSON APIs | Google/Cloudflare `application/dns-json` (covered live against Cloudflare) | 🟡 |

DoH client tests run against a scripted in-process HTTP listener speaking
RFC 8484 (both directions verified with RawDns). DoT tests use Hermod's own
DoT server where a real peer is needed, plus a scripted TLS listener for
byte-level assertions — but conformance judgments always come from the RawDns
side of the connection.

### 4.7 DNSSEC (`DNSConformance.Dnssec.Tests`)

| RFC | Focus | Status |
|-----|-------|:--:|
| 4034 App. B | key tag algorithm on **both** published IANA root KSKs (20326, 38696) | ✅ |
| 4034 §5.1.4 | DS digest reproduces IANA's published root anchor; tampered digest and unknown digest type rejected | ✅ |
| 4034 App. B | key tag survives a wire round-trip unchanged | ✅ |
| 4034 §5.1.4 | DS of the BIND-signed fixture zone matches `dnssec-dsfromkey` | ✅ |
| 4034 §3.1.8 | RRSIG validation of BIND-signed RRsets: SOA, NS, A, AAAA, MX, TXT | ✅ |
| 4035 §5.3 | DNSKEY RRset validates under the KSK (the DS→DNSKEY chain link) | ✅ |
| 4035 §5.3.3 | tampered RDATA and verification under an unrelated key are rejected | ✅ |
| 4034 §6.3 | canonical ordering applied by the validator (reversed RRset still validates) | ✅ |
| 4034 §3.1.8 | a **live** cloudflare.com SOA RRSIG validates end-to-end (Online) | ✅ |
| 4034 §5.1 | **every algorithm the validator claims** — 5, 7, 10, 13, 14, 15, 16 — each against a zone BIND signed with it: key shape, A/AAAA/TXT/SOA/NS RRSIGs, DS digest, tampered RDATA and wrong-key rejection | ✅ |
| 6605 | ECDSA P-256 (13) and P-384 (14): fixed-width r\|\|s, 64/96-octet keys | ✅ |
| 8080 | Ed25519 (15) and Ed448 (16): raw 32/57-octet keys, verified via BouncyCastle | ✅ |
| 8080 §6 | signing: all four published examples reproduced byte for byte, public keys derived from the private half, fixed lengths, wrong-length and wrong-shape keys refused | ✅ |
| 8080 + 2931 | SIG(0) signed and verified with every algorithm RFC 8624 §3.1 allows a signer to choose — 8, 10, 13, 14, 15, 16 — over a socket, each with a wrong-key control | ✅ |
| 8624 | RSA/SHA-1 (5, 7) still validates — deprecated for signing, not for verifying | ✅ |
| 4035 §4.3 | Secure / Insecure / Bogus / Indeterminate classification via `ValidateAsync` | ✅ |
| 4034 §3.1.5 | expired and not-yet-valid signatures are Bogus | ✅ |
| 5011 §2.3/§2.4.1 | 30-day hold-down; no trust on first sight; continuity required; ZSKs ignored | ✅ |
| 4034 §3.1.3 | RRSIG Labels excludes the leading asterisk | ✅ |
| 4035 §5.3.2 | wildcard-expanded RRsets validate against the wildcard signature | ✅ |
| 5011 §2.1 | a revoked KSK is dropped from the anchors and cannot come back | ✅ |
| 4592 §2.1.1 | wildcard owner names round-trip; the `*` label is accepted leftmost only, and never by the strict hostname parser | ✅ |
| 5155 App. A | NSEC3 hash vectors: all twelve hashed owner names, salt per iteration, canonical-wire input, Base32hex | ✅ |
| 5155 §8, 4035 §5.4 | authenticated denial of existence: match/cover, closest encloser, opt-out, wildcard NODATA, and canonical ordering against the §6.1 list | ✅ |
| 5155 §6, §7.2.7 | opt-out, against a zone BIND signed with `-A`: the flag on every NSEC3, no NSEC3 for the insecure delegation, and a referral whose covering record carries the flag; a name inside an opted-out span is covered but not proven | ✅ |
| 4035 §3.1.4.1 | a DS query at a zone cut is answered by the parent rather than referred | ✅ |
| 4035 §3.1, 5155 §7 | the *serving* side, against the BIND-signed fixture zones: RRSIGs with the answer and denial records with the "no", both gated on the DO bit; NSEC and NSEC3 NXDOMAIN and NODATA proofs; a wildcard answer keeping its RRSIG's `labels` field and carrying the proof the queried name was absent; no spare NSEC3s | ✅ |
| 8945 | TSIG: MAC over the §4.3.3 variables, CLASS/TTL/placement, BADSIG vs BADKEY vs BADTIME, fudge window, rewritten ID, request-bound responses | ✅ |
| 2931 | SIG(0): the §3 record shape, the §3.1 signed data for both the request and the transaction form, ARCOUNT taken before the record was appended, tampering and foreign keys and the validity window all rejected | ✅ |
| 3110 §2, 6605 §4 | public key encodings: RSA's length-prefixed exponent then modulus, ECDSA's bare curve point with no 0x04 marker | ✅ |

### 4.8 Interop projects

**`DNSInterop.PublicResolvers.Tests`** (category `Online`) — 23 ✅

| Focus | Status |
|-------|:--:|
| Do53 UDP against Cloudflare, Google, Quad9 | ✅ |
| Do53 TCP against Cloudflare, Google | ✅ |
| DoT (853) against Cloudflare, Google | ✅ |
| DoH POST/GET against Cloudflare, POST against Google | ✅ |
| DoH JSON (`application/dns-json`) against Cloudflare | ✅ |
| MX, AAAA, CAA resolve in the wild | ✅ |
| HTTPS/SVCB resolves in the wild | ✅ |
| root DNSKEY: large answer completed (no truncation surfaced) | ✅ |
| NXDOMAIN reported as NXDOMAIN; CNAME chain followed | ✅ |
| live root DNSKEY contains the IANA KSK; live RRSIG validates | ✅ |
| deliberately bogus zone (dnssec-failed.org) does not resolve | ✅ |

**`DNSInterop.LinuxTools.Tests`** (category `WSL`) — 34 ✅
Hermod's `DNSServer` bound to all interfaces, interrogated from WSL:

| Focus | Status |
|-------|:--:|
| `dig`: A record, NOERROR + qr/aa flags, no structural warnings | ✅ |
| `dig`: NXDOMAIN; AAAA, MX, TXT, SRV, CNAME, PTR, CAA, NS | ✅ |
| `dig +tcp`, `+noedns`, `+edns=0`, `+edns=1` (BADVERS probe) | ✅ |
| `kdig`: UDP, TCP, and **DoT (`+tls`)** against Hermod's TLS listener | ✅ |
| `drill`: A, AAAA, MX, SRV, SOA — a third parser lineage | ✅ |
| dig, kdig and drill agree on a multi-record answer set | ✅ |
| all of the above still pass after the case-preservation and compression changes | ✅ |
| `delv` fully validates a Hermod-served signed answer, a wildcard answer, an NSEC NXDOMAIN, an NSEC NODATA, an NSEC3 closest-encloser proof, and the DNSKEY RRset — the last only reachable over the TCP retry | ✅ |
| …and refuses the identical answer under a trust anchor with the right name and the wrong key: the control that makes "fully validated" mean something | ✅ |

**`DNSInterop.ExternalServers.Tests`** (category `WSL`) — 13 ✅
BIND `named` in WSL serving the fixture zone; Hermod is the client:

| Focus | Status |
|-------|:--:|
| A, multi-A (BIND emits compression), AAAA, MX, TXT, SRV, SOA, CAA, TLSA | ✅ |
| CNAME chase against BIND | ✅ |
| NXDOMAIN from BIND; TCP transport | ✅ |
| multi-character-string TXT served by BIND | ✅ |
| Knot / Unbound / CoreDNS via Docker | ⬜ (no Docker daemon here) |

---

## 5. Solution layout

```
DNSConformanceTests/
├── DNSConformanceTests.sln
├── PLAN.md                  ← this file
├── FINDINGS.md              ← conformance deviations discovered by the suite
├── README.md                ← how to run
├── build/
│   └── CommonTestSettings.props
├── libs/                    ← git submodules (existing)
│   ├── Hermod/
│   └── Styx/
├── src/
│   └── DNSConformance.Core/             ← shared infrastructure (NOT tests)
│       ├── RawDns/                      ← independent reference codec
│       │   ├── RawDnsWriter.cs          ← builder for messages/names/RRs
│       │   ├── RawDnsReader.cs          ← independent parser
│       │   └── RawDnsMessage.cs         ← plain DTOs
│       ├── Scripted/
│       │   ├── ScriptedUdpServer.cs     ← canned/computed UDP responder
│       │   ├── ScriptedTcpServer.cs     ← framing-aware TCP responder
│       │   ├── ScriptedTlsServer.cs     ← DoT-speaking TLS responder
│       │   └── ScriptedDoHServer.cs     ← RFC 8484 HttpListener responder
│       ├── Fixtures/
│       │   ├── HermodServerFixture.cs   ← DNSServer on ephemeral ports
│       │   ├── TestCertificate.cs       ← self-signed cert factory
│       │   └── ZoneFixtures.cs          ← fixture zone loading
│       ├── Wsl.cs                       ← WSL bridge (run tool, host IP discovery)
│       ├── TestEnvironment.cs           ← capability probing (network/WSL/docker)
│       └── TestCategories.cs            ← Online / WSL / Docker / Slow / KnownIssue
├── conformance/
│   ├── Directory.Build.props            ← imports build/CommonTestSettings.props
│   ├── DNSConformance.WireFormat.Tests/
│   ├── DNSConformance.ResourceRecords.Tests/
│   ├── DNSConformance.Edns.Tests/
│   ├── DNSConformance.Client.Tests/
│   ├── DNSConformance.Server.Tests/
│   ├── DNSConformance.SecureTransports.Tests/
│   └── DNSConformance.Dnssec.Tests/
├── interop/
│   ├── Directory.Build.props
│   ├── DNSInterop.PublicResolvers.Tests/
│   ├── DNSInterop.LinuxTools.Tests/
│   └── DNSInterop.ExternalServers.Tests/
└── fixtures/
    ├── zones/
    │   ├── conformance.test.zone        ← every supported RR type
    │   ├── signed/                      ← BIND-signed zone + keys + DS (committed)
    │   └── resign.sh                    ← regenerate via WSL dnssec-signzone
    ├── bind/                            ← named.conf for the WSL BIND instance
    └── docker/                          ← compose for Knot/Unbound/CoreDNS (optional)
```

No `Directory.Build.props` at the repository root — a root-level file would
leak into the submodule builds. Shared settings live in
`build/CommonTestSettings.props`, imported by per-folder props.

## 6. Infrastructure design

* **RawDns codec** — a deliberately small, well-commented encoder/decoder
  written straight from RFC 1035 (+3596/4034/6891 where needed). It favors
  strictness and reports offsets on error. It is the measuring stick; if a
  RawDns bug is ever found, fix it and re-run — never adjust it to match Hermod.
* **Scripted servers** — accept a delegate `byte[] → byte[]?` so a test can
  return canned bytes, computed responses, garbage, partial writes (TCP), or
  nothing (timeout tests). They record every request for later assertions.
* **HermodServerFixture** — wraps `DNSServer` + `AuthoritativeDNSRequestHandler`
  with the standard fixture zone on 127.0.0.1 ephemeral ports (UDP/TCP/TLS),
  and on `0.0.0.0` when WSL tools must reach it.
* **WSL bridge** — `wsl.exe -e …` wrapper; discovers the Windows host IP as
  seen from WSL (default-route gateway, `/etc/resolv.conf`, or 127.0.0.1 under
  mirrored networking); probes tool availability once per run.
* **Categories & skipping** — `[Category(TestCategories.Online/WSL/Docker/Slow)]`;
  `TestEnvironment` probes once and `Assert.Ignore`s with instructions.
* **Timeouts** — every socket test carries an explicit short timeout; suite
  target: offline projects < 60 s total.

## 7. Phases

| Phase | Content | State |
|------:|---------|-------|
| 0 | Exploration of Hermod's DNS stack; environment probing; WSL tool installation | ✅ done |
| 1 | This plan; solution scaffold; `DNSConformance.Core` (RawDns, scripted servers, fixtures) | ✅ done |
| 2 | Layer-1/2 conformance projects (wire format, RRs, EDNS, client, server) | ✅ done |
| 3 | Secure transports + DNSSEC projects incl. BIND-signed fixtures | ✅ done |
| 4 | Interop projects (public resolvers, WSL tools, BIND) | ✅ done |
| 5 | Run everything runnable here; triage red tests → [FINDINGS.md](FINDINGS.md) | ✅ done |
| 6 | Deepen 🟡/⬜ areas: wildcard signatures, chain classification, RFC 5011, ECDSA, keepalive/padding, negative caching, CNAME semantics, NSEC3 hashing and proofs, TSIG end to end | ✅ done — the padding policies closed it on both encrypted transports (findings 30, 31, 32) |
| 7 | External suites: ISC `genreport` EDNS battery, Zonemaster undelegated (needs a Docker daemon) | ⬜ next |
| 8 | CI: GitHub Actions — `ci.yml` gates every push on the offline suite, Windows and Debian 13; `nightly.yml` adds interop, live resolvers, fixture re-signing, and a second job that tests against Hermod **master** rather than the pinned gitlink | ✅ done |

## 8. Running the suite

```powershell
# everything that runs without network/WSL:
dotnet test DNSConformanceTests.sln --filter "TestCategory!=Online&TestCategory!=WSL&TestCategory!=Docker"

# include live-network interop:
dotnet test interop/DNSInterop.PublicResolvers.Tests

# GNU/Linux tool interop (needs WSL + bind9-dnsutils/knot-dnsutils/ldnsutils):
dotnet test interop/DNSInterop.LinuxTools.Tests

# single area:
dotnet test conformance/DNSConformance.Dnssec.Tests
```

WSL preparation (already done on this machine):

```bash
wsl -u root -e sh -c 'apt-get update && apt-get install -y bind9-dnsutils knot-dnsutils ldnsutils bind9 bind9utils'
```

## 9. Findings protocol

A red conformance test is triaged into exactly one bucket:

1. **Suite defect** — RawDns or the test misreads the RFC → fix the suite.
2. **Hermod deviation** — documented in `FINDINGS.md` (RFC quote, observed
   behavior, repro test name, suggested fix), test stays red as the tracking
   signal. If a deviation blocks many unrelated tests it may additionally be
   tagged `KnownIssue` so dashboards can separate "new" from "known" red.
3. **Ambiguity** — RFC language genuinely unclear → documented in FINDINGS.md
   under "Interpretations", test asserts the dominant implementation behavior
   (verified via dig/BIND).
