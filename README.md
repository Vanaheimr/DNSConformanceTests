# DNS Conformance & Interoperability Test Suite

An independent .NET 10 test solution that measures the DNS client and server of
[Vanaheimr Hermod](https://github.com/Vanaheimr/Hermod) against the DNS RFCs,
and against real implementations: ISC BIND, Knot DNS, NLnet Labs ldns and the
public resolvers.

Hermod and Styx are consumed as git submodules under `libs/`, so the suite can
be pointed at any Hermod revision and acts as an unbiased referee.

- **[RFC coverage](#rfc-coverage)** — what is asserted, what is queued, what is
  out of scope and why
- **[PLAN.md](PLAN.md)** — architecture and the section-by-section coverage matrix
- **[FINDINGS.md](FINDINGS.md)** — the record of what this suite caught, and the
  RFC ambiguities it had to rule on

**Current status: 390 tests · 390 ✅ · 0 ❌.**

The suite has found 16 RFC deviations in Hermod. All are fixed;
[FINDINGS.md](FINDINGS.md) records each with chapter and verse, the change, and
the test that pins it.

## Getting started

```bash
git submodule update --init --recursive
dotnet build DNSConformanceTests.slnx
```

Everything that needs no network, WSL or Docker:

```bash
dotnet test DNSConformanceTests.slnx --filter "TestCategory!=Online&TestCategory!=WSL&TestCategory!=Docker"
```

If a future run turns up a new deviation, tag it `KnownIssue` and exclude the
category to keep a green gate while it is open:

```bash
dotnet test DNSConformanceTests.slnx --filter "TestCategory!=KnownIssue"
```

Tests requiring prerequisites `Assert.Ignore` with an actionable message rather
than failing, so a bare checkout is always green-or-skipped.

## Test categories

| Category | Needs | Run with |
|----------|-------|----------|
| *(none)* | nothing — loopback sockets only | the default filter above |
| `Online` | outbound DNS (UDP/53, TCP/853, HTTPS) | `--filter "TestCategory=Online"` |
| `WSL` | the BIND/Knot/ldns tools — via WSL on Windows, natively on Linux | `--filter "TestCategory=WSL"` |
| `Docker` | a reachable Docker daemon | `--filter "TestCategory=Docker"` |
| `Slow` | > ~5 s runtime | exclude to keep the inner loop fast |
| `KnownIssue` | — | marks a confirmed deviation ([FINDINGS.md](FINDINGS.md)) |

### Continuous integration

Two workflows, mirroring Hermod's own, on the same two legs — `windows-latest`
and Debian 13 in a container — because Hermod is what is under test and a
conformance result that holds on only one platform is worth knowing about.

| Workflow | Trigger | Runs |
|----------|---------|------|
| `ci.yml` | push, pull request | the offline suite, both platforms. Nothing but loopback sockets, so red means a conformance result changed |
| `nightly.yml` | 03:41 UTC | the offline suite again, plus interop and the live resolvers, plus the suite against Hermod **master** |

The nightly does three things the gate structurally cannot.

It **re-signs the DNSSEC fixtures** on the Linux leg before testing. Real BIND
signatures expire a month after they are made, so a committed fixture is a
deadline; regenerating removes it, and exercises `resign.sh` while it is at it.

It **runs the interop lane natively**. On a Linux runner `dig`, `kdig`, `drill`
and `named` are ordinary programs on the same loopback as the server under
test — no bridge, no firewall. The `WSL` category keeps its name because that is
where the tools live on a developer machine, but nothing about those tests needs
WSL.

And it **tests against Hermod master**, not against the pinned submodule. The
gate answers "would a fresh clone build"; nothing in it notices when Hermod
moves, because a push to Hermod does not touch this repository. A referee that
only ever sees one frozen revision is not refereeing.

### Preparing WSL for the interop lane

```bash
wsl -u root -e sh -c 'apt-get update && apt-get install -y bind9-dnsutils knot-dnsutils ldnsutils bind9 bind9utils'
```

That provides `dig`, `kdig`, `drill`, `delv`, `named` and `dnssec-signzone`.

If the WSL tools cannot reach the Hermod server, it is almost always a Windows
Firewall rule blocking inbound traffic from the WSL subnet — the tests detect
this and skip with that explanation.

## RFC coverage

Three lists: what the suite **asserts today**, what is **queued**, and what is
**out of scope** — with the reason, so the boundary is auditable rather than
implied. [PLAN.md §4](PLAN.md) breaks the first list down section by section.

Nothing here is aspirational: an RFC is listed as covered only if a passing test
names it in a `[Property("RFC", …)]` attribute.

### Covered — asserted by passing tests

| RFC | Topic | What the suite pins down |
|-----|-------|--------------------------|
| **1034** | Domain concepts | the CNAME rule (§4.3.2) — an alias answers *every* QTYPE; chains followed in-zone, cycles terminate |
| **1035** | Message format | header bit positions, question encoding, name limits (63/255), compression pointers both directions, case preserved byte-exactly, UDP truncation, FORMERR |
| **1183** | RP, AFSDB | two-name RDATA |
| **2181** §10.1 | Clarifications | an alias owns no other data |
| **2308** | Negative caching | NXDOMAIN vs NODATA kept distinct, both cached per (name, type), TTL = `min(SOA.MINIMUM, SOA.TTL)`, entries actually expire, a referral is not mistaken for NODATA |
| **2535** §3, **3445** | KEY | wire round-trip, protocol fixed at 3, the use bits, and "no key information" kept distinct from a key with one use forbidden |
| **2539** | Diffie-Hellman in KEY | length-prefixed prime/generator/public value; a well-known-group index refused rather than read as a literal prime; truncated and over-long RDATA rejected |
| **2782** | SRV | priority/weight/port/target, no RDATA compression on emit |
| **2930** §4.1 | TKEY, Diffie-Hellman mode | keying material against the §4.1 formula applied by hand; nonce order not interchangeable; the derived secret actually signs and verifies as a TSIG key |
| **3403** | NAPTR | flags/service/regexp character-strings |
| **3596** | AAAA | full and compressed IPv6 forms |
| **4033/4034/4035** | DNSSEC | key tag (App. B) on both IANA root KSKs, DS digests vs. IANA's published anchor, RRSIG validation against BIND-signed RRsets, canonical ordering, Secure/Insecure/Bogus/Indeterminate classification, expired and not-yet-valid signatures, wildcard reconstruction (§5.3.2) |
| **4255** | SSHFP | algorithm × fingerprint-type matrix |
| **4343** | Case-insensitivity | names differing only in case are equal, hash alike, order alike |
| **4398** | CERT | type/keytag/algorithm |
| **4592** §2.1.1 | Wildcards | `*` accepted as leftmost label only, and never by the strict hostname parser |
| **5011** | Trust-anchor rollover | 30-day hold-down, no trust on first sight, continuity required, ZSKs ignored, a revoked KSK dropped for good |
| **5155** | NSEC3 | hashing — all twelve hashed owner names of App. A reproduce; salt applied every iteration, iteration count is *extra* rounds, canonical-wire input; Base32hex order-preserving. §8 proofs: match, cover, closest encloser, opt-out |
| **5452** | Spoofing resistance | transaction IDs span the 16-bit space; a non-matching response is ignored, not fatal |
| **6605** | ECDSA | P-256 and P-384: fixed-width r‖s, 64/96-octet keys |
| **6698**, **8162** | TLSA, SMIMEA | usage/selector/matching-type, underscored owner names |
| **6891** | EDNS0 | OPT wire form (golden bytes), extended-RCODE combining, exactly one OPT, BADVERS for version > 0, payload-size negotiation |
| **7043** | EUI48, EUI64 | fixed-width RDATA |
| **7208** | SPF | multi-character-string concatenation |
| **7344** | CDS, CDNSKEY | mirror the parent DS/DNSKEY formats |
| **7477** | CSYNC | SOA-serial + flags + type bitmap |
| **7553** | URI | target is raw remaining octets, **not** a domain name |
| **7766** | DNS over TCP | 2-byte framing, TC→TCP fallback, split/dribbled reassembly, connection reuse, recovery on close |
| **7828** | TCP Keepalive | zero-length in queries, 2-byte 100 ms units in responses |
| **7830**, **8467** | Padding | all-zero octets, 128-byte query and 468-byte response blocks |
| **7858** | DoT | client and server; framing over TLS, session reuse (3 queries → 1 handshake) |
| **7871** | Client Subnet | family, prefix length, address truncated to the prefix |
| **7873** | Cookies | 8-byte initial client cookie encoding |
| **7929** | OPENPGPKEY | binary blob |
| **8080** | Ed25519, Ed448 | raw 32/57-octet keys, cross-checked with BouncyCastle |
| **8310** §8.1 | DoT auth profile | a rejecting certificate validator means no query leaves the host |
| **8484** | DoH | GET `?dns=` base64url **unpadded**, POST content types, no trailing bytes, HTTP errors never reach the wire parser |
| **8624** | Algorithm selection | every algorithm 8624 asks a *validator* to implement — 8, 10, 13, 14, 15, 16 — verifies a real BIND signature; deprecated RSA/SHA-1 (5, 7) still validates, as it must |
| **8659** | CAA | critical-flag bit, length-prefixed tag, unprefixed value |
| **8914** | Extended DNS Errors | info-code + extra-text |
| **8945** | TSIG | MAC over message + §4.3.3 variables, checked against HMAC applied by hand; CLASS ANY, TTL 0, last in additional, ARCOUNT counts it; BADSIG / BADKEY / BADTIME kept distinct; the fudge window, a rewritten message ID, a response bound to its request's MAC. End to end: the server verifies signed queries and signs its replies, the client signs and checks the answer |
| **8976** | ZONEMD | serial/scheme/hash |
| **9460** | SVCB, HTTPS | alias and service mode, SvcParams parsed to RDLENGTH |

All eight signature algorithms Hermod's validator claims are covered against
real BIND signatures, each from a zone signed with that exact algorithm rather
than a shared fixture: 5, 7, 10, 13, 14, 15 and 16 in
`SignatureAlgorithmMatrixTests`, and 8 (RSA/SHA-256) as the main `dnssec.test`
fixture zone in `RrsigValidationTests`.

### Queued — on the todo list

| RFC / area | What is missing | Blocker |
|------------|-----------------|---------|
| **1876** LOC | size/precision/altitude edge cases; only the common shape is covered | — |
| **2181** §8 | MSB-set TTL is *observed*, not asserted — receiver behavior is loosely specified | needs a defensible reading |
| **2930** (GSS mode) | GSS-TSIG, the TKEY mode that is actually deployed | needs a Kerberos/SPNEGO stack, which is not something a DNS library grows on its own |
| **2931** | SIG(0): per-message signatures under a public key, the asymmetric alternative to TSIG | the KEY record exists now; SIG (type 24) and the signing path do not |
| **3110** | the 3-octet exponent-length form, for RSA keys with an exponent over 255 bytes; BIND's fixtures all use the 1-octet form | needs a hand-built key |
| **3597** | unknown-type opacity: no compression inside unknown RDATA, `\#` presentation round-trip. The server already survives an unassigned TYPE | — |
| **4592** (server side) | wildcard *matching* at query time; only the owner-name representation is covered | `InMemoryDNSZone` has no wildcard lookup |
| **5155** (zone side) | walking an NSEC3 chain to answer from a signed zone; opt-out | the hash exists; `InMemoryDNSZone` has no NSEC3 chain to walk |
| **6672** | DNAME subtree rewrite and the synthesized CNAME; only the record shape is covered | — |
| **7129** | the *server* producing denial records for a signed zone it serves | `InMemoryDNSZone` holds no NSEC or NSEC3 chain to serve from |
| **7344** | the delete sentinel (algorithm 0) | — |
| **7873** | the cookie *protocol*: server-cookie reuse (Hermod does this) and BADCOOKIE retry, not just the encoding | — |
| **8198** | aggressive NSEC caching — **implemented** in `DNSCache`/`DNSClient`, currently untested | — |
| **8945** (transports) | signing over DoT and DoH | wired for UDP and TCP, which is where TSIG is deployed; the TLS and HTTPS clients each serialize separately and are untouched |
| interop | `delv` validating a Hermod-served signed zone | — the interop lane runs on CI now, so this is work rather than a prerequisite |
| external | ISC `genreport` EDNS battery; Zonemaster undelegated | phase 7 |
| interop | Knot, Unbound, CoreDNS as peers | needs a Docker daemon; no runner leg for it yet |

**TKEY's Diffie-Hellman mode is covered, and comes with three caveats worth
stating rather than discovering.** The exchange is unauthenticated on its own —
RFC 2930 §5 requires the KEY records themselves to be authenticated before the
derived secret means anything. Its key derivation is fixed to MD5 by §4.1, with
no conforming alternative, so the code path cannot run on a FIPS-restricted host
and says so instead of substituting a hash no peer would agree with. And it is
not what anyone actually deploys: that is GSS-TSIG (RFC 3645, mode 3), which
needs a Kerberos stack and stays out of scope.

There are also no published test vectors for the derivation — RFC 2930 gives the
formula and no worked example — so the tests encode the specification text
directly rather than reproducing someone else's numbers, which is weaker
evidence than the RFC 5155 Appendix A vectors and is called out as such.

Nothing on this list is blocked; the rest is work that has not been done.

### Out of scope

Out of scope means *this suite will not test it*, and says why. If Hermod grows
the feature, the entry moves up a list — none of these are refusals on principle.

| RFC / area | Why not |
|------------|---------|
| **1034** §5 — iterative resolution, root priming | Hermod's client is a stub resolver that forwards to configured servers. There is no iterative resolver here to hold to the algorithm. |
| **1995** IXFR, **5936** AXFR | Hermod has the QTYPE code points and nothing behind them. A test would be a feature request wearing a test's clothes. |
| **2136** dynamic update | Likewise: the opcode exists in the enum, the protocol does not. |
| **5890**/**5891** IDNA | No punycode anywhere in Hermod. At the DNS layer names are octets; A-label conversion belongs to the application. |
| **6147** DNS64, RPZ, filtering | Not features Hermod has, and not ones it is trying to have. |
| **6762** mDNS, **6763** DNS-SD | The server can bind a multicast UDP socket, but implements no mDNS semantics — no cache-flush bit, no probing/announcing, no `.local`. A multicast socket is not mDNS. |
| **7626**, **9076** privacy considerations | Informational — no testable requirement to assert. |
| **7671**/**7672**/**7673** DANE usage | The suite asserts the TLSA/SMIMEA *record*. What a mail or web client does with it is above the DNS layer. |
| **8484** DoH **server** | Hermod is a DoH *client*; its server speaks UDP, TCP and DoT. The client side is covered above. |
| **9250** DoQ, DNS over HTTP/3 | No QUIC in Hermod at all. |

## Projects

```
src/DNSConformance.Core          shared infrastructure (not tests)
conformance/                     RFC conformance, offline
  …WireFormat.Tests              RFC 1035 header, names, compression, TTLs
  …ResourceRecords.Tests         ~25 RR types: wire format + round-trips
  …Edns.Tests                    RFC 6891 OPT + typed EDNS options
  …Client.Tests                  client vs. scripted servers
  …Server.Tests                  Hermod server vs. raw sockets
  …SecureTransports.Tests        RFC 7858 DoT, RFC 8484 DoH
  …Dnssec.Tests                  key tags, DS digests, RRSIG validation
interop/                         interoperability
  …PublicResolvers.Tests         Cloudflare / Google / Quad9, all transports
  …LinuxTools.Tests              dig, kdig, drill vs. the Hermod server
  …ExternalServers.Tests         BIND as server, Hermod as client
fixtures/                        test zones, BIND config, DNSSEC material
```

### How the suite avoids grading Hermod with Hermod

Every assertion is checked against an independent reference:

- **`RawDns`** — a small, strict DNS encoder/decoder in
  `src/DNSConformance.Core/RawDns`, written directly from RFC 1035. It is the
  measuring stick: Hermod-produced bytes are decoded with it, and the messages
  Hermod parses are built with it. If a RawDns bug ever surfaces, fix RawDns —
  never bend it to match Hermod.
- **Published RFC vectors** — e.g. the RFC 1035 §4.1.4 compression example, the
  RFC 4034 §4.3 NSEC type-bitmap example, IANA's root trust anchors.
- **Other implementations** — BIND's `dnssec-signzone` produces the DNSSEC
  fixtures, BIND serves zones that Hermod's client reads, and dig/kdig/drill
  read what Hermod's server writes.

### Scripted servers

`ScriptedUdpServer`, `ScriptedTcpServer`, `ScriptedTlsServer` and
`ScriptedDoHServer` are loopback listeners driven by a delegate, so a test can
reply with canned bytes, garbage, dribbled TCP writes, spoofed transaction IDs
or nothing at all. They record every request for assertions.

## Regenerating the DNSSEC fixtures

The signed zone under `fixtures/zones/signed/` is committed, but can be
regenerated at any time (requires WSL + `bind9utils`):

```bash
wsl -e sh fixtures/zones/resign.sh
```

This creates a fresh RSASHA256-signed `dnssec.test` zone with `dnssec-keygen` /
`dnssec-signzone`, flattens it to one record per line for the fixture loader,
and writes the matching DS record — then does the same once per signature
algorithm (`ecdsa.`, `ecdsap384.`, `ed25519.`, `ed448.`, `rsasha512.`,
`rsasha1.`, `nsec3rsasha1.`), so every verification path Hermod implements has
real signatures to check against.

An algorithm the local BIND cannot sign with is skipped rather than aborting the
run; the matching tests then report the fixture as missing and ignore themselves.

## Adding a test

Cite the requirement, and make the failure message explain the violation rather
than the mechanics:

```csharp
[Test]
[Property("RFC", "6891 §6.1.1")]
public async Task Response_To_Edns_Query_Contains_An_Opt_Record()
{
    // RFC 6891 §6.1.1: responders "MUST include an OPT record in their
    // respective responses" when the query carried one.
    var request  = RawDnsWriter.Query(0x1001, ZoneFixtures.AName, RawDnsType.A, ednsPayloadSize: 4096);
    var raw      = await RawDnsProbe.UdpAsync(server.UdpPort, request);
    var response = RawDnsReader.Parse(raw!);

    Assert.That(response.Opt, Is.Not.Null,
                "an EDNS-aware responder MUST include an OPT record when the query had one");
}
```

When a test goes red, triage it into one of three buckets:

1. **Suite defect** — RawDns or the test misreads the RFC. Fix the suite.
2. **Hermod deviation** — record it in [FINDINGS.md](FINDINGS.md) with chapter
   and verse, tag the test `[Category(TestCategories.KnownIssue)]`, and leave it
   red as the tracking signal.
3. **Ambiguity** — the RFC genuinely permits both readings. Assert the dominant
   implementation behavior (check with dig/BIND) and note it under
   "Interpretations" in FINDINGS.md.
