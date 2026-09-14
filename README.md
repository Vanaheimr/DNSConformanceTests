# DNS Conformance & Interoperability Test Suite

[![CI](https://github.com/Vanaheimr/DNSConformanceTests/actions/workflows/ci.yml/badge.svg)](https://github.com/Vanaheimr/DNSConformanceTests/actions/workflows/ci.yml)
[![Nightly](https://github.com/Vanaheimr/DNSConformanceTests/actions/workflows/nightly.yml/badge.svg)](https://github.com/Vanaheimr/DNSConformanceTests/actions/workflows/nightly.yml)

An independent .NET 10 test solution that measures the DNS client and server of
[Vanaheimr Hermod](https://github.com/Vanaheimr/Hermod) against the DNS RFCs,
and against real implementations: ISC BIND, Knot DNS, NLnet Labs ldns, native
DNS-SD implementations and the public resolvers.

Hermod and Styx are consumed as git submodules under `libs/`, so the suite can
be pointed at any Hermod revision and acts as an unbiased referee.

- **[RFC coverage](#rfc-coverage)** — what is asserted, what is queued, what is
  out of scope and why
- **[PLAN.md](PLAN.md)** — architecture and the section-by-section coverage matrix
- **[FINDINGS.md](FINDINGS.md)** — the record of what this suite caught, and the
  RFC ambiguities it had to rule on

**Current verified status on Windows (2026-09-15): 1049 ✅ · 0 ❌ · 4 platform-specific skips.**

That full run exercised all twelve test projects and every category, including
the public resolvers, WSL tools, Docker servers and native multicast DNS-SD. The
four skips are the RSA public-key exponent cases that Windows CNG cannot import;
the Linux CI leg covers them.

The suite has found 48 RFC deviations in Hermod. All are fixed;
[FINDINGS.md](FINDINGS.md) records each with chapter and verse, the change, and
the test that pins it.

## Getting started

```bash
git submodule update --init --recursive
dotnet build DNSConformanceTests.slnx
```

Everything that needs no external network, multicast, WSL or Docker:

```bash
dotnet test DNSConformanceTests.slnx --filter "TestCategory!=Online&TestCategory!=WSL&TestCategory!=Docker&TestCategory!=Multicast"
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
| `Multicast` | a multicast-capable interface and native `dns-sd` command | `--filter "TestCategory=Multicast"` |
| `Slow` | > ~5 s runtime | exclude to keep the inner loop fast |
| `KnownIssue` | — | marks a confirmed deviation ([FINDINGS.md](FINDINGS.md)) |

### Continuous integration

Two workflows, mirroring Hermod's own, on the same two legs — `windows-latest`
and Debian 13 in a container — because Hermod is what is under test and a
conformance result that holds on only one platform is worth knowing about.

| Workflow | Trigger | Runs |
|----------|---------|------|
| `ci.yml` | push, pull request | fresh DNSSEC signatures, then the offline suite on both platforms. Nothing but loopback sockets, so red means a conformance result changed |
| `nightly.yml` | 03:41 UTC | the offline suite again, plus unicast and multicast interop, the live resolvers, both external suites, and the suite against Hermod **master** |

**Both workflows sign the DNSSEC fixtures before testing**, which is not a
nicety: `dnssec-signzone` gives a signature thirty days, so a committed fixture
is a deadline. Left alone it arrives as twenty red tests about Bogus verdicts on
some unrelated push, and the validator is right every time — the signatures
really have expired. The nightly signs on its Linux leg; the gate signs in a job
of its own, because its Windows leg cannot (BIND is not installable there) and
both legs take the result. Running `resign.sh` this often also keeps it working,
which a script used twice a year does not stay.

That leaves the committed fixtures unread by CI, so their expiry is invisible
there. `FixtureFreshnessTests` is what notices on a developer checkout, which is
where a lapsed fixture actually gets in the way: it names the date and the script
instead of letting the DNSSEC tests blame the validator.

The nightly does three further things the gate structurally cannot.

It **runs the interop lane natively**. On a Linux runner `dig`, `kdig`, `drill`
and `named` are ordinary programs on the same loopback as the server under
test — no bridge, no firewall. The `WSL` category keeps its name because that is
where the tools live on a developer machine, but nothing about those tests needs
WSL.

It **runs the two outside verdicts**, which is the point of having them: a
judgment that only ever happens on one developer's machine is not a regression
guard. `genreport` is built from source on the Linux leg, because it is packaged
nowhere; Zonemaster gets a job of its own on a plain `ubuntu-latest`, since it
ships as a container and cannot be run from inside the Debian container the
other jobs use. That job fails rather than skips when a prerequisite is missing,
and fails again if the tests report themselves as not executed — a green tick
that asked nothing is the failure mode worth guarding against here.

And it **tests against Hermod master**, not against the pinned submodule. The
gate answers "would a fresh clone build"; nothing in it notices when Hermod
moves, because a push to Hermod does not touch this repository. A referee that
only ever sees one frozen revision is not refereeing.

### Preparing WSL for the interop lane

```bash
wsl -u root -e sh -c 'apt-get update && apt-get install -y bind9-dnsutils knot-dnsutils ldnsutils bind9 bind9utils'
```

That provides `dig`, `kdig`, `drill`, `delv`, `named` and `dnssec-signzone`.

ISC's `genreport` — the EDNS compliance battery behind dnsflagday, and the only
tool here that reaches its own verdict about Hermod — is not packaged, so it is
built from source once:

```bash
wsl -u root -e sh interop/genreport/build-genreport.sh
```

That clones ISC's repository, builds it, and installs the binary to
`/usr/local/bin`, which a non-login WSL shell has on its `PATH`. It needs
`git`, `gcc`, `make`, `autoconf`, `automake`, `pkg-config` and `libssl-dev` —
but no BIND development package, despite appearances: the tool wants libresolv,
which glibc provides. `GenreportComplianceTests` skips when the binary is
missing.

**Zonemaster** — the registry-grade zone checker, and the suite's other outside
verdict — runs in a container and needs `socat` for the port-53 bridge:

```bash
wsl -u root -e sh -c 'apt-get install -y docker.io socat && for i in zonemaster/cli cznic/knot coredns/coredns mvance/unbound; do docker pull $i; done'
```

The last three of those images are Knot, CoreDNS and Unbound, which serve
BIND's own interop zone so Hermod can be pointed at four encoders instead of
one.

This WSL distribution runs `init` rather than systemd, so nothing starts the
Docker daemon by itself. Either start it for the session:

```bash
wsl -u root -e /usr/sbin/dockerd
```

or make it permanent by putting `[boot]` / `systemd=true` into `/etc/wsl.conf`
and running `wsl --shutdown`. Without a daemon the Zonemaster tests skip with
that instruction.

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
| **1034** | Domain concepts | the CNAME rule (§4.3.2) — an alias answers *every* QTYPE; chains followed in-zone, cycles terminate. Zone cuts end the search: a name below a delegation is answered with the child's NS records and glue, AA clear, while the apex's own NS records are not a delegation to itself |
| **dns-json** | Google/Cloudflare JSON | not an IETF standard, so what it carries is judged by the RFCs that define the records. The `data` field is the presentation form of the RDATA, so it is read by the zone-file reader rather than by a dispatch table of its own ✅ (finding 48) — which had dropped every underscore and wildcard name, every type it did not list including RFC 3597 §5's generic form, and the whole additional section, all without a word. Ten types are sent through both readers and their RDATA compared, so the two cannot drift apart |
| **4035** §3.2, **6840** §5.7 | AD and CD | the two header bits DNSSEC added, read and written on every transport and carried through `Query<T>`'s typed wrapper ✅ (finding 47) — including the JSON API, where they arrive as named fields because there is no header. Reading is the fix; setting them is left to the caller, since §3.1.6 and §3.2.2 make that a policy question. The reserved Z beside them is read past rather than mistaken for a quarter of the RCODE |
| **1035** | Message format | header bit positions, question encoding, name limits (63/255), compression pointers both directions, case preserved byte-exactly, UDP truncation, FORMERR |
| **6891** §6.1.1 | OPT is not zone data | the record interface can write a resource record both ways, to the wire and as a master-file line — so what the zone-file reader returns can be written back without a cast. OPT is the one type that refuses, and says which section: its CLASS is a payload size and its TTL a flags field, so even the columns of a master file would be lies |
| **1035** §5.1 | Master file | the *file*, not the line: `$ORIGIN`, `$TTL` (2308 §4), `@`, an owner name omitted by starting the line with a blank, parentheses across lines, comments outside quoted strings. The class comes from the line — `CH` and `CLASS3` alike, per §3.2.4 — rather than being assumed IN, so `version.bind. CH TXT` is a record the zone can hold and the server already knew how to match. A TTL may carry BIND's units (`1h`, `2w`, `1d12h`), in a record, in `$TTL` and in the four SOA intervals; a number with no unit after it is not one, which is what keeps the header reader from eating a record type. A relative name is completed against the current origin — in the owner and in the RDATA of all fifteen types that hold a name — and refused outright when there is no origin to complete it against ✅ (finding 45). `$INCLUDE` and `$GENERATE` are refused by name rather than skipped. Measured against the same `interop.test.zone` that BIND, Knot, CoreDNS and Unbound are handed |
| **1183** | RP, AFSDB | two-name RDATA |
| **1876** | LOC | the six fields that hold something other than what they mean. §2's scaled octet across all 256 values — 91 of them defined, the rest refused rather than rendered as a sphere wider than the solar system. The 2^31 offset on latitude and longitude and the 100 km offset on altitude, at both ends of the 32-bit range. §3's master-file defaults applied only to fields that are absent, not to fields that were written (finding 28). And the version field checked, with a record this build cannot read written in RFC 3597 §5's generic form — which is the example §5 itself gives |
| **2181** §8 | TTL range | a received TTL with the sign bit set reads as zero rather than as an expiry 136 years out, and every value below the bit is taken literally — the half that stops "always zero" from passing. On the way out the value is capped at 2^31-1 instead of being allowed to spill into the sign bit. OPT is left alone, because RFC 6891 §6.1.3 spends the same four octets on an extended RCODE (finding 38) |
| **2181** §10.1 | Clarifications | an alias owns no other data |
| **2181** §11 | Name syntax | "any binary string whatever can be used as the label of any resource record": a zone-file owner name and the thirteen record types that hold a name in their RDATA all accept the wildcard of RFC 4592 §2.1.1 and the underscore names of RFC 8552, which hostname syntax forbids ✅ (finding 44). Every line of every signed fixture is read, and Hermod's rendering of each is compared against the text BIND wrote for it, with the known divergences asserted as an exact set |
| **2308** | Negative caching | NXDOMAIN vs NODATA kept distinct, both cached per (name, type), TTL = `min(SOA.MINIMUM, SOA.TTL)`, entries actually expire, a referral is not mistaken for NODATA — and on the serving side (§3) every negative answer cites the zone's SOA, without which none of the above has anything to work from |
| **2535** §3, **3445** | KEY | presentation round-trip — KEY and SIG had a writer and no reader, so a line Hermod wrote it could not read back ✅ (finding 46); SIG's signature time reads both forms RFC 4034 §3.2 publishes, the fourteen digits and the count of seconds. Wire round-trip, protocol fixed at 3, the use bits, and "no key information" kept distinct from a key with one use forbidden |
| **2539** | Diffie-Hellman in KEY | length-prefixed prime/generator/public value; a well-known-group index refused rather than read as a literal prime; truncated and over-long RDATA rejected |
| **2782** | SRV | priority/weight/port/target, no RDATA compression on emit |
| **2930** §4.1 | TKEY, Diffie-Hellman mode | keying material against the §4.1 formula applied by hand; nonce order not interchangeable; the derived secret actually signs and verifies as a TSIG key |
| **2931** | SIG(0) | the record shape §3 asks for — root owner, class ANY, TTL 0, type covered 0 — and the signed data of §3.1 assembled by hand and checked with the platform's own RSA and ECDSA rather than with Hermod's verifier: `RDATA \| request` for a query, `RDATA \| query \| response` for a transaction, over the message *before* ARCOUNT counted the SIG(0). Tampering, a foreign key, the right key under the wrong name, and both ends of the validity window all rejected; RSA/SHA-1 refused for signing and still accepted for verifying (RFC 8624 §3.1). End to end: the client signs over UDP *and* over the TCP retry, the server verifies before serving and refuses what does not verify, an unsigned query is still served and a signed one is ignored without error when no key is configured (§3.2), and a message carrying both a TSIG and a SIG(0) is refused |
| **3403** | NAPTR | flags/service/regexp character-strings |
| **3110** §2 | RSA public keys in DNSKEY | both length forms of the exponent: one octet while it fits in one, and a zero octet plus a two-octet length beyond 255 — with 255 itself asserted as the last short one, since "always use the long form" would otherwise pass. No leading zero octet in exponent or modulus. The long form needs a hand-built key, which is also where it stops being portable: OpenSSL will hold such a key and Windows CNG refuses it outright, so these skip on Windows with that reason and the Linux leg is what covers them |
| **3123** | APL | §4 the wire form: the address family, the prefix, and the octet that carries the negation flag in its top bit beside a seven-bit length — plus the MUST that only octets can show, "the sender MUST NOT include trailing zero octets in the AFDPART regardless of the value of PREFIX", since `10.0.0.0/16` and `10/16` print identically and differ only on the wire. §5 the text form both ways, negation included, and an address family RFC 3123 gives no syntax for written in the RFC 3597 §5 generic form rather than an invented one. An empty prefix list is a legal APL and reads back as one. Every expected string is `named-checkzone -D`'s output for the same zone |
| **3596** | AAAA | §2.2 the wire form, full and compressed IPv6 text on input. §2.4 the presentation form, which is "the textual representation of an IPv6 address" and therefore not URI syntax: `IPv6Address.ToString()` brackets `::` and `::1` for an HTTP authority, and that string went into zone files that BIND then refused to load ✅ (finding 50) |
| **4701** | DHCID | §3.1 the identifier type code, digest type code and digest; §3.5 the presentation form, which is base-64 of the whole RDATA block rather than of the digest alone — checked against all three of the RFC's own examples, which between them cover identifier types 0, 1 and 2 |
| **3597** | Unknown RR types | §2 a type with no parser is kept as opaque data, in requests and in responses, and stepping over it leaves the reader where the next record begins — so it costs no record behind it. §3 the RDATA is served back octet for octet, including RDATA that reads as a compression pointer. §4 the eleven post-1035 types that carry a name in their RDATA emit it uncompressed, while the five RFC 1035 types still compress. §5 the `\#` generic form both ways, `TYPEnnn`/`CLASSnn`, a bare decimal read as a TTL and not a class, and a *known* type written generically re-read as that type. §6 RDATA compared as octets, case sensitively |
| **4033/4034/4035** | DNSSEC | key tag (App. B) on both IANA root KSKs, DS digests vs. IANA's published anchor, RRSIG validation against BIND-signed RRsets, canonical ordering, Secure/Insecure/Bogus/Indeterminate classification, expired and not-yet-valid signatures, wildcard reconstruction (§5.3.2). Serving side (§3.1): RRSIGs travel with the answer and denial records with the "no", both only for a querier that set the DO bit; a wildcard answer keeps its RRSIG's `labels` field pointing at the wildcard and carries the proof that the queried name was absent; and a DS query at a zone cut is answered by the parent rather than referred (§3.1.4.1) |
| **4255** | SSHFP | algorithm × fingerprint-type matrix |
| **4025** | IPSECKEY | §2.3's gateway field, whose meaning is decided by the octet before it: none, four octets of IPv4, sixteen of IPv6, or a wire-encoded name whose length "is implicit" and therefore has to be found by walking labels — the one place in this record where being one octet out produces a shorter key that still decodes and still looks like a key. §2.4 the name uncompressed, asserted by walking the RDATA rather than trusting the serializer. §2.5 a record with no key at all, which is legal and which BIND cannot represent in either the presentation or the generic form. Every expected string is `named-checkzone -D`'s own output |
| **4343** | Case-insensitivity | names differing only in case are equal, hash alike, order alike |
| **5952** §4 | IPv6 text | the canonical form a zone file is written in, one case per subsection: §4.1 leading zeros suppressed, §4.2.1 `::` used to its maximum capability, §4.2.2 never for a single zero group, §4.2.3 the longest run and the leftmost of two equal ones, §4.3 lowercase. Written once in `DNSTools.ToZoneFileText` and used by both AAAA and APL, because findings 46 and 48 were each a second implementation quietly disagreeing with the first |
| **4398** | CERT | type/keytag/algorithm |
| **4592** | Wildcards | §2.1.1 the owner name: `*` accepted as leftmost label only, and never by the strict hostname parser — which is the parser the zone-file reader used to reach for, so every wildcard line BIND wrote was unreadable ✅ (finding 44). And the *relative* form of the same name, `*` on its own, which is how a hand-written zone file spells a wildcard and which a separate rule refused — taking the whole zone file with it ✅ (finding 51). §3.3.1 the *matching*: synthesis at the closest encloser and nowhere above it, an exact match and an empty non-terminal each suppressing it, more than one label covered, no type of its own meaning NODATA — and the answer carrying the queried name, with the asterisk absent from the response entirely |
| **5011** | Trust-anchor rollover | 30-day hold-down, no trust on first sight, continuity required, ZSKs ignored, a revoked KSK dropped for good |
| **4035** §2, **5155** §6/§7 | Signing | the direction the stack never had. Every authoritative RRset signed and no delegation's NS RRset or glue; an NSEC chain that closes, or an NSEC3 one with the empty non-terminals §7.1 demands and the opt-out of §6; the labels field of §3.1.3 shortened for a wildcard. **BIND's `dnssec-verify` is the judge** for all six algorithms RFC 8624 §3.1 lets a signer choose, and `dnssec-dsfromkey` for the DS. What it reads is a zone *file*, so the fields that only matter in an answer — the labels field, the opt-out flag — are pinned separately; both of those gaps were found by mutations that survived it. The suite's fixtures stay BIND-signed: a validator measured against its own signatures measures nothing. **And the same signer at runtime**: a zone signed in process by `InMemoryDNSZone.Sign` rather than by `dnssec-signzone`, served by a live Hermod and validated end to end by `delv` — answer, wildcard, NODATA denial and the DNSKEY RRset, under NSEC and NSEC3 both. No fixture is involved: the keys are generated at start-up and the trust anchor is the public half of the one that signed, so nothing on the wire existed before the test ran. The three failures an outside judge cannot see are pinned separately — signing twice must replace rather than accumulate, a record added afterwards makes the signatures stale and says so, and the expiration the zone reports is the one in its RRSIGs rather than one it merely remembers |
| **5155** | NSEC3 | §3.3 presentation format: the salt hexadecimal and the next hashed owner name base32hex, read and written, against the record App. A publishes ✅ (finding 43). Hashing — all twelve hashed owner names of App. A reproduce; salt applied every iteration, iteration count is *extra* rounds, canonical-wire input; Base32hex order-preserving. §8 proofs read: match, cover, closest encloser, opt-out. §7 proofs written: the three-record closest-encloser proof a server owes an NXDOMAIN, the matching record for NODATA, the covering record for a wildcard answer — and never more NSEC3s than asked for, since every spare one is free zone-walking material. §6 opt-out, against a zone BIND signed with `-A`: the flag on every record, no NSEC3 for the insecure delegation, and the §7.2.7 referral proof whose covering record carries the flag |
| **5452** | Spoofing resistance | §9.2 transaction IDs span the 16-bit space. §9.1's six-item list of what a response MUST match. Three items are the connected socket's - source and destination address, destination port - which leaves three for the resolver: the query name, class and type, each compared against the outstanding question on every transport, with a response carrying no question section at all matching nothing ✅ (finding 49). The comparison is RFC 4343's, case-insensitive, so a server that folds the QNAME before answering is still answering — a fix that compared octets would refuse most of the deployed world. §4.2 a non-matching response is ignored and not fatal, where *ignored* means the query keeps waiting: the reaction finding 5 fixed on the ID, now reached by the check finding 49 added |
| **6605** | ECDSA | P-256 and P-384: fixed-width r‖s, 64/96-octet keys |
| **6672** | DNAME | the substitution of §2.2 on labels rather than characters — so a name that merely ends with the owner's spelling is not redirected, and neither is the owner itself (§2.3). Served: the DNAME in the answer, the synthesized CNAME beside it with the DNAME's TTL (§3.1, where RFC 2672 said zero), YXDOMAIN when the rewritten name passes 255 octets (§2.2), records below the owner occluded (§2.4), and a chain into its own subtree bounded. Followed: the same substitution in the resolver, shared rather than written twice. `delv` validates the redirection end to end, including the CNAME carrying no signature |
| **6762**, **6763** | mDNS and DNS-SD | independent wire assertions for three probes and two announcements, ID/AA/RD/QU semantics, unique cache-flush versus shared PTR records, DNS-SD PTR answers carrying SRV/TXT/A additionals, TTL-zero goodbyes, and legacy-unicast ID/question/TTL behavior. Bidirectional live interop: native `dns-sd` discovers Hermod and Hermod resolves a native `dns-sd` publication |
| **6698**, **8162** | TLSA, SMIMEA | usage/selector/matching-type, underscored owner names |
| **6891** | EDNS0 | OPT wire form (golden bytes), extended-RCODE combining, exactly one OPT, BADVERS for version > 0, payload-size negotiation |
| **6895** §3.1, §3.2 | IANA registries | the two registries that decide which number means what. On the wire: no response carries a QTYPE-only code point as a record TYPE or CLASS, TYPE 0 and the obsolete mail QTYPEs are answered NODATA with the zone SOA, and `*` is still served with data types — without which "answers nothing" would satisfy the rule. In presentation format: each mnemonic checked against the suite's own table, class 254 is NONE and class 0 is reserved with no name at all (finding 39) |
| **7043** | EUI48, EUI64 | fixed-width RDATA |
| **7208** | SPF | multi-character-string concatenation |
| **7344**, **8078** | CDS, CDNSKEY | the records mirror DS and DNSKEY (7344 §3.1/§3.2), and the protocol around them. RFC 8078 §4's delete sentinel — `CDS 0 0 0 0`, `CDNSKEY 0 3 0 0` — recognised only in the mandated form and only as an RRset of exactly one record, since a sentinel beside a real CDS asks for a DS to be installed and for all of them removed at once. RFC 7344 §4.1's acceptance rules, which are what keeps the sentinel from being a way for anyone who can write in a child zone to switch its DNSSEC off: apex, signed by a key in **both** the current DNSKEY and DS RRsets, and not breaking the delegation |
| **7477** | CSYNC | SOA-serial + flags + type bitmap |
| **7553** | URI | target is raw remaining octets, **not** a domain name |
| **7766** | DNS over TCP | 2-byte framing, TC→TCP fallback, split/dribbled reassembly, connection reuse, recovery on close |
| **7828** | TCP Keepalive | the option — zero-length in queries, 2-byte 100 ms units in responses — and whether it ever reaches the wire. §3.3.2 makes an OPT RR in the query, not the keepalive option, what lets a server volunteer a timeout, so the OPT record is measured on each client transport in turn: DoT and plain TCP send one and read an unsolicited timeout back, the UDP client's TCP retry sends one and ignores what arrives (§3.2.2 permits that), and plain TCP used to send none at all (finding 34). Then both of §3.2.2's endings, on both connection-holding clients and counted in handshakes rather than taken on trust: TIMEOUT 0, the server asking for its connection back, ends the session at once (findings 35, 36), and an advertised idle timeout ends it before that timeout expires rather than after — asserted as a deadline, not merely as an eventual close (finding 37) |
| **7830**, **8467** | Padding | the option and the *policies*. RFC 7830 §4's two rules that leave the responder no choice — pad when the query carried the option, never pad when the query indicated no EDNS(0) — and §4's ceiling, the requestor's payload size, which shortens the padding rather than dropping it when it disagrees with the block length. RFC 8467 §4.1's blocks, 128 for queries and 468 for responses, each reached at the first boundary that holds the message rather than any boundary above it. §3's wire rules: option code 12, at most one per OPT meta-RR, all-zero octets outbound and octets of any value accepted inbound. Both sides measure *after* signing, so a TSIG or SIG(0) record is inside the block the observer counts — the combination neither RFC addresses. On **DoH** as well: RFC 8467 §1 scopes itself by property rather than protocol — "other encrypted DNS transports specified in the future" — and RFC 8484 §9 asks for the same thing from its side, so the 128-octet query block applies there too. What differs on DoH is the ceiling, which §6 tells a responder to ignore, and the collision with base64url: a message padded to 128 has length ≡ 2 (mod 3), so §4.1's block puts *every* GET into the one encoding case where a `=` would appear and must not |
| **7858** | DoT | client and server; framing over TLS, session reuse (3 queries → 1 handshake) |
| **7871** | Client Subnet | family, prefix length, address truncated to the prefix |
| **7873** | Cookies | the protocol, not only the encoding. Client (§5.3): a response echoing a client cookie that was never sent is discarded, and only the *server* half of a returned cookie is ever stored — the client cookie is the one unpredictable value in the mechanism, and a peer able to set it has neutralised it. BADCOOKIE is retried once with the cookie the response supplied. Server (§5.2): a server cookie bound to the client cookie, the client's address and a timestamp, BADCOOKIE with a fresh cookie when it is missing or wrong, FORMERR for the option lengths §5.2.2 rules out, and no change at all to a query that carries no cookie. §4.1: the client cookie is *derived* from the client address, the server address and a client secret rather than remembered — stable per server, different for any two servers (the MUST in that paragraph), and changing by itself when this host's address does, which is what the client address is in the input for |
| **9018** | Interoperable server cookies | §4's structure and §4.4's `SipHash-2-4(Client Cookie \| Version \| Reserved \| Timestamp \| Client-IP, Server Secret)`, pinned to all four vectors of Appendix A — including the byte order §4.4 does not state and the vectors settle. §4.3's timestamp window compared with RFC 1982 serial arithmetic, so the 2106 wrap does not make every fresh cookie look 136 years old |
| **7929** | OPENPGPKEY | binary blob |
| **8080** | Ed25519, Ed448 | both directions. Verifying: raw 32/57-octet keys against BIND-signed fixtures. Signing: all four §6 examples reproduced as exact byte strings — which EdDSA's determinism (RFC 8032 §5.1.6) makes possible and which a sign-then-verify round trip could not do, since pre-hashing or a non-empty Ed448 context verifies against itself and nothing else. Public keys derived from the private half rather than carried beside it, and SIG(0) signed with all six algorithms RFC 8624 §3.1 permits, end to end over a socket |
| **8198** | Aggressive NSEC caching | ranges judged in canonical order, not string order; the zone taken from the SOA rather than guessed; and an NSEC that was never DNSSEC-validated never reaches the cache |
| **8310** §8.1 | DoT auth profile | a rejecting certificate validator means no query leaves the host |
| **8484** | DoH | *Client:* GET `?dns=` base64url **unpadded**, POST content types, no trailing bytes, HTTP errors never reach the wire parser. *Server:* both methods, base64url decoded at every length mod 3, `application/dns-message` with no charset §7.1 never registered, NXDOMAIN and NODATA carried by 200 while a 4xx carries no reply at all, 415/406/405-with-Allow for the requests that never became a DNS question, §5.1 freshness from the smallest Answer TTL or the SOA MINIMUM rather than the SOA's own TTL, and §6's ignored payload size — which neither truncates the answer nor shortens its padding. Driven by `RawDoHProbe`: .NET's HTTP stack and the suite's own base64url, never Hermod's. Every server row asserted twice, once per HTTP version — §5.2 recommends HTTP/2 for performance and changes no requirement of §4, so both listeners answer to all of it, and one port serving both under ALPN answers byte-identically either way |
| **8624** | Algorithm selection | every algorithm 8624 asks a *validator* to implement — 8, 10, 13, 14, 15, 16 — verifies a real BIND signature; deprecated RSA/SHA-1 (5, 7) still validates, as it must |
| **8659** | CAA | critical-flag bit, length-prefixed tag, unprefixed value |
| **8914** | Extended DNS Errors | info-code + extra-text |
| **8945** | TSIG | MAC over message + §4.3.3 variables, checked against HMAC applied by hand; CLASS ANY, TTL 0, last in additional, ARCOUNT counts it; BADSIG / BADKEY / BADTIME kept distinct; the fudge window, a rewritten message ID, a response bound to its request's MAC. End to end: the server verifies signed queries and signs its replies, the client signs and checks the answer — including on the TCP retry after a truncated datagram, which used to go out unsigned. Both mechanisms ride every transport: UDP, TCP, DoT and DoH, the last two asserted by reading the message back out of the TLS framing and out of a `?dns=` parameter |
| **8976** | ZONEMD | serial/scheme/hash |
| **9460** | SVCB, HTTPS | alias and service mode, SvcParams parsed to RDLENGTH |

All eight signature algorithms Hermod's validator claims are covered against
real BIND signatures, each from a zone signed with that exact algorithm rather
than a shared fixture: 5, 7, 10, 13, 14, 15 and 16 in
`SignatureAlgorithmMatrixTests`, and 8 (RSA/SHA-256) as the main `dnssec.test`
fixture zone in `RrsigValidationTests`.

**And BIND's own validator agrees.** `delv` — pointed at a Hermod server serving
the signed fixture zone, with that zone's KSK as its trust anchor — reports
*fully validated* for a signed answer, a wildcard answer, an NSEC name error, an
NSEC NODATA, an NSEC3 closest-encloser proof, and the DNSKEY RRset. That last
one only arrives over the TCP retry, since two 2048-bit keys and their signature
do not fit in a datagram.

This matters more than the count suggests. Every other DNSSEC test here compares
what Hermod sent against the records BIND *wrote* — which catches an invented or
mangled record and cannot catch a wrong reading of RFC 4035 §3.1 or RFC 5155 §7,
because the same reading produced both the server and the assertions. `delv`
brings its own, from the people who wrote the signer. A companion test hands it
the identical answer under a trust anchor with the right name and the wrong key
and requires it to refuse — otherwise "fully validated" would only prove that
`delv` says yes.

### Queued — on the todo list

| RFC / area | What is missing | Blocker |
|------------|-----------------|---------|
| **2930** (GSS mode) | GSS-TSIG, the TKEY mode that is actually deployed | needs a Kerberos/SPNEGO stack, which is not something a DNS library grows on its own |

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

**SIG(0) carries the same caveat**, for the same reason: RFC 2931 gives the
formula and no worked example. The tests assemble the signed data from §3.1 by
hand and check it with the platform's own RSA and ECDSA, so the oracle is at
least not the code under test — but it is still one reading of the specification
rather than an agreed set of numbers. The one place that reading is pinned
harder is the ARCOUNT: a signature taken over the incremented count is asserted
*not* to verify, which is the difference between interoperating and merely
round-tripping against yourself.

**Neither mechanism applies to DoH's JSON APIs, and that is not a gap.**
RFC 8484 §4.1 carries a DNS message, so a signature over that message survives
base64url encoding untouched — which is what the DoH tests read back out of the
`?dns=` parameter. Google's and Cloudflare's `application/dns-json` carries a
*rendering* of an answer instead: there are no octets to authenticate, and
nothing to sign or check.

**RFC 7129 is not in the covered list even though its subject is**, because it
is informational and nothing normative can be asserted against it. What it
explains — which records a signed zone owes each kind of negative answer — is
covered under RFC 4035 §3.1 and RFC 5155 §7, and 7129 remains the readable
account of why those particular records.

One entry, and it is the blocked one — that column is not decoration.
Everything else this list once held has been done; what is left needs a
Kerberos/SPNEGO stack before a single assertion can be written. It sits here
rather than under *Out of scope* because it is a gap and not a refusal: GSS-TSIG
is what is actually deployed, and a suite that judged Hermod's transaction
security without saying so would be quietly flattering it.

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
| **7626**, **9076** privacy considerations | Informational — no testable requirement to assert. |
| **7671**/**7672**/**7673** DANE usage | The suite asserts the TLSA/SMIMEA *record*. What a mail or web client does with it is above the DNS layer. |
| **9250** DoQ, DNS over HTTP/3 | No QUIC in Hermod at all. |

## Projects

```
src/DNSConformance.Core          shared infrastructure (not tests)
conformance/                     RFC conformance, offline
  …WireFormat.Tests              RFC 1035 header, names, compression, TTLs
  …ResourceRecords.Tests         43 RR types: wire format, presentation format, round-trips
  …Edns.Tests                    RFC 6891 OPT + typed EDNS options
  …Multicast.Tests               RFC 6762 mDNS + RFC 6763 DNS-SD wire behavior
  …Client.Tests                  client vs. scripted servers
  …Server.Tests                  Hermod server vs. raw sockets
  …SecureTransports.Tests        RFC 7858 DoT, RFC 8484 DoH
  …Dnssec.Tests                  key tags, DS digests, RRSIG validation, zone signing
interop/                         interoperability
  …PublicResolvers.Tests         Cloudflare / Google / Quad9, all transports
  …LinuxTools.Tests              dig, kdig, drill, delv and ISC genreport vs. the Hermod server
  …Multicast.Tests               native dns-sd ↔ Hermod live interop
  …ExternalServers.Tests         BIND, Knot, CoreDNS, Unbound as servers; Zonemaster
fixtures/                        test zones, BIND config, DNSSEC material
  bind/format.test.zone          hand-written: the format cases a generated zone cannot hold
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
  read what Hermod's server writes. In the other direction, `dnssec-verify`
  judges zone files Hermod's own signer wrote, `dnssec-dsfromkey` judges the
  DS it derives, `named-checkzone` settles what the master file format
  actually permits, and `delv` validates the answers a live Hermod gives from
  a zone it signed itself — which is the only one of these that sees the
  fields existing solely in a response, and therefore the only one that could
  have caught the labels field or the opt-out flag.
- **A second, hand-written corpus** — `fixtures/bind/format.test.zone`
  exists because the first one could not contain the cases that matter.
  The DNSSEC fixtures are `named-compilezone` output: every name written
  out in full, every TTL a bare number, so a relative wildcard and a
  bracketed `::1` could not appear in them and therefore could not be
  refuted by them — which is how findings 50 and 51 survived fifty
  findings of zone-file work. `named-checkzone -D` flattens the new file
  and Hermod's reading of it is compared record for record, as an exact
  set in both directions.

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
