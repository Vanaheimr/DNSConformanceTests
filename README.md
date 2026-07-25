# Hermod DNS Conformance & Interoperability Test Suite

An independent .NET 10 test solution that measures the DNS client and server of
[Vanaheimr Hermod](https://github.com/Vanaheimr/Hermod) against the DNS RFCs,
and against real implementations: ISC BIND, Knot DNS, NLnet Labs ldns and the
public resolvers.

Hermod and Styx are consumed as git submodules under `libs/`, so the suite can
be pointed at any Hermod revision and acts as an unbiased referee.

- **[PLAN.md](PLAN.md)** — architecture and the full RFC coverage matrix
- **[FINDINGS.md](FINDINGS.md)** — conformance deviations this suite found

**Current status: 284 tests · 283 ✅ · 1 ❌.**

The suite has found 15 RFC deviations. Fourteen are fixed in Hermod; one is open,
and it is pinned by a red test tagged `KnownIssue` so it cannot be forgotten. [FINDINGS.md](FINDINGS.md) records every one with chapter and verse,
and — for the fixed ones — the change and the test that pins it.

Excluding `KnownIssue` gives a green gate:

```bash
dotnet test DNSConformanceTests.slnx --filter "TestCategory!=Online&TestCategory!=WSL&TestCategory!=Docker&TestCategory!=KnownIssue"
```

## Getting started

```bash
git submodule update --init --recursive
dotnet build DNSConformanceTests.slnx
```

Everything that needs no network, WSL or Docker:

```bash
dotnet test DNSConformanceTests.slnx --filter "TestCategory!=Online&TestCategory!=WSL&TestCategory!=Docker"
```

To see only the open deviations — every one of these is expected to fail, and a
*passing* test here means a finding has been fixed and should be untagged:

```bash
dotnet test DNSConformanceTests.slnx --filter "TestCategory=KnownIssue"
```

Tests requiring prerequisites `Assert.Ignore` with an actionable message rather
than failing, so a bare checkout is always green-or-skipped.

## Test categories

| Category | Needs | Run with |
|----------|-------|----------|
| *(none)* | nothing — loopback sockets only | the default filter above |
| `Online` | outbound DNS (UDP/53, TCP/853, HTTPS) | `--filter "TestCategory=Online"` |
| `WSL` | WSL + BIND/Knot/ldns tools | `--filter "TestCategory=WSL"` |
| `Docker` | a reachable Docker daemon | `--filter "TestCategory=Docker"` |
| `Slow` | > ~5 s runtime | exclude to keep the inner loop fast |
| `KnownIssue` | — | marks a confirmed deviation ([FINDINGS.md](FINDINGS.md)) |

### Preparing WSL for the interop lane

```bash
wsl -u root -e sh -c 'apt-get update && apt-get install -y bind9-dnsutils knot-dnsutils ldnsutils bind9 bind9utils'
```

That provides `dig`, `kdig`, `drill`, `delv`, `named` and `dnssec-signzone`.

If the WSL tools cannot reach the Hermod server, it is almost always a Windows
Firewall rule blocking inbound traffic from the WSL subnet — the tests detect
this and skip with that explanation.

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
and writes the matching DS record.

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
