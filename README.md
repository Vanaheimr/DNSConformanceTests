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

**Current verified status on Windows (2026-10-28): 1639 ✅ · 0 ❌ · 4 skips** — the
four are platform-specific: Windows CNG refuses RSA public exponents of 255
octets and more, so RFC 3110's long exponent form is covered by the Linux leg.
The thirty-three tests that need container images ran this time. `cznic/knot`,
`coredns/coredns`, `mvance/unbound` and `zonemaster/cli` are pulled — 185 MiB
compressed, deliberately and never by a test run — into the Docker daemon inside
the Debian WSL instance, which is where the tests look for it: they run `docker`
through `wsl -u root` rather than through a Windows client, and a `docker info`
typed into a Windows shell answers "command not found" whatever the daemon is
doing. That daemon does not start by itself (see
[Preparing WSL](#preparing-wsl-for-the-interop-lane)); without it the
thirty-three skip and say so.

Nothing is excluded from that figure, and it has no red tracker tests: when it was
measured there was no open finding for one to track. Findings 64 to 66 were opened and
closed on the same day: their four tracker cases were red at 360c8e28
(1587 ✅ otherwise). So was finding 67, whose fix Vanaheimr/Hermod#148 was
written in parallel with its tracker: its four cases — the tracker in two, and two
tests in `ChainWalkTests` that assert the same rule one step up — were red at
8dc9663a (the DNSSEC project 327 ✅ · 4 ❌ otherwise). So were findings 68 to 70,
the three neighbours #148 closed with it and recorded afterwards: their trackers,
and the tests for two more links of 67, were Secure at 8dc9663a and pass from
12baa4e6 on. So was finding 71, whose fix Vanaheimr/Hermod#150 was merged before its
tracker was written: its eight cases were red at the previous pin (12baa4e6, the
DNSSEC project 335 ✅ · 8 ❌ otherwise). So were findings 72 to 75, which Hermod's
master fixed on 2026-10-04 without the suite noticing, until the nightly lane that
runs against that master went red on two tests that had pinned the old verdict as
correct: their eight cases were red at the previous pin (b64479e9, DNSSEC 342 ✅ ·
4 skips and client 156 ✅ otherwise). So were findings 76 and 77, a root zone
signed with NSEC3, which the second DNSSEC mutation round found on 2026-10-28 and
Vanaheimr/Hermod#162 fixed: their five trackers were red at bbbf88b6 (DNSSEC
370 ✅ · 5 ❌ · 4 skips otherwise) and pass from 925c80d5 on. All of them are among
the 1639 now, and so are the tests of that round. Of the 1643 tests, 1512 are the
offline suite as `ci.yml` runs it — every project, with the Online, WSL, Docker
and Multicast categories left out — which is 1508 ✅ · 0 ❌ · 4 skips.

The Multicast DNS querier tests came after that run: 66 cases for the client and
the browser, nine of them the trackers of findings 78 to 85, red at 925c80d5 and
passing from b514b630 on. There the Multicast project is 97 ✅ · 0 ❌, and the
offline suite 1574 ✅ · 0 ❌ · 4 skips.

So did the tests written for the client block's open mutation rows: 43 cases for
the transport clients, the convenience lookups and the JSON mode of DoH, four of
them the trackers of finding 86, red at b514b630 and passing from f3c0517c on.
Two older tests went with that fix, because what they checked was a query of two
questions. One of the new ones found a DoH query running past its deadline, 8.2 s
for 3 s against a refused port, and one more pins the same for a server gone
between two queries; no RFC speaks to that, and the same Hermod change fixes it.
With them the Client project is 199 ✅ · 0 ❌, and the offline suite 1615 ✅ ·
0 ❌ · 4 skips.

Twelve more followed, three for each transport client: a query whose client is
disposed under it, a query for two types against a server that never answers,
and the runtime a failure reports. None of the three is an RFC matter. All
twelve were red at f3c0517c, except the two-type cases for UDP and DoH, which
are the control. Vanaheimr/Hermod#184 fixed them, and #186 and #190 a race it
left, in which a TCP query whose client went away came back as a timeout once in
a full run; they pass at cbdd1bb1.

And the tests for findings 87 to 89. Four cases for RFC 7766 §6.2.1.1, two of
them the trackers of finding 87 and two the controls that show the test server
can tell a client that pipelines from one that waits; and eight for RFC 9460
§2.1, six of them the trackers of finding 88; and thirty-four for RFC 9460's
own test vectors, twenty-six of them the trackers of finding 89. All of the
trackers were red at 4f116936 and pass from cbdd1bb1 on. With them, and the two
`RecordBranchTests` cases that keep an escaped quote inside a quoted SvcParam
value (MUTATION.md, *One row per mutant*), the Client project is 215 ✅ · 0 ❌,
the ResourceRecords project 502 ✅ · 0 ❌, and the offline suite 1675 ✅ · 0 ❌ ·
4 skips.

And the tests the mutation sweep asked for when it measured finding 89's fix
again (MUTATION.md, *The result: the SvcParam presentation, measured again*):
thirty-four cases that ask each SvcParamKey at its edges and hand the writer
octets its keys cannot hold, and twenty-four for RFC 9460's failure vectors,
six of them the trackers of finding 90, red at cbdd1bb1 and passing from
f11dad26 on. With them the ResourceRecords project is 560 ✅ · 0 ❌.

And the tests it asked for when it measured finding 87's fix (MUTATION.md, *The
result: the stream clients, measured*): twenty-four cases against a server that
reads every query as it arrives and tells its connections apart. Ten ask what a
client does with a connection that ends under a query, nine what it does with
an edns-tcp-keepalive TIMEOUT, of 0 above all, two whether an answer out of order
reaches its caller at once, and three what comes next for a client that was
disposed, or whose connection was refused. Eight of them are the trackers of
findings 91 and 92, red at cbdd1bb1 and passing from f11dad26 on. With them the
Client project is 239 ✅ · 0 ❌, and the offline suite 1757 ✅ · 0 ❌ · 4 skips.

And the test it asked for when it measured the fixes for findings 90 to 92
(MUTATION.md, *The result: both slices again, after findings 90 to 92*): two
cases that read AliasMode records, one SVCB and one HTTPS. RFC 9460 §2.4.2 has a
recipient ignore an AliasMode record's SvcParams, so `mandatory` without its key
and `no-default-alpn` without `alpn` are read there, while §2.1's key written
twice is refused in every mode. With them the ResourceRecords project is
562 ✅ · 0 ❌, and the offline suite 1759 ✅ · 0 ❌ · 4 skips.

And the case the second multicast sweep found (MUTATION.md, *The result:
multicast after findings 78 to 85*): RFC 6762 §16 folds "a" to "z" in names and
nothing else, while Hermod's multicast code folded `É` to `é` as well. Four
trackers pair `Café` with `CafÉ`, each beside a control in which the
two names differ in an ASCII letter's case. They are finding 93, red at 0f595ac4
and passing from c5b4ce08 on. With them the Multicast project is 104 ✅ · 0 ❌, and
the offline suite 1766 ✅ · 0 ❌ · 4 skips.

And the tests the same sweep asked for (MUTATION.md, *Fourteen of fifteen, and
the one finding 93 took away*): thirteen cases at the edges of the querier's new
code. Four ask how known answers are split across packets and how many are
listed (RFC 6762 §7.1, §7.2, §17), five which of another host's queries stand in
for a browser's own (§7.3), and four what an expiring SRV record, and a TXT
record that empties or fills, change about an instance (RFC 6763 §5, §6.1). One
assertion more says a probe sets no TC bit (§18.5). With them the Multicast
project is 117 ✅ · 0 ❌, and the offline suite 1779 ✅ · 0 ❌ · 4 skips.

And the tests the responder's open rows asked for (MUTATION.md, *The
responder's thirty-seven*): twenty-one cases. Two say from when a response heard
while probing counts: from the first probe on, a record of any type at the name
is a conflict, and before it a record of another type is ignored (RFC 6762
§8.1). Six what the responder sends as it publishes, changes and withdraws: no
probe for shared records alone, no goodbye for a publication withdrawn while
probing, a changed address announced as often as the first, a goodbye for a
shared record taken out, and announcements split across packets, with a record
too large for any packet sent alone (§8.1, §8.3, §8.4, §10.1, §17). Twelve which
queries are answered, and how: a unicast query only from the local link (§5.5,
§11), none with a nonzero opcode or rcode (§18.3, §18.11), a question of class
ANY as one of class IN (RFC 1035 §3.2.5), a negative answer where the question
asked for it (§5.4, §6.1), and only an answer from a shared record set after a
delay (§6). And one says a record may be multicast again exactly one second
later (§6). With them the Multicast project is 138 ✅ · 0 ❌, and the offline
suite 1800 ✅ · 0 ❌ · 4 skips.

And the case those tests found: RFC 6762 §8.1 has a responder silently ignore
every response heard before its first probe, and Hermod took another address for
the name, heard in the delay before that probe, for a conflict. The case is
finding 94, red at c5b4ce08 and passing from cdc03cc6 on. With it the Multicast
project is 139 ✅ · 0 ❌, and the offline suite 1801 ✅ · 0 ❌ · 4 skips.

And the tests the client's and the browser's open rows asked for (MUTATION.md,
*The client's twenty-nine and the browser's twenty-eight*): twenty-seven cases
and one assertion. For the client: a lookup reports an answer as authoritative,
whole and not recursive, whatever the header said (RFC 6762 §18.4 to §18.7); the
cache answers what it holds, and ForceUpdate asks anyway; a record is no answer
once its TTL has run out, and is reported expired once (§5.2); §10.2 flushes
what was received more than one second ago and lists no known answer with the
cache-flush bit; and a goodbye costs nothing else in its packet and is no
additional record (§10.1). For the browser: a record heard again is no update
and draws no query, while a new address is an update; an instance is asked about
again for what it still lacks (RFC 6763 §6); an address reaches its instance
and, when it expires, changes only the instances on its host; an instance never
reported goes without a report; the query at 80 % is not repeated on every tick
(§5.2); and an instance whose pointer was cleared from the cache goes after 75
minutes (§10). With them the Multicast project is 166 ✅ · 0 ❌, and the offline
suite 1828 ✅ · 0 ❌ · 4 skips.

And the case those tests found: RFC 6762 §5.2 plans the queries that keep a
record alive at 80, 85, 90 and 95 % of its lifetime, each with a random
variation of 2 %, and Hermod's browser asked once, at 80 % exactly. The case is
finding 95, red at cdc03cc6 and passing from 3050ab75 on. With it the Multicast
project is 167 ✅ · 0 ❌, and the offline suite 1829 ✅ · 0 ❌ · 4 skips.

And the tests the message's and the helpers' open rows asked for (MUTATION.md,
*The message's twenty-seven and the helpers' thirty-three*): thirty-three cases
and two assertions. Hermod's message reader refuses ten packets RFC 1035 §4.1
cannot walk, takes a header alone for a message, and reads AA and RD where they
are; compressed names are decoded (RFC 6762 §18.14); a question matches records
of its class; a probe's records carry no cache-flush bit (§10.2) and a response
no TC bit (§18.5). The hybrid client sends local. and the link-local reverse
domains, and only those, to Multicast DNS (§3, §12); an NSEC bitmap has no
trailing zero octet (RFC 4034 §4.1.2); the tie-break lets the longer list win
and compares rdata uncompressed (§8.2.1); and a unique record taken out with its
whole RRSet gets a goodbye (§10.1). With them the Multicast project is
200 ✅ · 0 ❌, and the offline suite 1862 ✅ · 0 ❌ · 4 skips.

And the case those tests found: RFC 1034 §3.7.1 has a query ask for records that
match its class, "just that class", and Hermod's Multicast DNS client took an
address of class CH for the answer to a lookup of class IN, from the link and
from the cache, while its browser made an instance of a service announced in
class CH. The cases are finding 96, red at 3050ab75 and passing from a12603df
on. With them the Multicast project is 203 ✅ · 0 ❌, and the offline suite
1865 ✅ · 0 ❌ · 4 skips.

And the tests the UDP transport's sixty open rows asked for (MUTATION.md, *The
transport's sixty*): fourteen cases over the host's own sockets, and so in the
Multicast category. A transport at its defaults hears 224.0.0.251 and FF02::FB
on every interface that is up (RFC 6762 §3); two transports on one port hear
each other's multicasts (§15.1); a transport of one address family works over
that family alone (§20); a multicast is on the local link whatever its source,
and a unicast when its source shares a prefix with the receiving interface
(§11); a response leaves on the interface its query came in on and nowhere else
(§14, §6.2); and a legacy query is answered by unicast to its source (§6.7).
With them the Multicast project is 217 ✅ · 0 ❌, and the offline suite, which
leaves the Multicast category out, 1865 ✅ · 0 ❌ · 4 skips.

And the case those tests found: RFC 6762 §7.3 lets another host's query stand in
for one's own, and Hermod's browser took its own query for another host's when
it came back over IPv6, from a link-local address the transport does not list.
It sent every second query of its series. The case is finding 97, red at
a12603df and passing from d906af2d on. With it the Multicast project is
218 ✅ · 0 ❌, and the offline suite 1865 ✅ · 0 ❌ · 4 skips.

And the tests the client block asked for when it was measured again
(MUTATION.md, *Thirty-five of thirty-five, and two answers that misreported their
time*): twenty-three cases. They cover a cached answer that holds the RRset with
its signatures and the CNAME or DNAME chain that leads to it, each link signed
(RFC 4035 §3.1.1, RFC 6672 §5.3.1), and is a miss for an expired link or a loop
(RFC 1034 §3.6.2). They cover the addresses to connect to, with RFC 8305 §3's
Resolution Delay for the other family. And a server listed twice is one server,
DoH asks for recursion when nobody said otherwise, an empty JSON body is a
failure like any other, and a disposed DoH client sends nothing. Three of the
cases were red at d906af2d. A UDP query whose TCP retry ran out of time reported
a failure rather than a timeout, and a response refused for not answering the
question reported a timeout and a runtime of zero. Neither is an RFC deviation,
so neither is a finding. The three pass from 38f6a355 on. With them the Client
project is 262 ✅ · 0 ❌, and the offline suite 1888 ✅ · 0 ❌ · 4 skips.

And §11's other half, which needs a second host: with the WSL virtual machine as
one, a unicast from an address on no subnet of the receiving interface is not on
the local link, and a multicast from it is. The two tests are in the WSL
category as well. With them the Multicast project is 220 ✅ · 0 ❌.

And the two cases the server block asked for when it was measured again
(MUTATION.md, *A body that was never sent, and a server that was not stopped*).
A POST with no content at all, which HTTP/2 sends as a single HEADERS frame (RFC
9113 §8.1), is refused with 400 like an empty one (RFC 8484 §4.1), over both
versions of HTTP. And a disposed DoH/2 server no longer listens on its port.
Hermod passed both already. With them the SecureTransports project is
167 ✅ · 0 ❌, and the offline suite 1891 ✅ · 0 ❌ · 4 skips.

And the case the transaction-security block asked for when it was measured
again (MUTATION.md, *The key a refusal is handed*). Handed the key it shares
with the sender, the TSIG signer still answers BADSIG and BADKEY with an
unsigned refusal (RFC 8945 §5.2.1, §5.2.2, §5.3.2), and with the same key it
signs a BADTIME one (§5.2.3). Hermod passed it already. With it the Dnssec
project is 376 ✅ · 0 ❌ · 4 skips, and the offline suite 1892 ✅ · 0 ❌ · 4 skips.

And the cases the resource-record block asked for when it was measured again
(MUTATION.md, *Eight of fifteen*): eight. An SSHFP in RFC 3597 §5's generic
form is the same record as in its own (RFC 4255 §3.1.3, RFC 6594 §3), and a
DHCID of exactly its header has its two type codes in base64 as well (RFC 4701
§3.5). A signature time at the epoch and at the last second 32 bits can count
is read, and one second past either end is refused (RFC 4034 §3.2). A `\X`
quotes one character even when two digits follow it, and `\255` is one octet
(RFC 1035 §5.1). Hermod passed them all already. With them the ResourceRecords
project is 570 ✅ · 0 ❌, and the offline suite 1900 ✅ · 0 ❌ · 4 skips.

And the three things the other seven rows found. A bare decimal that a class
has the number of, 1 for IN, 3 for CH, was read as that class and not as the
TTL, and a comma-separated list of mnemonics as the two values combined: `A,MX`
as MX (RFC 1035 §5.1, RFC 3597 §5). A URI record's target was read as an HTTP
URL, so `mailto:` gained an `https://` and `urn:` was refused (RFC 7553 §4.4,
RFC 3597 §3). And a quoted TXT string the escape reader refused was read a
second time as unquoted text, backslashes and all, and so was every line with
a string written without quotes, and every SPF record (RFC 1035 §5.1, RFC 7208
§3.3). The cases are findings 98 to 100, thirty-four of them, red at 38f6a355
and passing from cf1e9954 on. Four older cases had asserted what the old
readers did: two read a TXT line written without quotes as one string with its
backslash, and two read JSON data that mixes quoted and bare strings as one
text. The four now say what BIND says. With them the ResourceRecords project is
609 ✅ · 0 ❌, and the offline suite 1939 ✅ · 0 ❌ · 4 skips.

And the cases the readers of those three fixes asked for when they were measured
(MUTATION.md, *The result: the presentation readers of findings 98 to 100*):
five.
- A `\DDD` with only its second or only its third character wrong is refused,
  as BIND refuses it (RFC 1035 §5.1).
- Google's JSON text for a TXT can begin with a quote and hold a backslash that
  no escape reads: at the end, before two digits at the end, or as `\256`. It
  is that one text, and not nothing.

Hermod passed them all already. With them the ResourceRecords project is
614 ✅ · 0 ❌, and the offline suite 1944 ✅ · 0 ❌ · 4 skips.

And the names a resolver answers itself (RFC 6761 §6.3, §6.4), asked while the
client block was measured a third time. The cache answers `localhost.` with
the loopback addresses, and that is all Hermod did. A name below it, such as
`www.localhost.`, and an MX or TXT query for localhost went to the configured
server. So did localhost itself from a client without a cache, with
`ForceUpdate`, or after `SetDNSServers` had emptied the cache. So did every
name below `.invalid`, and whatever the server answered was the answer.
`NameResolution`, which Hermod's other clients resolve through, took only the
text `localhost` as the loopback addresses. The cases are findings 101 and 102,
nineteen of them, red at cf1e9954 and passing from 56f2c957 on. With them the
Client project is 282 ✅ · 0 ❌, and the offline suite 1964 ✅ · 0 ❌ · 4 skips.

And the same names asked of the server (RFC 6761 §6.1 to §6.4, items 5 and 6).
Hermod's authoritative server refused every special-use name it served no zone
for: `localhost.` and the names below it, every name below `.invalid`, the test
names outside `conformance.test.` and the private-address reverse names. And it
served what a zone held at `localhost.` or `host.invalid.`, which the RFC fixes
whatever is configured. The cases are findings 103 and 104, twenty-nine of them,
red at 56f2c957 and passing from c2f4bdde on; sixteen guards beside them pass.
With them the Server project is 199 ✅ · 0 ❌, and the offline suite
2009 ✅ · 0 ❌ · 4 skips.

And the .onion names of the Tor network (RFC 7686 §2), which a resolver without
Tor MUST answer with NXDOMAIN, and an authoritative server too. Hermod's
`DNSClient` sent them to the configured server and took its answer,
`NameResolution` connected to it, and the server refused them or served what a
zone held at them. The cases are findings 105 and 106, twelve of them, red at
c2f4bdde and passing from 6ff76e99 on. Three guards beside them pass, one of
them a .alt name, which RFC 9476 §3.2 has a server treat like any other. With
them the Client project is 289 ✅ · 0 ❌, the Server project 207 ✅ · 0 ❌, and
the offline suite 2024 ✅ · 0 ❌ · 4 skips.

And the link-local names of Multicast DNS (RFC 6762 §22.1): `.local.` and the
link-local reverse domains, which a library SHOULD NOT send to its unicast
servers and an authoritative server SHOULD answer with NXDOMAIN by default.
Hermod's `DNSClient` sent them to its servers, and the server refused them or
served what a zone held at them. The cases are findings 107 and 108, fourteen
of them, red at 6ff76e99 and marked `KnownIssue`; fourteen guards beside them
pass. With them the Client project is 297 ✅ · 7 ❌, the Server project
213 ✅ · 7 ❌, and the offline suite 2038 ✅ · 14 ❌ · 4 skips.

That full run exercised all twelve test projects and every category, including
the public resolvers, WSL tools, Docker servers and native multicast DNS-SD. The
four skips are the RSA public-key exponent cases that Windows CNG cannot import;
the Linux CI leg covers them.

The suite has found 108 RFC deviations in Hermod. All but findings 107 and 108
are fixed; [FINDINGS.md](FINDINGS.md) records each with chapter and verse, the
change, and the test that pins it.

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
| `Multicast` | a multicast-capable interface; the interop project also a native `dns-sd` command | `--filter "TestCategory=Multicast"` |
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
| **3123** | APL | §4 the wire form: the address family, the prefix, and the octet that carries the negation flag in its top bit beside a seven-bit length — plus the MUST that only octets can show, "the sender MUST NOT include trailing zero octets in the AFDPART regardless of the value of PREFIX", since `10.0.0.0/16` and `10/16` print identically and differ only on the wire. §5 the text form both ways, negation included, and an address family RFC 3123 gives no syntax for written in the RFC 3597 §5 generic form rather than an invented one. An empty prefix list is a legal APL and reads back as one. Every expected string is `named-checkzone -D`'s output for the same zone. §5 also says what the format is *not*, and that half was missing: fifteen malformed items are now refused with nothing left behind — no address family, an unparseable one, one past sixteen bits, no prefix, one past an octet, an address that does not parse under the family it claims, and a family §4 gives no AFDPART. §5.1's `0..32` and §5.2's `0..128` are asserted from both sides, because a rejection test only ever proves that something is refused, and a comparison shifted one step would start refusing the /32 and /128 host routes that are the commonest prefixes there are. An address of nothing but zeros is the limit case of §4's MUST — every octet is a trailing zero, so the AFDPART is empty and the item is four octets of header with nothing behind it, read back through the wire as well as the text. None of this came from reading the RFC again: a mutation sweep reported all nine of `TryParse`'s refusals as changeable to acceptance without a single test noticing |
| **3596** | AAAA | §2.2 the wire form, full and compressed IPv6 text on input. §2.4 the presentation form, which is "the textual representation of an IPv6 address" and therefore not URI syntax: `IPv6Address.ToString()` brackets `::` and `::1` for an HTTP authority, and that string went into zone files that BIND then refused to load ✅ (finding 50) |
| **4701** | DHCID | §3.1 the identifier type code, digest type code and digest; §3.5 the presentation form, which is base-64 of the whole RDATA block rather than of the digest alone — checked against all three of the RFC's own examples, which between them cover identifier types 0, 1 and 2 |
| **3597** | Unknown RR types | §2 a type with no parser is kept as opaque data, in requests and in responses, and stepping over it leaves the reader where the next record begins — so it costs no record behind it. §3 the RDATA is served back octet for octet, including RDATA that reads as a compression pointer. §4 the eleven post-1035 types that carry a name in their RDATA emit it uncompressed, while the five RFC 1035 types still compress. §5 the `\#` generic form both ways, `TYPEnnn`/`CLASSnn`, a bare decimal read as a TTL and not a class, and a *known* type written generically re-read as that type. §6 RDATA compared as octets, case sensitively |
| **4033/4034/4035** | DNSSEC | key tag (App. B) on both IANA root KSKs, DS digests vs. IANA's published anchor, RRSIG validation against BIND-signed RRsets, canonical ordering, Secure/Insecure/Bogus/Indeterminate classification, expired and not-yet-valid signatures, wildcard reconstruction (§5.3.2). The chain of trust link by link (§5.2): every DNSKEY RRset verified under a key an authenticated DS or the anchor names, every DS RRset under its parent's key (finding 67); a signer that encloses the owner (§5.3.1, finding 68); every RRset of an answer covered by a signature that verified (finding 69); and a denial read only from the NSEC records whose signatures did (§5.4, finding 70). Serving side (§3.1): RRSIGs travel with the answer and denial records with the "no", both only for a querier that set the DO bit; a wildcard answer keeps its RRSIG's `labels` field pointing at the wildcard and carries the proof that the queried name was absent; and a DS query at a zone cut is answered by the parent rather than referred (§3.1.4.1) |
| **4255** | SSHFP | algorithm × fingerprint-type matrix |
| **2782** | SRV selection | the algorithm, not just the record. The lowest priority *it can reach*, so an unreachable one is a dead end for that priority and not for the query ✅ (finding 52); weight-0 targets first, an inclusive draw and "greater than or equal", which together are what give a weight 0 the "very small chance" the RFC asks for rather than none at all; and equal weights that actually spread, since all-zero is what the RFC recommends when there is no selection to make. Distributions are asserted seven standard deviations wide — a bound that only asked whether a weight-0 target was *ever* chosen let a mutation through |
| **4025** | IPSECKEY | §2.3's gateway field, whose meaning is decided by the octet before it: none, four octets of IPv4, sixteen of IPv6, or a wire-encoded name whose length "is implicit" and therefore has to be found by walking labels — the one place in this record where being one octet out produces a shorter key that still decodes and still looks like a key. §2.4 the name uncompressed, asserted by walking the RDATA rather than trusting the serializer. §2.5 a record with no key at all, which is legal and which BIND cannot represent in either the presentation or the generic form. Every expected string is `named-checkzone -D`'s own output |
| **4343** | Case-insensitivity | names differing only in case are equal, hash alike, order alike |
| **5952** §4 | IPv6 text | the canonical form a zone file is written in, one case per subsection: §4.1 leading zeros suppressed, §4.2.1 `::` used to its maximum capability, §4.2.2 never for a single zero group, §4.2.3 the longest run and the leftmost of two equal ones, §4.3 lowercase. Written once in `DNSTools.ToZoneFileText` and used by both AAAA and APL, because findings 46 and 48 were each a second implementation quietly disagreeing with the first |
| **4398** | CERT | type/keytag/algorithm |
| **4592** | Wildcards | §2.1.1 the owner name: `*` accepted as leftmost label only, and never by the strict hostname parser — which is the parser the zone-file reader used to reach for, so every wildcard line BIND wrote was unreadable ✅ (finding 44). And the *relative* form of the same name, `*` on its own, which is how a hand-written zone file spells a wildcard and which a separate rule refused — taking the whole zone file with it ✅ (finding 51). §3.3.1 the *matching*: synthesis at the closest encloser and nowhere above it, an exact match and an empty non-terminal each suppressing it, more than one label covered, no type of its own meaning NODATA — and the answer carrying the queried name, with the asterisk absent from the response entirely |
| **5011** | Trust-anchor rollover | 30-day hold-down, no trust on first sight, continuity required, ZSKs ignored, a revoked KSK dropped for good, and none of it on the word of a DNSKEY RRset no anchor signed (a revocation: the revoked key) |
| **4035** §2, **5155** §6/§7 | Signing | the direction the stack never had. Every authoritative RRset signed and no delegation's NS RRset or glue; an NSEC chain that closes, or an NSEC3 one with the empty non-terminals §7.1 demands and the opt-out of §6; the labels field of §3.1.3 shortened for a wildcard. **BIND's `dnssec-verify` is the judge** for all six algorithms RFC 8624 §3.1 lets a signer choose, and `dnssec-dsfromkey` for the DS. What it reads is a zone *file*, so the fields that only matter in an answer — the labels field, the opt-out flag — are pinned separately; both of those gaps were found by mutations that survived it. The suite's fixtures stay BIND-signed: a validator measured against its own signatures measures nothing. **And the same signer at runtime**: a zone signed in process by `InMemoryDNSZone.Sign` rather than by `dnssec-signzone`, served by a live Hermod and validated end to end by `delv` — answer, wildcard, NODATA denial and the DNSKEY RRset, under NSEC and NSEC3 both. No fixture is involved: the keys are generated at start-up and the trust anchor is the public half of the one that signed, so nothing on the wire existed before the test ran. The three failures an outside judge cannot see are pinned separately — signing twice must replace rather than accumulate, a record added afterwards makes the signatures stale and says so, and the expiration the zone reports is the one in its RRSIGs rather than one it merely remembers. **Keeping them fresh is a capability rather than a requirement** — RFC 6781 is Informational and names no interval, and it is a validating resolver rather than an authoritative server that decides an expired signature is expired — so `Resign` and `ResignIfDue` exist, are driven by the caller rather than by a timer inside the zone, and are tested for what they claim rather than against a specification that does not ask for them. The validity is remembered as a *length*: a repeat that reused the old absolute expiration would produce signatures exactly as stale as the ones it replaced, and would look like re-signing from every angle |
| **5155** | NSEC3 | §3.3 presentation format: the salt hexadecimal and the next hashed owner name base32hex, read and written, against the record App. A publishes ✅ (finding 43). Hashing — all twelve hashed owner names of App. A reproduce; salt applied every iteration, iteration count is *extra* rounds, canonical-wire input; Base32hex order-preserving. §8 proofs read: match, cover, closest encloser, opt-out. §7 proofs written: the three-record closest-encloser proof a server owes an NXDOMAIN, the matching record for NODATA, the covering record for a wildcard answer — and never more NSEC3s than asked for, since every spare one is free zone-walking material. §6 opt-out, against a zone BIND signed with `-A`: the flag on every record, no NSEC3 for the insecure delegation, and the §7.2.7 referral proof whose covering record carries the flag |
| **5452** | Spoofing resistance | §9.2 transaction IDs span the 16-bit space. §9.1's six-item list of what a response MUST match. Three items are the connected socket's - source and destination address, destination port - which leaves three for the resolver: the query name, class and type, each compared against the outstanding question on every transport, with a response carrying no question section at all matching nothing ✅ (finding 49). The comparison is RFC 4343's, case-insensitive, so a server that folds the QNAME before answering is still answering — a fix that compared octets would refuse most of the deployed world. §4.2 a non-matching response is ignored and not fatal, where *ignored* means the query keeps waiting: the reaction finding 5 fixed on the ID, now reached by the check finding 49 added |
| **6605** | ECDSA | P-256 and P-384: fixed-width r‖s, 64/96-octet keys |
| **6672** | DNAME | the substitution of §2.2 on labels rather than characters — so a name that merely ends with the owner's spelling is not redirected, and neither is the owner itself (§2.3). Served: the DNAME in the answer, the synthesized CNAME beside it with the DNAME's TTL (§3.1, where RFC 2672 said zero), YXDOMAIN when the rewritten name passes 255 octets (§2.2), records below the owner occluded (§2.4), and a chain into its own subtree bounded. Followed: the same substitution in the resolver, shared rather than written twice. `delv` validates the redirection end to end, including the CNAME carrying no signature |
| **6762**, **6763** | mDNS and DNS-SD | independent wire assertions for three probes and two announcements, ID/AA/RD/QU semantics, unique cache-flush versus shared PTR records, DNS-SD PTR answers carrying SRV/TXT/A additionals, TTL-zero goodbyes, and legacy-unicast ID/question/TTL behavior. Bidirectional live interop: native `dns-sd` discovers Hermod and Hermod resolves a native `dns-sd` publication. §6.4's key/value syntax is asserted as rules rather than as examples: a key is "printable US-ASCII values (0x20-0x7E), excluding '='", with both ends of that interval accepted and control characters, 0x7F, non-ASCII and '=' refused; a string with no '=' is a boolean attribute whose value is null, which `k=` — a key set to nothing — is not; the split is at the *first* '=' so a base64 value keeps its padding; a string beginning with '=' and an empty string are silently ignored; and of a repeated key only the first occurrence counts. Found by the mutation sweep, which could invert every one of those branches unnoticed. The querier side, client and browser, with the suite as the other host on the link: a query's header (§18) and questions (§5.3); what a querier MUST ignore — a source port other than 5353, a nonzero opcode or rcode, a unicast answer nobody asked for or from off the link (§6, §11), another host's known answers (§7.1) — and what it MUST NOT let cost a message: header bits, a question section, an NSEC it cannot parse (§6.1, §18). NSEC as a negative answer, TTL expiry, the one-second grace of a goodbye and of cache-flush, the burst a flush spares, the class without its top bit (§5.2, §10). The browser's 1 s/doubling query intervals and refresh at 80 % of a lifetime, known answers with their remaining TTL and no cache-flush bit, and RFC 6763's resolution from PTR to SRV/TXT to the target's addresses. It found eight deviations, findings 78 to 85, all fixed |
| **6698**, **8162** | TLSA, SMIMEA | usage/selector/matching-type, underscored owner names |
| **6891** | EDNS0 | OPT wire form (golden bytes), extended-RCODE combining, exactly one OPT, BADVERS for version > 0, payload-size negotiation |
| **6895** §3.1, §3.2 | IANA registries | the two registries that decide which number means what. On the wire: no response carries a QTYPE-only code point as a record TYPE or CLASS, TYPE 0 and the obsolete mail QTYPEs are answered NODATA with the zone SOA, and `*` is still served with data types — without which "answers nothing" would satisfy the rule. In presentation format: each mnemonic checked against the suite's own table, class 254 is NONE and class 0 is reserved with no name at all (finding 39) |
| **7043** | EUI48, EUI64 | fixed-width RDATA |
| **7208** | SPF | multi-character-string concatenation |
| **7344**, **8078** | CDS, CDNSKEY | the records mirror DS and DNSKEY (7344 §3.1/§3.2), and the protocol around them. RFC 8078 §4's delete sentinel — `CDS 0 0 0 0`, `CDNSKEY 0 3 0 0` — recognised only in the mandated form and only as an RRset of exactly one record, since a sentinel beside a real CDS asks for a DS to be installed and for all of them removed at once. RFC 7344 §4.1's acceptance rules, which are what keeps the sentinel from being a way for anyone who can write in a child zone to switch its DNSSEC off: apex, signed by a key in **both** the current DNSKEY and DS RRsets, and not breaking the delegation |
| **7477** | CSYNC | SOA-serial + flags + type bitmap |
| **7553** | URI | target is raw remaining octets, **not** a domain name |
| **7766** | DNS over TCP | 2-byte framing, TC→TCP fallback, split/dribbled reassembly, connection reuse, recovery on close. §7's *first* MUST as well as its second ✅ (finding 53): a response that does not match is stepped over rather than ending the read, because on a reused connection it is usually the answer to a query that already timed out — returning it left the stream one message behind for good, on TCP and on DoT alike. The other half of that finding is the case no matching rule reaches: a read abandoned between the length prefix and the end of the body has lost the frame boundary, so the connection is dropped rather than reused, while one abandoned before the prefix has consumed nothing and is kept. A connection the server closes in the middle of an answer is asked again like one it resets there, the cut-off query and those pipelined beside it ✅ (finding 91) |
| **7828** | TCP Keepalive | the option — zero-length in queries, 2-byte 100 ms units in responses — and whether it ever reaches the wire. §3.3.2 makes an OPT RR in the query, not the keepalive option, what lets a server volunteer a timeout, so the OPT record is measured on each client transport in turn: DoT and plain TCP send one and read an unsolicited timeout back, the UDP client's TCP retry sends one and ignores what arrives (§3.2.2 permits that), and plain TCP used to send none at all (finding 34). Then both of §3.2.2's endings, on both connection-holding clients and counted in handshakes rather than taken on trust: TIMEOUT 0, the server asking for its connection back, ends the session at once (findings 35, 36), and an advertised idle timeout ends it before that timeout expires rather than after — asserted as a deadline, not merely as an eventual close (finding 37). Both are about the connection the option arrived on: the next connection starts from nothing, and the late answer of one being drained cannot close the one that replaced it ✅ (finding 92) |
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
| **8945** | TSIG | MAC over message + §4.3.3 variables, checked against HMAC applied by hand; CLASS ANY, TTL 0, last in additional, ARCOUNT counts it; BADSIG / BADKEY / BADTIME kept distinct; the fudge window, a rewritten message ID, a response bound to its request's MAC. End to end: the server verifies signed queries and signs its replies, the client signs and checks the answer — including on the TCP retry after a truncated datagram, which used to go out unsigned. Both mechanisms ride every transport: UDP, TCP, DoT and DoH, the last two asserted by reading the message back out of the TLS framing and out of a `?dns=` parameter. §5.4 names the *reaction* to a reply that does not verify, not just the verdict — "continue to wait for a signed response until the request times out" ✅ (finding 53), where the client used to report a failure the moment the forgery arrived, which hands whoever sent it the power to end the request |
| **8976** | ZONEMD | serial/scheme/hash |
| **9460** | SVCB, HTTPS | alias and service mode, SvcParams parsed to RDLENGTH. The presentation format both ways: §2.1's escapes decoded ✅ (finding 88), each key's value in its own wire format ✅ (finding 89), Appendix D.2's vectors in both directions, and each key up to its edges — the longest alpn-id, both ends of a port, a hint of the other family — with the writer falling back to `keyNNNNN` for octets its key cannot hold. Appendix D.3's failure vectors, all six refused: the four that are one malformed value, and a key written twice and a `mandatory` naming a key the record lacks ✅ (finding 90) |

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
| **2230** KX, **8005** HIP, **6742** NID/L32/L64/LP | record types Hermod has no parser for | nothing — they are rare and none of them has the shape that makes a record type worth reaching for first. RFC 3597 §5 already carries them: Hermod reads and writes them as `TYPE36`, `TYPE55` and so on, losing nothing but the mnemonic. IPSECKEY was taken ahead of them because its gateway field changes meaning with the octet before it and its length is written nowhere, which is where parsers go wrong; these three are a preference and a name, a fixed-shape key, and a 64-bit identifier |

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

Two entries, and only the first is blocked — that column is not decoration, and
neither is an empty cell in it. GSS-TSIG needs a Kerberos/SPNEGO stack before a
single assertion can be written, and sits here rather than under *Out of scope*
because it is a gap and not a refusal: it is what is actually deployed, and a
suite that judged Hermod's transaction security without saying so would be
quietly flattering it. The record types are the other kind of entry entirely —
unblocked, unstarted, and written down so that the decision to defer them is a
decision rather than something nobody got round to.

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

### And what grades the suite

Everything above is about judging Hermod with something other than Hermod. It
says nothing about whether a green test is green because the code is right or
green because the test asks nothing, and from the outside those are identical.
Four tests here turned out to be the second kind, every one found by accident.

[MUTATION.md](MUTATION.md) is the answer to that question and the only number in
this repository that was not chosen by whoever wrote the tests. Changes are made
to Hermod's resource-record code one at a time — a comparison shifted, a
condition inverted, a rejection made to succeed — and the suite is run against
each. **Of 605 such changes, 370 went unnoticed; 252 of those are real gaps
rather than equivalent code.** About half of what can be changed in that code,
this suite did not watch. Every one of them has since been answered: 194 closed by
a test, 54 unreachable rather than untested, and 4 whose line a fix removed — none
left open. Closing them turned up four more
deviations — [findings 54, 55 and 56](FINDINGS.md), plus `DNSSRVEndpoint`'s
broken `Equals` and `CompareTo` — each of them a survivor that no test could
kill, because no input could reach it.

The list is not a backlog. It is a map of where the suite believes it is looking
and is not — which is how APL's nine unexercised rejection paths were found,
days after APL's own tests were written and passed.

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
