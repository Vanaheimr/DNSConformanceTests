# Mutation Sweep — what the suite would notice

Every other document here says what the suite **asserts**. This one says what it
**misses**, and it is the only number in the repository that was not chosen by
the person writing the tests.

A conformance suite grades a DNS stack. Nothing grades the suite. A test can be
green because the code is right, or green because the test asks nothing — and
from the outside those look identical. Four tests in this suite turned out to be
the second kind, each found by accident: a compiler error that happened to sit
beside `Is.False.Or.True`, a `.Trim()` in a measurement helper, a test that never
looked at the address family it was named after, and a bound that only asked
whether something *ever* happened.

Mutation testing asks the question directly. Change one thing in the code under
test — flip a comparison, invert a condition, make a rejection succeed — rebuild,
and run the suite. If no test fails, nothing in the suite is watching that line.
The count that belongs here is the one in README's status line, which moves every
round; naming it twice only guarantees one of the two goes stale.

---

## Seven blocks, five measured

The DNS code lives in seven folders and the sweep started with one of them. That
was not a judgement about the others — it was where the work began, and saying so
is the difference between a measurement and a claim. The map, with the cheapest
test project that exercises each:

| block | folder | judged by | mutants | state |
|---|---|---|---:|---|
| `records` | `DNS/ResourceRecords` | ResourceRecords | 687 | measured, **closed** |
| `core` | `DNS` (the files directly in it) | ResourceRecords | 478 | measured, **closed**, 1 never measured |
| `tsig` | `DNS/TSIG` | SecureTransports | 94 | measured, **closed**, 1 never measured |
| `dnssec` | `DNS/DNSSEC` | Dnssec | 227 | measured, **9 open**, 3 never measured |
| `client` | `DNS/Client` | Client | 558 | not measured |
| `multicast` | `DNS/Multicast` | Multicast | 598 | not measured |
| `server` | `DNS/Server` | Server | 361 | measured, **63 open**, 1 never measured |

One line of `sweep_folder.py` runs any of them. The `multicast` row is worth a
second look before anyone reads a number off it: its judge has **four tests** for
598 mutable places, so whatever that block eventually reports will be a statement
about the tests rather than about mDNS.

**Three of those counts used to be wrong, and how they were wrong is worth
keeping.** The table said 70 for `tsig`, 202 for `dnssec` and 551 for `multicast`;
counting them again gives 94, 227 and 598. It is not staleness — none of those
three folders changed between the two revisions the sweeps ran at, and
`genmut.py` has not changed since it was written. The numbers were simply wrong
when they were typed, and nothing caught them because the column looks measured
and only two of its rows were. The `tsig` sweep is what found it: it announced 94
mutants against a row promising 70.

The four rows that were right — `records`, `core`, `client`, `server` — are right to
the mutant. `core` counts 479 today rather than the 478 it was measured at, which
is not an error: finding 57's fix and the compression-table fix each added a
comparison. The measured figure stays, because it is what was measured.



---

## The result: the server

Measured against Hermod **`cc8323d5`**, `libs/Hermod/Hermod/DNS/Server/**`, judged
in pass 1 by Server and in pass 2 by the remaining seven projects.

| | |
|---|---:|
| mutants | 361 |
| not viable (would not compile) | 63 |
| killed by Server | 106 |
| killed by another project | 69 |
| survived everywhere | 122 |
| never finished | 1 |
| real gaps | **115** |

**Pass 2 earned its keep here, where for DNSSEC it bought nothing.** It caught 69
of the 195 survivors handed to it — better than one in three, against 21 of 63 for
`tsig` and none at all for `dnssec`. The difference is how many projects touch the
folder. Everything that speaks to a server runs through `DNS/Server`, so a
mutation the Server tests miss has seven more chances to be seen; DNSSEC has
exactly one judge and there is no second opinion to be had.

Where the 115 are:

| file | gaps | what it is |
|---|---:|---|
| `DNSServer.cs` | 36 | the listeners: binding, the transports, the sockets |
| `ZoneDenialOfExistence.cs` | 15 | what an authoritative server proves absent |
| `InMemoryDNSZone.cs` | 14 | the zone itself: lookup, wildcard, referral |
| `DNSOverHTTPSServer.cs`, `DNSOverHTTP2Server.cs`, `DNSOverHTTPSResource.cs` | 23 | DoH |
| `DNSMessagePipeline.cs` | 10 | what a message meets on the way in and out |
| `AuthoritativeDNSRequestHandler.cs` | 8 | the answer itself |
| `DNSServerOptions.cs`, `DNSCookies.cs` | 9 | the options, and cookies |

### A SIG that covers a type, and a file that answers nothing

RFC 2931 §3 identifies the whole mechanism by a single field: a SIG(0) is
*"identified by having a 'type covered' field of zero"*. A SIG record with any
other value is an ordinary RFC 2535 signature over an RRset, travelling in the
additional section where a transaction signature would sit. It authenticates
nothing about the request, so the request is unsigned and has to be served as
one — and a server that fed it to verification instead would refuse an ordinary
message on the strength of a record the sender is entitled to include.

The test signs a query properly and then changes that one field, locating it
through the suite's own parser rather than by counting octets. The signature
stops matching, which is the point: nothing may look at it.

`DNSMessagePipeline.cs:419` carries the same operator twice and the two mutants
now have different answers, which is what was predicted and is why the line was
left open two rounds ago rather than claimed as equivalent. The first connective
guards a null `TryStripSIG0` cannot produce and stays. The second is the
type-covered test itself, and it is now dead. The ledger keys on file, line and
operator and cannot say *one of two*, so the line is filed under the round that
closed half of it and this paragraph carries which half.

### DNSServer.cs, where a black-box suite has nothing to say

Thirty-six gaps, half of them `ConfigureAwait(false)`, and of the other eighteen
**not one is closeable by a test from outside**. That is not a failure of imagination; it is what the file is.

Five are equivalent outright. `length > sharedBuffer.Length` cannot fire in
either reading: the buffer comes from `ArrayPool.Shared.Rent(UInt16.MaxValue)`,
which allocates at least that much and in practice the next power of two, while
`length` is a `UInt16`. The two `DualMode = false` lines say in their own comments
that they are unobservable while the IPv4 listener is bound, which the round on
the four timeouts had already confirmed from the other direction. And the two
mutations of `bound.Count < endPoints.Count && !portChosenBySystem` change which
runs write a warning to the log and nothing that reaches a socket.

The remaining thirteen are real mutations that this suite cannot reach, and each
for a different reason, which is the interesting part:

| | |
|---|---|
| the bind retry policy — six lines | reachable only through a port race, and a race is not a test |
| the "no IPv6 on this host" filter | needs a host without IPv6 |
| two multicast socket options | the multicast listener is switched off in every fixture |
| `leaveInnerStreamOpen` | a resource lifetime, visible only through exhaustion |
| a zero `TCPReadTimeout` | a configuration nothing sets |
| the two DoH port-collision tests | start-up validation, and no RFC says what a server does when two of its own listeners want one port |

A conformance suite judges what comes back on the wire. This file decides how the
socket that carries it was opened, and almost nothing about that survives the
journey to an answer. Naming that is worth more than thirteen tests that would
each assert a configuration this suite chose itself.

### Both edges of a window, and a length that was never the one deciding

Nine gaps in the two smallest files left. Three fall, all in `DNSCookies.cs`, and
the five in `DNSServerOptions.cs` are open for a reason worth naming.

RFC 9018 §4.3 sizes the replay window: a server *"SHOULD allow cookies within a
1-hour period in the past and a 5-minute period into the future"*. A period **of**
an hour — so a cookie exactly an hour old is inside it, and one exactly five
minutes ahead is too. Both edges belong to the window, and a comparison one step
out shortens it by a second at each end.

That one is asked of the function directly, which is a departure from the house
rule and so gets its reason written down. The seam is already there — `Create`
and `Validate` both take the moment to use — the running server takes its clock
from the wall, and what is measured is a window against the timestamp *inside* the
cookie. From outside the edge cannot be reached at all. What the test asserts is
the window, not the keyed hash beneath it; the hash is what the tests around it
exercise, over the wire, against a cookie this process did not make.

**The length check took two attempts, and the first one is the lesson.** RFC 7873
§4.2 gives the Server Cookie *"a variable length, from 8 to 32 octets"*, so a
COOKIE option of 16 to 40 is well formed whatever a server mints. Hermod mints
sixteen. Every other legal length arrives and has to be turned away as a cookie
that does not check out — not as a malformed option, which is the other side of a
line the existing length test already covers with 7, 9, 15 and 41 octets of
*option*, none of which reach the validator at all.

The first version of the test sent those lengths as octets of zero, and the
mutant survived it. A cookie of zeros carries a timestamp of zero, so the replay
window rejected it fifty-six years late and the length never became the check
that mattered. The timestamp is in the clear and an attacker sets it freely, so
the test now sets it too — and with the window satisfied, a nine-octet server
cookie carries the mutant past the length check and into a read off the end of
the array.

Both of those were predictions that came out wrong in the same round, and neither
was about the RFC: the first missed which check fires first, the second missed
which of two guards the version octet belongs to. `160` stays, because the
version is inside the eight octets the hash is computed over — a cookie with the
wrong version has a MAC that cannot match, so the explicit check decides nothing
the comparison below it does not decide again.

**And the five options.** `EnableUDPUnicast`, `EnableUDPMulticast`,
`EnableTCPUnicast`, `EnableTLSUnicast`, `UseCompression` — every one a real
mutation, and none of them reachable, because every fixture that builds a
`DNSServer` states all five. The suite always has an opinion, so the defaults
never apply. Reaching them means a fixture that deliberately withholds one, which
is a decision about what this suite should assert rather than an omission.

Worth one line while passing, and not acted on: **`EnableUDPMulticast` defaults to
true**, so a server built with no opinion joins a multicast group. No RFC forbids
it and nothing here asserts it either way.

### A media type named in order to exclude it

Twenty-three gaps across the three DoH files. Three fall, and two of them are the
same sentence of RFC 9110:

> a value of 0 means "not acceptable"

`application/dns-message;q=0` names the one media type this server has, in order
to rule it out. It is a refusal written as a mention, and to anything that
compares media types and stops there it looks exactly like a request for that
type. The `AcceptsDNSMessages` check reads the quality first and says so in its
own comment, and both halves of that check — the comparison and the `return
false` under it — were unwatched.

**The existing test aims one step short.** It sends `Accept: application/json`,
which is refused before the quality is ever consulted: the type simply is not the
one on offer. §12.4.2's case is the other one, where the type *is* on offer and
the field withdraws it.

The third is the ceiling. A DNS message is at most 65535 octets, because that is
what RFC 1035 §4.2.2's two-octet length prefix can count — so 65535 is the
largest one allowed rather than the first one too many, and a comparison one step
out refuses the largest message a client may legitimately send.

**Only the inside of that boundary can be asked for.** One octet more never
reaches the check at all: the HTTP layer declines the body and resets the
connection — `ENHANCE_YOUR_CALM` over h2 — so the 413 the resource would generate
is written for a request that cannot arrive. The test says so, and asks for the
half that can be wrong in a way anyone would notice.

### Twenty that stay, and two tests that closed nothing

Two of the four predictions came out. The other two are worth more than the two
that did.

**A test can assert the right status for the wrong reason.** The empty-POST test
asks for 400 and gets 400 — with the mutation in place as well, by a different
route. The HTTP layer hands an empty array and never a null, so the first half of
`queryBytes is null || queryBytes.Length == 0` is dead, and the second is
redundant with the parser below, which refuses a nought-octet message anyway. The
test states something true and cannot tell the two paths apart, which is not the
same as stating nothing.

**And a 405 is not always the same 405.** The other test sends a PUT and asks for
a body with the refusal, which is RFC 9110 §15.5.6 and §6.4.1 and which nothing
had asked for. It killed nothing, because the line it was aimed at answers a
different case: `'{methodText}' is not an HTTP method this server knows` fires
where `HTTPMethod.TryParse` returns null, and that happens only for a name that
breaks §9.1's token syntax — an unknown but well-formed name becomes a new
`HTTPMethod` and is refused further along as a method this *resource* does not
allow. A `:method` that breaks the token rules is refused by the client stack
before it reaches a socket. The branch is unreachable from any client this suite
can drive; the test stays, because what it asserts is true and was untested.

The rest divide as before. Six more are unreachable guards — the body-read guard
whose comment warns of a wait that cannot happen, a `:path` beginning with a
question mark where HTTP/2 requires a slash, the 500 path, and the SOA minimum
whose two branches return the same number where the comparison could differ.
Seven are `ConfigureAwait(false)`. Six are options of the embedded HTTP server —
`AutoStart`, `DisableMaintenanceTasks`, certificate revocation — which no
specification about DNS constrains, and which are the same case as
`InMemoryDNSZone.Remove`: real mutations in code this suite has no standing to
judge.

The last is `ServeHTTP11ViaALPN && certificate is not null`, and it is open for a
third reason again: the DoH fixture does not offer that switch, so both readings
build the same renderer. Reaching it means new fixture surface for a behaviour no
RFC asks for, which is a decision rather than an omission.

### A conditional that was a comment, and the first open finding

`DNSMessagePipeline.cs:374` looked like the most careful line in the file:

```csharp
ErrorResponse = TSIGSigner.BuildErrorResponse(
                    Buffer,
                    result.Error,
                    result.Error == TSIGSigner.BADTIME ? key : null
                );
```

RFC 8945 draws a sharp line there. §5.2.3: *"A response indicating a BADTIME
error MUST be signed by the same key as the request"*, with the server's clock
in Other Data so the sender can resynchronise. §5.3.2, for the other failures:
the server *"MUST NOT send back a signed error message"*. Two refusals that must
differ, and one conditional that appears to make them differ.

The mutation survived, and following that led to the answer: `BuildErrorResponse`
builds every refusal with `MAC: []` and `OtherData: []`, unconditionally. The key
reaches the record's owner name and algorithm and stops. When it is null the
fallback constructs an equivalent key from the request's own TSIG, so **both
readings of that conditional emit identical bytes**. The line states an intention
the code below it does not carry out.

So the mutant is equivalent — and its ledger entry says when it stops being so.
The moment a BADTIME reply is signed, the two readings differ, and the test
written for the finding kills the mutation. An equivalence that expires is worth
more written down than a gap left open.

**And this is [finding 58](FINDINGS.md), the first to land open.** The existing
tests asked both refusals for their RCODE, which is the half they agree on;
nothing looked inside the TSIG, where §5 requires them to disagree. Hermod
answers BADTIME unsigned and with no server time, so a client with a drifting
clock is told what is wrong and not what to correct it to — and an unsigned
refusal can be forged by anyone able to send a packet, which is the class of
attack TSIG exists to close. The BADSIG half is already right.

Per [PLAN.md §9](PLAN.md) the test stays red as the tracking signal. It carries
the `KnownIssue` category, and the sweep now excludes that category: a test that
fails for a documented reason fails for the mutant and the clean tree alike, so
while it is open it can detect nothing, and leaving it in would have stopped
every future run at `baseline is not clean`.

### Four edges, and eighteen lines that say why they cannot move

Two files and twenty-two gaps. Four fall, and how the other eighteen divide is
the more useful half.

**The edge of the requestor's buffer, which is consulted twice.** RFC 6891 §6.2.3
calls the advertised payload size *"the number of octets of the largest UDP
payload that can be reassembled and delivered in the requestor's network stack"*.
A message of exactly that many octets is therefore one the requestor can take:
the boundary belongs on the inside. The server checks it once for the whole
answer and again for each shortened one it tries on the way down, and both
checks were unwatched.

The suite already asked whether an oversized answer gets truncated. That question
is satisfied by a response of *any* size as long as TC is set, so it said nothing
about where the edge is.

The new tests compute no sizes at all. They ask once to learn what the server
produces, then ask again advertising exactly that many octets — so the assertion
holds whatever the records encode to, and no arithmetic in the test file can
drift away from the wire.

**And what survives the shedding.** §6.1.1 has no exception for the case where
nothing could be kept:

```csharp
for (var count = answers.Length - 1; count >= 0; count--)
{
    ...                                   // AdditionalRRs: responseOPT
    if (bytes.Length <= limit) return bytes;
}
return Serialize(new DNSResponse(..., AnswerRRs: [], AdditionalRRs: []));
```

Read the bound as `count > 0` and the loop never tries the empty answer, so a
single oversized record falls past it into the return below — which drops the OPT
record with everything else. The difference is not "fewer answers". It is an EDNS
response that stops being one: a truncated reply without an OPT tells the client
the server does not speak EDNS, and the retry may then be made without it, taking
the DO bit with it.

**And twelve octets.** RFC 1035 §4.1.1's header is twelve octets, which is the
shortest message that can be answered at all — the transaction id is in the first
two, and the reply needs nothing else. One octet of slack in `if
(RequestBytes.Length < 12)` turns a FORMERR into silence, and silence is what a
client reads as *server unreachable*: it retries, backs off, and moves to the
next name server, when the truth was that its own query was malformed. The
existing test for a truncated request sends a header **plus** a fragment of a
name, so it stays clear of the edge.

### The handler, where nothing fell and that is the answer

Eight gaps in `AuthoritativeDNSRequestHandler.cs`, no kills, and three different
reasons.

**Two are dead code.** `HasValidServerCookie`'s `return false` for a server with
no cookie secret has one caller, whose condition opens with
`DNSCookieSecret is not null` — the line answers for a state the method is never
in. And `FollowCanonicalNames` returns early for QTYPE CNAME and ANY, but it is
called only where the store answered `NoData`, and a node holding a CNAME answers
`Found` to a query for CNAME or ANY. The guard is correct, its own comment says
why, and it cannot be reached.

**Two are limits no specification names.** The CNAME chain stops at sixteen and
the DNAME redirection at sixteen; read as seventeen, both still terminate and
both are still conformant. RFC 1034 §4.3.2 warns that a chain may loop and gives
no number, and RFC 6672 §2.2 calls *"fairly lengthy valid chains of DNAME RRs"*
legitimate. Same category as `DNSSECValidator.cs:863`.

**Four are `ConfigureAwait(false)`**, which joins the eight already open in the
DNSSEC block: not equivalent, and with no reading a test host can take, because
there is no synchronization context there for the two to differ about.

**A prediction was wrong here, in the same way as the last one.** `237` was
expected to fall to the two new CNAME tests. It did not, and the reason was four
lines away in a *different method*: the caller. The round before that, `371`
survived because the answer lived in a call made before it. Reading a function
without reading its call sites has now produced two wrong predictions in two
rounds, from opposite directions.

The two tests stay regardless. RFC 1034 §3.6.2 states the restart rule and then
takes one case back out of it — *"The one exception to this rule is that queries
which match the CNAME type are not restarted"* — and the existing test asked that
of `alias`, whose target holds no CNAME. A server that wrongly restarted would
look for a CNAME at the target, find none, and return the same single record. The
rule was being tested at the one name where it cannot show.

### One `||` whose two halves disagree

`DNSMessagePipeline.cs:419` carries the same operator twice and gets no ledger
entry, because its two mutants have different answers:

```csharp
if (!SIG0Signer.TryStripSIG0(Buffer, out var unsigned, out var sig) ||
    unsigned is null || sig is null || !sig.IsTransactionSignature)
```

`TryStripSIG0` has one `return true` with both outputs set above it, so the null
terms cannot decide anything and turning the first `||` into `&&` changes nothing
that can arrive. Turning the second one into `&&` drops
`!sig.IsTransactionSignature` from the expression entirely — and a SIG record
whose type covered is not zero, which RFC 2931 §3 says is not a transaction
signature at all, would then be sent to verification instead of served as the
unsigned request it is. One dead guard and one real gap under one key. It stays
open until the second has a test; closing it now would close both.

### The bit that gates three other answers, a bare DS, and the last candidate of a walk

Fourteen gaps in `InMemoryDNSZone.cs`. Five fall.

**Three of them were one line written three times.**

```csharp
if (DNSSECOK && Zone.Denial is not null)
```

An authoritative server arrives at RFC 4035 §3.2.1 from four directions — a
wildcard answer, a wildcard holding no such type, a plain NODATA, and "no such
name" — and the same gate stands at each. One test covered it, asking
`zz.dnssec.test.` with the DO bit clear, which is the fourth. The other three
carried the identical condition with nothing watching it. §3.2.1 does not single
out the NXDOMAIN case: a server answering a query with the bit clear *"MUST NOT
perform any of the additional processing described below"*, whatever the answer
turns out to be.

**A referral that works perfectly for everyone who is not checking.** §3.1.4
leaves no room: *"the name server MUST return both the DS RRset and its
associated RRSIG RR(s) in the Authority section along with the NS RRset"*. The
call is `WithSignatures(delegationSigners, atDelegation, true)`, and read as
`false` the DS goes out bare. The delegation still works, the child still
answers, every name under it resolves — for anyone not validating. A resolver
that *is* validating holds a DS it cannot believe, and the correct response to
that is to call the whole child Bogus. The failure is invisible exactly until it
matters.

That test writes its zone out record by record, signature included. Nothing in it
verifies the signature — selecting and sending it is the server's whole job here
— and a fabricated one keeps the test independent of which key material happens
to be on disk this month.

**And the last candidate of a walk.** RFC 6672 §2.3 lets a DNAME share an owner
name with an NS RRset in exactly one place: *"DNAME RRs MUST NOT appear at the
same owner name as an NS RR unless the owner name is the zone apex."* Every DNAME
in this suite sat below the apex, which is the ordinary case and also the easy
one — the walk up from QNAME finds it with labels to spare. At the apex it is the
**last** candidate that walk will ever consider, so `labels.Length - skip >=
apexDepth` read as `>` loses it and nothing else. A zone whose entire purpose is
to mirror a name space somewhere else then answers as though the DNAME were not
there, for every name it holds.

The same section draws the other line — *"such a DNAME cannot be used to mirror a
zone completely, as it does not mirror the zone apex"* — so the second test asks
the apex for itself and gets its SOA. A walk that started one step too *high*
would pass the first test and fail that one.

### Nine that stay, and only two of them equivalent

**Two are provably the same value.** `489` is
`signingKeys is null || !SignaturesExpireAt.HasValue`, and the two fields are
assigned once each, six lines apart inside `Sign`, with no path between them that
can fail — so they are null together and set together, and where both operands
always agree, `||` and `&&` cannot. `894` is `return Records.Length > 0`, where
`Add` never creates an empty list and `Remove` drops the key the moment its list
empties: a `TryGetValue` that succeeded has found records.

**Seven are not equivalent, and six of those are not this suite's to close.**
They sit in `Remove(DomainName, Type?, Class?)`, and the mutations are real
enough — `&&` read as `||` removes records matching the type *or* the class
rather than both, and `==` read as `!=` removes everything except what was named,
which is a zone quietly destroying itself. None of it is reachable. Hermod
answers every opcode but zero with NOTIMP, so there is no RFC 2136 dynamic update
and no query that edits a zone; nothing in Hermod's own DNS code calls `Remove`;
and neither does this suite. It is public API with no consumer, and a black-box
conformance suite has no specification to hold it to. Writing tests for it would
be writing Hermod's unit tests inside a suite that exists to do something else.
They stay open, and the reason is written here rather than hidden in a ledger
entry claiming they are equivalent.

The seventh is `SignaturesExpireAt.Value - DateTime.UtcNow > Before`, one more
for the list of **boundaries that need a seam**. An RRSIG's expiration is a
whole number of seconds and `UtcNow` is not, so the one instant where the two
readings differ cannot be reached from outside. Only a `Now` parameter makes it
reachable, which is what the four in the DNSSEC block are waiting for and what
Hermod has twice accepted on request.

### A zone that holds nothing but its own apex

Fifteen gaps in `ZoneDenialOfExistence.cs`, and the file turns on one sentence of
RFC 4034 §4.1.1: *the value of the Next Domain Name field in the last NSEC record
in the zone is the name of the zone apex*. A zone with one name has one NSEC,
which is therefore both the first and the last — so its next name is its own
owner, and the span it describes is everything below the apex rather than an
interval inside it.

```csharp
var above = CompareCanonical(Name, owner) > 0;
var below = CompareCanonical(Name, next)  < 0;
var wraps = CompareCanonical(owner, next) >= 0;

if (wraps ? (above || below) : (above && below))
    return nsec;
```

Read `wraps` as `>` instead of `>=` and a chain of one record stops wrapping.
Every name below the apex is then neither strictly after the owner nor strictly
before the next, the covering search finds nothing, and the NXDOMAIN goes out
with no proof at all — which a validating resolver has to treat as Bogus rather
than as absent. Every other test here works with chains of three names or more,
where owner and next always differ. That is why nothing noticed.

This is not a contrived zone. It is what a signer produces for an empty one: a
name held away from the world, or a zone that has just been created.

The test writes the zone out record by record rather than signing it, which buys
two things. The NSEC is *stated* rather than produced, so what is measured is the
server's selection of it and nothing else. And with no RRSIG travelling beside
it, the duplicate check in `Collect` has nothing to hide behind: in an apex-only
zone the two halves of §3.1.3.2 — that the name is absent, and that no wildcard
could have answered — resolve to the same single record, and the RFC asks for it
once. The NSEC3 hash is computed in the test too, for the reason the rest of this
file already gives: a test that hashed the way the server hashes would agree with
it where both were wrong.

Three of the fifteen fall. The wrap at 311, the duplicate check at 597, and the
hash comparison at 443 — that last one only in the NSEC3 zone. `CompareHashes`
walks the shorter of the two arrays and answers by length if it reaches the end;
two identical twenty-octet hashes are the only call where it *does* reach the
end, and a bound one too generous reads past it.

**The fourth prediction was wrong, and that is the part worth keeping.** `371` is
the NSEC3 twin of `311`, the same mutation on the same expression one screen
down, and it was expected to die with it. It survived. The NSEC3 form of
`ForNameError` asks for a *matching* record before it asks for any covering one:

```csharp
Collect(proof, MatchingNSEC3(closestEncloser));
Collect(proof, CoveringNSEC3(NextCloser(QName, closestEncloser)));
Collect(proof, CoveringNSEC3(Wildcard(closestEncloser)));
```

In a one-record zone the record the covering calls would return is the record the
matching call already returned, and `Collect` drops the duplicate. The answer is
identical whether the wrap works or not. The NSEC branch two screens up has no
matching call — only two covering ones — so the same mutation empties the proof
there. **Same operator, same expression, same zone, opposite verdicts**, and the
difference is four lines away in a different method. Reading the two as
symmetrical because they look symmetrical is what the measurement caught.

### The twelve that stay, and why they are three different things

Twelve equivalences in one file is more than any round so far, which is reason to
separate them rather than wave at them.

**Two compute the same value.** `445` is `Left[i] < Right[i] ? -1 : 1` under an
`if` that has already established the two differ, and less-than cannot disagree
with less-or-equal where equality is excluded. `565` is
`Skip >= Labels.Length ? "." : String.Join('.', Labels.Skip(Skip)) + "."`, where
at equality the second branch joins nothing and appends the dot — which is the
dot the first branch returns.

**Eight guard a state no caller produces.** Every call of `CoveringNSEC` and
`CoveringNSEC3` passes a name the zone does not hold; that is what those calls
are *for*. So a name equal to an owner, or to a next name, never arrives, and the
strictness of the comparison is never consulted — `306`, `307`, `369`, `370`.
RFC 4034 §4.1.3 wants it strict all the same: a name equal to an owner is
*matched*, not covered, and proving it absent would be proving a lie. `333`,
`352` and `424` guard nulls their callers cannot pass, and `528` tests whether
QNAME is its own closest provable encloser, which a name that exists cannot be.
Right, and unreachable — the same category as the eighteen guards in the `tsig`
block.

**Two are shadowed by a path that supplies the same answer.** `371` above, and
`466`, whose walk loses exactly the apex candidate and whose `return` below the
loop is the apex.

### Four mutants with no verdict, and what three of them turned out to be

Four came back TIMED-OUT rather than killed or survived. A mutant gets ten times
the clean run here, which is 120 s, and none of the four finished in it. A
timeout is a statement about the instrument, so each was planted by hand and one
test class — twelve tests, 144 ms clean — was run on its own:

| | with the mutant |
|---|---|
| `DNSServer.cs:374` `==`→`!=` | **12 of 12 failed**, 2 m 5 s |
| `DNSServer.cs:427` `==`→`!=` | **12 of 12 failed**, 2 m 5 s |
| `DNSServer.cs:718` `==`→`!=` | **12 of 12 failed**, 2 m 5 s |
| `DNSServer.cs:297` `false`→`true` | **still running after 600 s** |

Three of them are kills the harness could not afford to wait for. Each makes
every bind throw, and the fixture answers a server that publishes no endpoint by
waiting five seconds and trying again — about ten seconds per test before it
gives up, which over the project's 140 tests is some twenty minutes against a
bound of two. The suite is red the whole way. It is simply never asked. Their
rows are corrected to KILLED, and `server-pass1.tsv.before-timeout-recheck`
keeps what was measured — the same treatment `DNSSECZoneSigner.cs:34`'s
PARSE-ERROR got, for the same reason.

The fourth is a different animal and keeps its TIMED-OUT, which is the true
verdict:

```csharp
for (var attempt = 1; ; attempt++)
{
    var bound  = new List<T>();
    var retry  = false;              // planted as true
    ...
    if (!retry) { ...; return bound; }
    foreach (var listener in bound) Release(listener);
}
```

With `retry` stuck true the loop binds every endpoint, releases them all and
starts again, for ever, at full speed and with real socket calls. It runs inside
a background listener task and reads no cancellation token, so `Stop()` cannot
reach it: every fixture that gives up leaves one more of them spinning. Nothing
on Hermod's public surface reports this — `listenerTasks` is private, `Start()`
returns successfully with every listener doomed, and a caller can only infer the
failure from an endpoint that never appears, which is what the fixture's own
comment already says it has to do.

**And that the loop terminates at all is not visible from the loop.** `for (;;)`
is bounded only because `retry` is set in exactly one place — an exception filter
three levels down that also tests `attempt < attempts`. It is correct. A reader
has to go and find that out.

One more went the other way, and it is the reason to check both directions.
`DNSServer.cs:330`'s `&&`→`||` also timed out in pass 1, and pass 2 then gave it
SURVIVED-EVERYWHERE — which says the other seven projects miss it and says
nothing at all about the block's own judge. Run on its own it passes 12 of 12 in
132 ms: the filter it guards needs a `SocketException` before it is reached at
all, so pass 1's timeout was a hiccup and not a slow red. Corrected to SURVIVED,
and it stays a gap.

### A default is noise when nothing on the wire reaches it

The triage calls a parameter default noise. The DNSSEC block needed an exception
for two of them, which are listed by name because no pattern can tell "the usual
value" from "the safe value". This block has four, and the interesting part is
that **none** of them needed the exception — for two different reasons, and the
difference is worth more than the verdict.

```csharp
Boolean  DNSSECOK            = false,     // IDNSZoneStore.cs:182, InMemoryDNSZone.cs:510
Boolean  ServeHTTP11ViaALPN  = true,      // DNSOverHTTP2Server.cs:271
Boolean  RequireDNSCookies   = false)     // AuthoritativeDNSRequestHandler.cs:90
```

The first three are unreachable. Every caller of `Lookup` passes `DNSSECOK`
explicitly — the handler computes it from the request's DO bit, per RFC 4035
§3.2.1, and the suite's one direct caller writes `DNSSECOK: true` — so the
default sits on no path that a wire test can travel. The ALPN one is sharper
still: the **same** default one overload up, at `DNSOverHTTP2Server.cs:191`, is
killed by SecureTransports. The policy is pinned; line 271 only repeats it for a
convenience overload nothing in the suite calls.

`RequireDNSCookies` is reachable and still not policy. Six fixture sites do
construct the handler with the default, but the branch it guards has four
conjuncts:

```csharp
if (DNSCookieSecret is not null &&
    RequireDNSCookies           &&
    ReadRequestCookie(Request) is not null &&
    !HasValidServerCookie(Request))
```

and none of those six sets a cookie secret, so the branch is dead whichever way
the flag reads. The two tests that do exercise it pass the flag explicitly. And
RFC 7873 §5.2.3 leaves the choice to the server: nothing in the specification
says the default must be permissive, which is what separates this from RFC 5155
§6's opt-out, where the default decides what every zone proves.

So the rule the two blocks together give is not "defaults are noise" and not
"defaults are policy". **A default is noise when no wire path reaches it, or when
no RFC constrains it. It is policy when the suite's own fixtures run on it and a
specification has something to say about which way it should read.**

---

## The result: DNSSEC

Measured against Hermod **`53f20591`**, `libs/Hermod/Hermod/DNS/DNSSEC/**`, judged
in pass 1 by Dnssec and in pass 2 by the remaining seven projects.

| | |
|---|---:|
| mutants | 227 |
| not viable (would not compile) | 35 |
| killed by Dnssec | 102 |
| killed by another project | **0** |
| survived everywhere | 85 |
| refused by the harness | 5 |
| real gaps | **84** |

**Pass 2 bought nothing here, and that is the finding about the shape of the
suite.** For `tsig` it caught 21 of 63 survivors, because transaction security is
something every other part of the stack touches. DNSSEC is touched by exactly one
project, so a mutation the DNSSEC tests miss is a mutation nothing sees. There is
no second opinion available for this code.

Where the 84 are:

| file | gaps | what it is |
|---|---:|---|
| `DNSSECValidator.cs` | 47 | the chain of trust: RRSIG, DS, the walk, RFC 5011 |
| `DenialOfExistence.cs` | 19 | NSEC and NSEC3 proofs |
| `DNSSECZoneSigner.cs` | 10 | what a signed zone is made of |
| `DNSSECSigning.cs` | 3 | the algorithms |
| `DNSSECCanonical.cs`, `DNSSECSigningKey.cs` | 4 | canonical form, key handling |

Fifty-seven of them are branches, which is the highest proportion of any block so
far. This is code that decides, and half of what it decides is unwatched.

### A rule the triage was missing, again

The classifier calls a parameter default noise, because most of them are: a
default is usually the usual value, and changing it changes nothing about what
the code can do. Two in this block are not.

```csharp
public sealed record NSEC3Parameters(Byte[]   Salt,
                                     UInt16   Iterations   = 0,
                                     Boolean  OptOut       = false)
```

RFC 5155 §6's opt-out leaves insecure delegations out of the NSEC3 chain. As a
default it decides what every zone signed without an opinion proves — and the
mutation that flips it survives the whole suite. The other is
`DNSSECSigningKey.Generate`'s `KeySigningKey = false`: a key made without an
opinion is a zone signing key, and the two sit at different places in the chain.

These are listed by name in `classify_folder.py` rather than matched, because no
pattern can tell "the usual value" from "the safe value" — the name can, and a
rule that cannot be written down should not be pretended into a regex. The list
is the second exception the triage has needed, after the `[NotNullWhen]` one, and
both were found the same way: by reading what the sweep had thrown away.

### One verdict the harness could not read

Pass 1 reported `DNSSECZoneSigner.cs:34` as PARSE-ERROR — the test run produced no
summary line it could parse, which is not a verdict either way. It was re-run on
its own: the mutant builds, the suite runs, 256 pass and nothing fails. The
verdict is SURVIVED and the first attempt was a hiccup in a forty-four-minute run.

The row was corrected in `dnssec-pass1.tsv` and the file as it was measured is
kept beside it as `dnssec-pass1.as-measured.tsv`, which is the same treatment the
contaminated pass-2 file got in the records block. A result that is quietly
rewritten is not a measurement any more.

---



### The three files nothing else had reached

Six gaps in three small files, none of which any other round had gone near, and
the last of the block that a test can take.

**A DNSKEY's RDATA is a public key.** RFC 4034 §2.1 says so, and every reader of
one holds nothing else: a validator learns keys off the wire and never sees a
private half. Asking a key object for its private parameters is not a milder
request that merely returns more — a key that has only the public half refuses
it outright. So an encoder written that way works perfectly in the signer's own
process, where the key was just generated, and throws in **every validator that
ever reads a DNSKEY back**. Two lines, one for RSA and one for ECDSA, and the
test strips both keys to their public parameters and asserts the encoding is
unchanged.

**RFC 3110 §2's exponent length has a boundary nobody reaches.** One octet when
it fits, otherwise a zero octet and a two-octet length — so 255 octets is the
last exponent written the short way. Real keys use 65537, three octets, which is
why the comment beside the code already said the long form "is exactly why
implementations get it wrong".

Getting there needed a key object that holds parameters and nothing else. Windows
CNG refuses to import a 255-octet exponent at all — *Unknown error
(0xc1000001)* — and it is right to refuse, because no such key is usable. But
the question is what the **encoder** writes when handed one, and §2 answers that
whether or not a platform will hold the key. A four-line `RSA` subclass returns
the parameters it was given and refuses the private half, which reaches the
boundary and, as a by-product, is also a key with no private half at all.

**Two names carry a labels field of zero** (RFC 4034 §3.1.3 counts neither the
root's null label nor a leading asterisk): the root apex, which has no labels,
and a name synthesised from the root zone's own wildcard `*.`, whose asterisk is
the one label there was. RFC 4035 §5.3.2 reconstructs the signed name from that
count, and the two must not be reconstructed the same way — one is signed under
its own name and the other under `*.`. A reconstruction that confused them would
hand the verifier octets the signer never hashed, and would do it only for the
root zone, which is the one zone every validator has an anchor for.

**The canonical comparison runs out of octets on exactly two inputs**: when one
RDATA is a prefix of another, and when two are equal. RFC 4034 §6.3 puts the
shorter first and calls the equal pair equal, and those are the only two cases
where the loop reaches its bound rather than returning early — so a bound one
step too far reads off the end of the array there and nowhere else. Both
functions are public and pure, and neither had a test of its own: they were
reached only through a signature that verified or did not, which says nothing
about why.

**And a CDS RRset of two records is a rollover, not a contradiction.** RFC 8078
§4's delete signal is one record and nothing beside it, which is why a sentinel
standing next to ordinary records is refused — but the refusal has to be about
the sentinel and not about the count. §3's algorithm rollover has the child
publish a DS for the old key and the new one at once, and a parent that read
"more than one record" as the contradiction would refuse every rollover it was
asked to make.

---

### Two readings that fail in opposite directions

What was left of the validator once the chain, the denial path and the probe had
been taken: the anchor set, the RRset an RRSIG covers, and the arithmetic above
the root.

**The anchor set is two public lines and one private predicate**, and between
them they decide whether a name is inside the island of trust at all. That
decision is what turns a missing signature into a verdict: RFC 4035 §4.3
separates Bogus from Insecure, and the separation is not about the answer but
about whether the resolver had grounds to expect a signature. An answer with no
proof from a zone under an anchor is what stripping the records looks like; the
same message from outside every anchor is an unsigned zone going about its
business.

`CoveredByATrustAnchor` had two mutations, and **they fail in opposite
directions**:

```csharp
return anchorName.Length == 0 ||
       name.Equals  (anchorName, ...) ||
       name.EndsWith("." + anchorName, ...);
```

Inverting the first test makes **every** name covered by any anchor at all, so
every unsigned zone becomes a forgery. Turning the first `||` into an `&&` makes
a **root anchor cover nothing** — and the root anchor is the one a resolver
actually ships with. The empty name there is not a name that fails to match; it
is the one that matches all of them. Three anchor sets and the same empty answer
pin all of it, including the "at or above" that has to include "at": an anchor
for exactly the queried name covers it, and a validator looking only for a strict
suffix would stop trusting the very zone it was handed an anchor for.

The removal API is the same identity rule one place further out. RFC 4034 §5.1's
"not a unique identifier" is why every lookup in this library matches on tag
*and* algorithm, and `RemoveTrustAnchor` is where a caller asks for that match by
hand. Matching on either half would retire one key by removing every anchor that
shares its algorithm — for a resolver holding the root's current and incoming
keys, the whole store.

**An RRSIG covers one RRset**, which RFC 4034 §3 means as one owner name and one
type together. Gathered by type alone, every record of that type in the message
joins the signed data and the signature fails over octets its signer never saw.
The consequence is not theoretical: an attacker who cannot forge a signature
would not need to, because adding one unsigned A record beside a signed one would
make the genuine answer fail to validate.

**And the root has no parent.** The walk asks each parent for the current zone's
DS, and above the root there is nobody to ask, so a chain that climbs all the way
up without meeting a configured anchor has ended and ended in failure. Read as
its own parent, the root does not send the walk into a loop — the depth limit
never comes into it. It asks the root for the root's own DS, gets no answer, and
reports the delegation unsigned, turning "this chain reaches no anchor I hold"
into "this zone is not signed". Three zones are needed to show it, because the
walk has to take the step twice.

**One more equivalent, and it is the line directly below the one just closed.**
`dotIndex < 0` answers `"."` for a zone of one label; `<=` would also answer it
when the first dot is at index 0. The string being tested is `Zone.TrimEnd('.')`,
and a name beginning with a dot has an empty leading label — which a
`DomainName` cannot hold and which trimming the other end cannot produce.

---

### The reasoning around a span, rather than the span itself

Two earlier rounds took the arithmetic of a single record: strictly above the
owner, strictly below the next, and the last record of a chain wrapping. What was
left is everything around it — which records may be put together into one proof,
and how many names a proof has to deny before it is one.

**Which records.** RFC 5155 §8.2: a validator "MUST ignore NSEC3 RRs with ...
different values" for hash algorithm, iterations or salt. A zone being re-signed
publishes two chains at once, and a record of the old one is hashed by a
different function — its spans are about a different space. The decoy that shows
this is the shape that matters: **its owner name is the hash of the queried name
under the reference record's salt**, so it looks like a match, while its own salt
field says it was computed under another. One decoy kills both halves of the
comparison, because it shares the algorithm and the iteration count and differs
only in the salt.

**And what counts as a record at all.** An NSEC3's owner name is the base32hex of
a hash (RFC 5155 §3); a record whose leftmost label is missing carries none.
`Base32HexDecode("")` answers with an empty array rather than refusing, so "no
hash" and "the empty hash" are one keystroke apart — and the empty hash is the
lowest value there is. A record reaching from it to the highest covers the whole
space: **one record proving the absence of every name in the zone.**

**How many names.** RFC 4035 §5.4 makes an NXDOMAIN proof two statements. The
first says the name is not in the zone; the second says no wildcard could have
synthesised it. A validator that stopped after the first would refuse answers the
zone is willing to give, and one that accepted any record at all as the second —
which is what inverting the wildcard match does — would prove NXDOMAIN from half
the evidence.

**The last one is the one worth having for its own sake.** The walk that looks
for the wildcard climbs from the queried name towards the root, and its bound is
`skip <= labels.Length`. Shortened to `<`, a **one-label query runs no iterations
at all** — and a one-label query is a top-level domain. The root zone's NXDOMAIN
is the most-answered negative response there is, and its wildcard is the root's
own `*.`, reached at the first step of the walk and only there. So the test for
that bound is not a boundary exercise; it is "a TLD that does not exist is denied
by the root", which any resolver does thousands of times a day.

**Three gaps here are equivalent, and all three arguments are one line.**

```csharp
if (Left[i] != Right[i])
    return Left[i] < Right[i] ? -1 : 1;
```

The value that separates `<` from `<=` is exactly the one the guard above
excludes — twice, once in the hash domain and once in the name domain, the same
two comparison helpers that have now produced a killed mutant and an equivalent
one apiece. The third is `nsecs.Length > 0`, which is reached only when there is
no NSEC3 either: widened, it hands `VerifyNSEC` an empty array, where the NODATA
loop has nothing to iterate and every `Any(...)` is false. It returns NotProven,
which is the answer the next line gives anyway.

---

### The zone where the records are not the zone's

Every test the suite had of the signer ran against a zone with no delegations in
it. `Every_Authoritative_Rrset_Is_Signed` says so in its own failure message
— "a zone with no delegations" — and that is exactly the shape in which the
question does not arise.

A delegation is the one place where the records present are not the zone's own
data. RFC 4035 §2.2 is explicit: an RRSIG **MUST NOT** be generated for a
delegation's NS RRset or for glue, because the NS RRset is authoritative in the
*child* and the glue is a copy of the child's addresses kept so the child can be
reached. The DS is the exception in the other direction — the parent's statement
about the child's key — and so is the NSEC or NSEC3 at the delegation point,
which is what proves what the parent does and does not delegate.

Four mutations sat on that one expression, and each of the four is one way for it
to be wrong: sign the child's NS RRset, sign the glue, stop signing the DS, stop
signing the denial record. **A signer with any of them produces a zone that looks
signed.** The one that stops signing the DS breaks every chain of trust through
the zone; the ones that sign the child's records make signatures the parent has
no right to make.

All four are asserted in one test, with a control, because separately each would
also pass against a signer that signed nothing at all.

**And the same story one level up, where a key gets its job.** The two DNSSEC key
roles are a convention built on one bit: RFC 4034 §2.1.1 puts the Zone Key flag
at bit 7 and RFC 3757's Secure Entry Point flag at bit 15, which on the wire
makes a zone-signing key 256 and a key-signing key 257. The consequence is RFC
4035 §5.2: a validator authenticates the DNSKEY RRset with the DS from the
parent, and the DS covers the key-signing key — so the DNSKEY RRset has to be
signed by *that* key or the chain does not close.

Every other test of the signer generated its key with `KeySigningKey: true` and
stopped there, so the bit's reading, its default, and the split it drives were
all unwatched. Four more mutations: invert the reading, default to "key-signing",
swap which key signs what, and drop the fallback for a zone keyed with only one
of the two roles. That last one is the sharpest — a zone with no key-signing key
is unusual and legal, and RFC 4035 §2.2's requirement that the apex DNSKEY RRset
be signed does not soften for it.

The flag test asserts the numbers 256 and 257 rather than the property alone,
because **a reading of the bit that is inverted in both directions at once is
self-consistent**: the key would report the role it was asked for while
publishing the other one to the internet.

**Three gaps in the signer are equivalent, and this time the argument is a
proof rather than a search.** The walk that enumerates empty non-terminals opens
with a guard:

```csharp
if (dot < 0 || dot + 1 >= name.Length)
    break;
```

and two lines below it are the ones the comment there calls "belt as well as
braces". The braces are what make the belt unobservable. `dot <= 0` differs only
for a name beginning with a dot, which a `DomainName` cannot hold and which
stripping a label cannot produce. The other two let the walk take one more step,
and that step either leaves the name unchanged (no dot in it) or empties it (the
dot is last) — after which `name == Apex`, or `name` not ending in `"." + Apex`,
breaks before `owners.Add` is reached. The set of empty non-terminals is the same
under all three readings, and all three were run to confirm it.

---

### The other column of the table

One line, and the suite had read half of RFC 8624 §3.1 to get there.

```csharp
// Unknown algorithm
_  => false
```

`SignatureAlgorithmMatrixTests` takes every algorithm that table asks a validator
to implement and drives it against a zone BIND signed with it. That is the
**DNSSEC Signing** column and the implemented half of **DNSSEC Validation**. The
same table has rows whose validation column reads **MUST NOT** — 1 (RSAMD5),
3 (DSA), 6 (DSA-NSEC3-SHA1) — and beyond the table are the numbers IANA has
assigned nothing to, including the two private-use ranges of RFC 4034 Appendix
A.1.

Nothing watched the arm that answers for all of them. Flipped to `true`, **the
attacker picks the number**: a signature under algorithm 100 is any octets at all,
and they verify.

The construction is the sharp one, because "returns false" is also what a broken
verifier returns. The key, the data and the signature are the same three in the
control and in the case, and the signature genuinely verifies under the number it
was made with. Only the number changes. RSAMD5 makes the point best: it carries
its key in the same RFC 3110 form as RSASHA256, so there is not even an encoding
to hide behind — the refusal is the number being forbidden and nothing else.

**Which verdict a forbidden algorithm earns is a question the RFCs leave open**,
and the test says so rather than settling it. Hermod answers Bogus, because
`ValidateRRSig` returns Bogus for "did not verify" and this arrives as a failure
to verify. There is a reading that says Insecure, and it is not a weak one: RFC
6840 §5.2 requires a DS of an unusable algorithm to be disregarded and the
delegation "treated as if it were unsigned", RFC 8624's own introduction says
"the effect of using an unknown DNSKEY algorithm is that the zone is treated as
insecure", and **Hermod already applies exactly that reasoning one layer down**,
in `HasUsableDelegationSigner`, with a comment about the day a child moves to an
algorithm this code has not learned yet being "precisely when the answer must not
be an outage".

Neither RFC states the rule for an RRSIG, so the assertion is deliberately loose
— not Secure, without naming which of the other three — and the reasoning is
written into the test rather than into a finding. A validator answering Bogus
where Insecure was meant takes a zone off the internet for its users; that is
worth recording, and it is not worth claiming as a deviation from a rule nobody
wrote.

---

### A step the suite never had to take

RFC 4035 §5.2 is a move repeated: the DS in the parent authenticates the child's
key, and the parent's key is authenticated the same way one level further up,
until a key is reached that the resolver was configured to believe.

**Every test in this suite anchored the fixture zone with its own DS**, which is
the shortest chain there is. The first check inside `WalkChainOfTrust` succeeds
and the step is never taken — so five mutations sat on the part that takes it,
and every test this suite has over the chain of trust walked past all five.

Anchoring one level *above* the fixture forces it. The child half stays genuine,
BIND's signature over BIND's zone, verified before the walk is reached; only a
parent zone above it is constructed, and the walk has to fetch the child's DS,
verify the child's KSK against it, cross into the parent, and choose which of the
parent's keys to carry up.

Three tests: the step taken once and anchored above, an unsigned parent, and a
parent publishing two keys. They pin **which signature the step reads** (the one
over the DNSKEY RRset, not whichever RRSIG the message happens to carry), **what
an unsigned parent means** — Insecure rather than Bogus, the same distinction
RFC 4035 §4.3 draws and the same reasoning the file already applies to a DS RRset
with no usable algorithm — and **which key the signature names**, by tag and
algorithm together.

**The third test was green and proved nothing, and only the mutation said so.**
The decoy was published without the SEP bit, on the reasoning that it needed only
the same algorithm to be picked by the wrong reading. It was picked — and then
one line below the lookup the walk falls back to "whichever published key is a
SEP of this algorithm", which is the ordinary way a zone's signing key is found
from its zone-signing one. The fallback handed the right key straight back, the
verdict never moved, and the test passed for a reason that had nothing to do with
what it claimed. Giving the decoy the bit as well closes that door, and the
mutation died.

That is the second time this block has produced the same lesson from the opposite
direction. In the key-identity round a second path was expected to rescue a wrong
choice and did not, because the decoys carried the right digest. Here a second
path was not expected to and did.

**One gap in the walk stays open, and it is deliberate:**

```csharp
for (var depth = 0; depth < 20; depth++)
```

`<` against `<=` differs only for a delegation chain of exactly twenty-one zones.
Such a chain is legal — RFC 1035 §2.3.4 caps a name at 255 octets, which leaves
room for far more than twenty-one labels — so the mutation is reachable, and the
two readings disagree about whether that chain validates or comes back
Indeterminate.

**They are both conformant, and the reason is a negative that had to be looked
for rather than assumed.** The obvious move was to call this the same case as
LOC's hemisphere boundary in the records block. It is not: that pair was
eventually *decided*, because §5 of RFC 1876 prints the reference implementation
and settles it, and the passage about it further down is kept as a warning
against exactly this judgement — the prose had been read and the appendix had
not.

So the appendix was looked for. RFC 9364 is the DNSSEC BCP, whose job is to
catalogue the whole series; it names no limit on the depth of a chain of trust,
on the number of DS-to-DNSKEY steps, or on validator work, and cites nothing
that does. A resolver that follows twenty is as correct as one that follows
twenty-one, and a test would pin a number Hermod is free to change. **If the
number is ever to be asserted, it should first become something a caller can
read** — the move the hold-down constant already made, which is why
`AddHoldDownTime` has a test and this does not.

The two `ConfigureAwait(false)` gaps beside it stay open for the reason given
elsewhere: not equivalent, but with no reading from a test host.

---

### The same four checks, written twice

RFC 4035 §5.4 is one sentence long where it matters: "the resolver MUST
authenticate the NSEC RRset". A denial of existence is two claims — the chain
says the name is absent, the signature says the zone is the one saying so — and
an unauthenticated proof is a proof an attacker can write.

`ValidateDenialAsync` therefore repeats, on the authority section, every check
`ValidateAsync` makes on the answer section: **the validity window, the key the
signature names, the signature itself, and the chain up to an anchor.** Four
rules, implemented a second time on their own lines. Six mutations sat on them
and the suite watched none.

Two of the four had already been answered on the other side of the house, and
their twins fell to the same two ideas:

- **The window** is the twin of the comparison in the answer path, and it wanted
  the same `Now` parameter that one did. With the seam already in place, the four
  ways to be wrong by one second are four assertions. It matters more here than on
  the answer side, not less: an expired denial is a replay of "no such name" from
  before the name existed, and it is the one replay that costs nothing to obtain
  — every resolver on the internet has been handed one.
- **The key lookup** is the twin of the one in the answer path, and it fell to
  the same relabelled key: the tag covers the DNSKEY's flags, so the same key
  material under a different SEP bit is the same key with a different tag. Publish
  only that, anchor it with its own DS, and a validator matching on algorithm
  alone verifies the NSEC chain and calls the denial Secure.

**The other two are a shape the answer path does not have**, and they are the
interesting half:

```csharp
if (sigResult   != DNSSECValidationResult.Secure) return sigResult;
...
if (chainResult != DNSSECValidationResult.Secure) return chainResult;
```

Inverting either turns "stop if this half failed" into "stop if this half
passed". Each then reports Secure the moment its own check succeeds, and the
rest of the method — including the part that asks whether the records prove
anything — never runs.

That is two separate fail-open attacks, and the tests are named after them rather
than after the lines. One offers a **signature that proves nothing**: a single
genuine NSEC from the fixture, with its genuine RRSIG, for a question it says
nothing about. Every cryptographic check passes and the answer is still a lie —
which is what replaying a real denial for a different name looks like. The other
offers a **proof nobody vouches for**: the whole chain, proving exactly what was
asked, under a trust anchor whose digest is not the key's. A well-formed proof
from an unanchored zone must not come back Secure, or anyone able to sign a zone
could deny any name in it.

Both inversions fall to both tests, which is the useful part of the count: the
two checks are independent, and the two failures are independent, and each test
catches whichever early return it reaches first.

---

### The set a resolver ends up believing in

RFC 5011 is how a resolver's trust anchors change when nobody touches its
configuration, and it has two halves that fail in opposite directions. §2.4.1: a
new key is admitted only after thirty days of continuous presence, so that
whoever can answer for a resolver for an afternoon cannot install one. §2.1: a
revoked key is dropped at once and never admitted again, so that a key known to
be compromised cannot be put back by republishing it without the bit.

`ProbeForTrustAnchorUpdatesAsync` had ten gaps in it, and nine are closed.
**Three were not about the
anchors at all — they were about the `Boolean` the probe returns.** A caller
writes its trust store out when it is told the set changed, so `modified = true`
turned off loses a rollover at the next restart, and `if (removed > 0)` widened
to `>= 0` has a file rewritten every time a stranger's revocation goes past.
Eight tests already stood here and not one of them looked at the return value.

Two more are the matching itself. The removal finds an anchor by tag **and**
algorithm:

```csharp
a => (a.KeyTag == liveKeyTag || a.KeyTag == keyTag) &&
      a.Algorithm == key.Algorithm
```

Turning that `&&` into `||` drops every anchor that merely shares the algorithm.
For a resolver holding the root's KSK and the one being rolled in beside it, that
is the whole store on one revocation. No test had a second anchor to lose, so a
bystander is all it took — and the bystander is the assertion, not the key that
was revoked.

**And then the pair that needed the pending set to be visible at all.** The
hold-down only applies to keys the resolver does not already trust, which it
decides with the same tag-and-algorithm match:

```csharp
var isExisting = trustAnchors.Any(a => a.KeyTag    == keyTag &&
                                       a.Algorithm == key.Algorithm);
```

Both mutations of that line are invisible in the answer. A resolver that failed
to recognise a key it already trusts returns "nothing changed" — which is what a
correct one returns — and leaves `TrustAnchors` exactly as long. The two readings
differ in one place only: whether a hold-down was started. That is a month away
in `TrustAnchors` and immediate in `PendingAnchors`, which Hermod exposes and
which the fixture that was already here was already using. Both tests assert on
it, and each kills a different half of the condition: the key that is already an
anchor pins the `==`, and a key sharing a tag under another algorithm pins the
`&&`.

The last one is the `catch` around the whole probe. The stub could model a
resolver that answers "I do not know" — `Unreachable` sets `IsValid` to false —
but that is caught one line earlier, by the guard that reads the response. It had
no way to model a transport that fails outright. One `Throws` flag, which returns
a faulted task instead of an answer, and the `catch` has a test: a probe that
learned nothing must report no change, or a caller persists a trust store built
from an answer that never arrived.

**The tenth gap needed a seam, and is the fourth place in this library to need
the same one.**

```csharp
if (Timestamp.Now - pending.FirstSeen >= AddHoldDownTime)
```

`FirstSeen` is a clock reading taken at one probe and `Timestamp.Now` is another
taken at the next, so the difference between them is the real time the two probes
took plus whatever the test travelled. Moving the clock forward by exactly thirty
days still leaves the milliseconds, and `>=` and `>` differ only at exact
equality. No amount of travelling gets a test onto that instant, because the
instant is defined by two readings the test does not make.

`TSIGSigner.Verify` takes `UInt64? Now`, `SIG0Signer.Verify` takes
`DateTimeOffset? Now`, and `ValidateAsync` gained one for the validity windows.
`ProbeForTrustAnchorUpdatesAsync` is the fourth, and **one reading now serves the
whole probe** — the hold-down that is being checked and the hold-down that starts
in the same pass were two separate readings of `Timestamp.Now` before, which is a
thirty-day interval measured from two different instants. A caller that names
neither cannot stand on the boundary; a caller that names one stands on it
exactly.

With that, the boundary is an ordinary test: seen at `t`, refused at
`t + 30 days - 1s`, admitted at `t + 30 days`. It moves no clock at all, so it
also leaves nothing behind for whatever runs next — which the two hold-down tests
beside it, which do travel, have to undo in a `finally`.

Nine of the probe's ten gaps are closed. The tenth is `ConfigureAwait(false)`,
which is not equivalent — it decides where a continuation resumes — but has no
reading from a test host, which has no synchronization context for the two
answers to differ about.

### Eight tests that were already there

`TrustAnchorRolloverTests` was not a new file. It had eight tests in it — the
hold-down constant, a new KSK entering the hold-down instead of becoming an
anchor, repeated sightings not shortening it, a pending key dropped when the zone
stops publishing it, a ZSK never becoming a candidate, an unreachable root
changing nothing, a revoked KSK removed, and a revoked key unable to come back —
and this round began by writing a new fixture over the top of it.

**Nothing downstream of a test file notices tests that stop existing.** The
replacement was green, the mutation run reported a clean baseline, and six gaps
fell exactly as predicted. The eight tests that went missing were not killing any
of the mutants this round was aimed at, so not one number moved in the direction
of the mistake. What caught it was reading `git diff --stat` before the commit
and seeing 419 changed lines in a file that was supposed to be new.

The round was redone from the file that was there. The six new tests are
additions to it, in its own vocabulary — which is how the pending set came to be
used above: the fixture had been reading it all along.

---

### The two ends of a span that proves nothing is there

An NSEC says "between my owner name and my next name there is nothing". Both of
those names exist — they are owner names in the chain — so the span is open at
both ends, and RFC 4034 §4.1.3 adds that the last record of a zone points back at
the apex, so that one record's span wraps around the end of the ordering.

Five mutations sat on those four lines. Four of them fell to five tests built
from NSEC records made by hand, because a signer will never produce the shapes
that matter: a query landing exactly on a boundary, a span running off the end of
the zone, and a chain of one record whose next name is its own owner.

- **The next name is not denied.** It is the next owner in the chain, and a span
  that reached it would be proof that a name the zone lists is missing — which is
  the proof an attacker wants for a name they removed.
- **A name past both ends is not denied.** Wanting only one of the two ends would
  let the first record of a zone deny everything after it.
- **The last record wraps**, and a name sorting after the zone's last name is
  denied by it. Treating that record like the others leaves a zone unable to deny
  anything past its end.
- **A chain of one record wraps onto itself.** Owner equal to next is still a
  wrap; reading equality as "no wrap" makes the span empty and denies nothing.

The fifth is the lower end, and it is genuinely unreachable. The two readings
differ only when the queried name equals the owner, and neither caller can put
that case in front of it: `VerifyNSEC`'s NODATA loop returns first whenever a
record owns the name, and for the wildcard the very next clause asks whether a
record owns it and answers the same way in the same iteration. The guard at the
*other* end of the same span has no such cover, which is why one of the pair was
killed by a test and the other written down.


### A key that verifies the signature and is not the one it named

RFC 4034 Appendix B computes the key tag by adding up the DNSKEY's RDATA, and
§5.1 says plainly that it "is not a unique identifier". So every lookup in a
validator matches on tag *and* algorithm, and RFC 4035 §5.3.1 makes it a MUST:
the RRSIG's algorithm and key tag "MUST match the owner name, algorithm, and key
tag for some DNSKEY RR in the zone's apex DNSKEY RRset".

Testing that needs a key which would verify the signature and is not the one the
signature named — otherwise "looked the key up properly" and "found something
that worked" cannot be told apart. **The tag covers the flags**, so the same key
material under a different SEP bit is the same key with a different tag. The zone
publishes only that, and a validator matching on algorithm alone finds it,
verifies, and reports Secure.

The trust anchors one level up work the same way, and the decoys there are the
part worth keeping: each carries the **right digest** for a key it does not name.
A wrongly chosen anchor would otherwise be caught by the digest check behind the
lookup, and the test would pass without saying anything about the lookup. With
the digest right, only the tag and the algorithm stand between the decoy and a
Secure verdict.

That is also where the reasoning went wrong on the way. Having written the decoys
for exactly that reason, I then talked myself out of expecting them to work — on
the grounds that the KSK path below would catch what the first loop missed. It
would have, for an anchor with the wrong digest. Five mutations fell where one was
predicted.

### The same five shapes, in the hash domain

The NSEC3 half of the same file is the same arithmetic written a second time,
against hashes instead of names, and it came out the same way: four killed and
one unreachable, the same four and the same one.

The chains are built by hand, which for NSEC3 means computing the hashes — RFC
5155 §5's H(name) with the suite's own SHA-1, so a record can be given a span
that ends exactly on the hash of the name being asked about. BIND produces no
such chain, which is why the fixture-based tests could not reach these.

**The unreachable one is unreachable for the same reason as its twin**, and that
is what makes the pair worth having: a name whose hash equals an owner *matches*
that record, and `VerifyNSEC3` looks for a match before it looks for a cover —
at the queried name and again at every ancestor on the way up. Nothing can be
handed to `FindCover` whose hash equals an owner in the set. The guard at the
other end of the span has no such cover, in both halves.

One kill was not predicted, and working out why is worth more than the kill.
`CompareHashes` walks to the length of the shorter hash and returns at the first
octet that differs. Moving the loop's bound by one reads past the end of the
array — but only when the walk gets that far, which means only when every octet
matched, which means only when the two hashes are *equal*.

There is exactly one place that compares a hash with itself: the chain of a
single record, whose next hashed owner name is its own owner. The test written
for the wrap detection is the only one in the suite that ever asks that question,
and it took this line down as a by-product.

### A test that proved the wrong thing

`ChainValidationTests` had `Expired_Signature_Is_Bogus` and
`Not_Yet_Valid_Signature_Is_Bogus`, both citing RFC 4034 §3.1.5, and the sweep
could turn the window check into one that never fires without either of them
noticing.

Both build their case by rewriting the RRSIG's inception and expiration:

```csharp
var expired = Rewindow(signature, Now - 7200, Now - 3600);
```

§3.1.8 puts the RRSIG RDATA into the signed data, so rewriting the window
breaks the signature as well. The record is then rejected for the other reason,
and a validator that had stopped looking at the clock entirely would still call
it Bogus. The test asserted the right verdict and demonstrated something
narrower than it claimed — that a tampered record does not verify.

The case that pins the check leaves the record exactly as BIND signed it and
moves the clock instead:

```csharp
var pastExpiry = TimeSpan.FromSeconds(signature.SignatureExpiration - Now) + TimeSpan.FromHours(1);
Timestamp.TravelForwardInTime(pastExpiry);
```

The signature still verifies — a signature does not know what time it is — and
only the window says the answer is stale. That is exactly what §3.1.5 is for: a
replayed answer from a zone that has since changed its mind carries perfectly
good cryptography.

### The four that need a seam Hermod has twice already

The same line has three mutations and only one of them fell. The other two, and
the two on its twin in the denial path, move the comparison by one second:

```csharp
if (now < rrsig.SignatureInception || now > rrsig.SignatureExpiration)
```

`now` comes from `Timestamp.Now` read inside `ValidateAsync`, so the second where
`now` equals the inception can only be hit by racing the clock — and a test that
is right 99 times in 100 is worse than no test.

**Hermod has already solved this twice in the same library.**
`TSIGSigner.Verify` takes `UInt64? Now = null` and `SIG0Signer.Verify` takes
`DateTimeOffset? Now = null`, both for exactly this check and exactly this
reason. The validator is the third of the three and the only one without it.


---

## The result: transaction security

Measured against Hermod **`53f20591`**, `libs/Hermod/Hermod/DNS/TSIG/**`, judged in
pass 1 by SecureTransports and in pass 2 by the remaining seven projects.

| | |
|---|---:|
| mutants | 94 |
| not viable (would not compile) | 5 |
| killed by SecureTransports | 26 |
| killed by another project | 21 |
| survived everywhere | 40 |
| refused by the harness | 2 |

**Every one of the 40 is a real gap.** That is the first thing this block said and
it is not how the other two went: the records sweep called 118 of its 358
survivors noise, and `core` called 71 of 203. Here the triage found none at all.
`DNS/TSIG` is almost pure logic — no `#region` names, no attributes, no parameter
defaults for the classifier to throw away — so the survivor count and the gap
count are the same number.

The second thing is that **a third of the pass-1 survivors were caught by somebody
else** (21 of 63), against `core`'s 60 of 265. The killers are spread across
Dnssec, ResourceRecords, WireFormat, Server and Client, which is what transaction
security looks like from outside: it is not a corner of the stack, it is a thing
every other part touches.

Where the 40 are:

| file | gaps | what it is |
|---|---:|---|
| `SIG0Signer.cs` | 18 | RFC 2931 — public-key transaction signatures |
| `TSIGSigner.cs` | 14 | RFC 8945 — shared-secret transaction signatures |
| `TKEYExchange.cs` | 5 | RFC 2930 — the Diffie-Hellman key exchange |
| `DNSTransactionSecurity.cs` | 2 | which of the two a message carries |
| `TSIGAlgorithms.cs` | 1 | the algorithm allow-list |

And they group into themes rather than scattering, which is what makes the block
worth taking as one piece:

- **Five copies of `Message.Length < 12`** — RFC 1035 §4.1.1's header — each one
  standing in front of a walk over octets a peer sent.
- **The two time windows**: RFC 2931 §3.1's inception and expiration, and RFC 8945
  §5.2.3's fudge. Both are the shape where one comparison decides whether a replay
  is accepted.
- **The `TryStrip*` guard chains**, where an `||` turned into an `&&` makes a
  message that failed one check pass anyway.
- **The two `Request.Length > 0` guards** — whether the request's MAC is prepended
  to the response's digest (RFC 8945 §5.4.1), which is what binds a response to
  its request.

The two the harness refused are one line carrying two mutations of the same
operator, which it cannot tell apart; they are recorded as SETUP-ERROR rather than
counted either way.





### Eighteen guards that cannot fire, and one that can

What was left of the `tsig` block after the tests was almost all one shape:

```csharp
if (!TryStripSIG0(SignedMessage, out var unsigned, out var sig) ||
    sig is null || unsigned is null)
```

Both strip functions set every output before their single `return true` and return
false on every other path, so a null output alongside a true result cannot happen
— which is exactly what the second and third terms test for. Whichever connective
is changed, the expression agrees with the original on both of the two cases that
can arrive. The same chain appears in both `Verify` overloads of each signer, in
`BuildErrorResponse`, in `CarriesBothTSIGAndSIG0` and in
`DNSTransactionSecurity`: thirteen mutants, one argument.

Two more arguments cover the remaining five:

- **`Message.Length < 12`**, three times. Twelve octets is a header and nothing
  else, so with ARCOUNT zero there are no records to walk and with ARCOUNT set the
  walk reads past the end and throws into the catch. Both readings answer false,
  and the suite now sends exactly that message and asserts it.
- **`offset < 0`**, twice. `FindLastRecordOffset` answers -1 or a position it took
  at the start of a record, and no record begins before octet twelve — so zero is
  not among its answers, and `<= 0` tests for a value that never arrives.

**The nineteenth was not one of them**, and separating it out is the point of
doing this by hand rather than by pattern:

```csharp
DomainName.ParseLenient(owner.Length == 0 ? "." : owner)
```

`DNSTools.ExtractName` ends on `String.IsNullOrEmpty(result) ? "." : result` and
never hands back an empty string, so the condition is dead and the expression
always yields `owner`. But the mutation inverts the condition rather than removing
it, and the inverted version always yields `"."` — which differs for any SIG whose
owner name is not the root. That is observable: `TryStripSIG0` hands the record
back and `SIG.DomainName` is public.

So it was left open rather than called equivalent, with the note that the ternary
should go. **That note got the RFC wrong**, and the correction is the reason this
was worth doing by hand twice. It said "RFC 2931 §3 puts the root there, so the
only input that tells the two apart is one the RFC does not describe". §3 does not
put the root there. It says:

> For all SIG(0) RRs, the owner name, class, TTL, and original TTL, are
> meaningless.

and then that the owner name **SHOULD** be root, "to conserve space". A SHOULD over
a field the same sentence calls meaningless is about as far from a requirement as
a specification goes — a peer may write a real name there, and a verifier that
refused it, or quietly replaced it, would be wrong about a message it has no
grounds to be wrong about.

That makes it a conformance question after all, and it is now answered by a test
rather than by an argument: a signed query whose SIG(0) owner is rewritten from
the root to a real name is still stripped, still carries that name back, and still
verifies — §3.1 signs the message *without* the SIG record, so the owner octets are
not in the digest and the rename cannot move the verdict. That test kills the
mutation.

The dead branch then went, after the behaviour it was standing in front of had
been pinned and not before. Its line is gone and nothing mutable is left on it,
which is the third state the ledger has: `superseded`.

**The `tsig` block is closed.** 94 mutants, 40 real gaps: 20 killed by a test, 19
unreachable and written down, 1 whose line a change removed.

### A silent ledger error, and the guard that now catches it

The first attempt at this round put a second `"DNS/TSIG/TSIGSigner.cs"` key into
the equivalence table. Python keeps the last of two identical keys and says
nothing, so the earlier entry — the skew expression from the windows round —
vanished, and the totals still added up: eighteen equivalents either way, because
seventeen had just been added.

What caught it was expecting a number. The round should have left one gap open and
left two.

`make_closed_folder.py` now refuses to write a ledger containing an entry that
matches no gap in the sweep's own output. That catches a line number that has
moved, a path spelled a shade differently, and a shadowed entry — all of which
otherwise produce a plausible total and a quietly missing row.

### Three refusals that look like one

`TKEYExchange` reads RFC 2539 §2's Diffie-Hellman fields: three values, each with
two octets of length in front of it. Its five gaps closed to four tests, and the
work was not writing the tests — it was working out which malformed RDATA reaches
which refusal, because the file already had tests for "truncated" and "well-known
group index" and neither touched the lines in question.

There are three ways the reader says no, and each needs its own shape:

- **No room for the length octets.** Reached only by RDATA of nought or one
  octets, or by a field that starts within one octet of the end. The existing
  truncation test cuts a value's *body* short, which is a different line.
- **A length with nothing behind it.** The prefix is present, it is the last
  thing in the RDATA, and it promises octets that are not there.
- **Lengths that do not add up**, which is the outer check and was already
  covered.

And the outer check is why two of those had survived a test that looked like it
should have caught them: when the inner reader is made to lie, `offset` stops
advancing, so `offset != RData.Length` usually notices and refuses anyway. The
only inputs where a lie gets through are the ones where the reader stops exactly
at the end of the data — which is what both new cases are built to do.

The fourth test is the opposite: **a length of zero is well formed.** §2 sets no
minimum, so a field that is present and empty is a field, and it is the single
input where the reader's two guards disagree about their jobs — there is room for
the length octets and no body to fit.

### The operand that runs out first in every real exchange

RFC 2930 §4.1 derives the keying material by XORing the DH value against two MD5
digests joined, which is always 32 octets. A DH value is not: the smallest modulus
RFC 2539 contemplates gives 128. So in every exchange that ever happens the
right-hand operand runs out first, and §4.1 says what then — the shorter is
left-justified, its missing tail treated as zero.

Every test in the file used a 17-octet secret, which is shorter than the digests,
so the branch that every real exchange takes was the one never taken. A 128-octet
secret makes the tail of the keying material the DH value unchanged, which is
checkable without recomputing anything.

`TKEYExchange` is closed: five gaps, five killed.

### The front door

`TryStripTSIG` and `TryStripSIG0` run on whatever a peer sent, before a key is
chosen and before a MAC is computed, and every verification path in the stack
begins by calling one of them. Ten of their gaps fell to seven tests that do
nothing but hand them messages which are not signed, in each of the ways a
message can fail to be.

Too short to hold RFC 1035 §4.1.1's header. A header whose ARCOUNT promises a
record that is not there. A real signature with its last octets taken away.
Octets after the last record, so the walk finishes somewhere other than where the
message does. An OPT at the end, which is a record but not a signature. And a SIG
whose Type Covered is not zero, which RFC 2931 §3 makes a signature over an RRset
rather than over this message.

Two of those came from getting it wrong first.

**The ARCOUNT that lies does not reach the guard it looks like it should.** A
twelve-octet header claiming one additional record sends `FindLastRecordOffset`
walking off the end, where `ExtractName` throws — so the exception handler catches
it and the `offset < 0` refusal three lines above is never reached. Reaching that
one needs a walk that *finishes* and finishes in the wrong place, which is what
trailing octets do. Two refusals that look like one, and only one message shape
reaches each.

**And a test whose name claimed more than it did.** It was called
`A_Sig_Over_An_Rrset_Is_Not_A_Transaction_Signature` and it never built a SIG over
an RRset — only unsigned messages, which the function refuses for a different
reason. Rewriting the Type Covered field of a real SIG(0) from 0 to A is what
makes the record still a signature, still last, and no longer about this message.

### The guards that are belt and braces

Most of what is left in this block is one shape repeated:

```csharp
if (!TryStripSIG0(SignedMessage, out var unsigned, out var sig) ||
    sig is null || unsigned is null)
```

`TryStripSIG0` never returns true with either output null, so the two null checks
cannot fire, and turning any one of those `||`s into an `&&` changes nothing a
caller can see. The same pattern appears in both `Verify` overloads of each
signer, in `CarriesBothTSIGAndSIG0`, and in `DNSTransactionSecurity` — which is
most of the twenty-three still open. They are worth writing down as what they are
rather than chased: defensive redundancy after a method whose contract already
rules the case out.

### Four windows, and the second that was never on either side of them

The first of the `tsig` block's forty, and every one of them was **already
tested**. That is what makes them worth writing down.

RFC 8945 §5.2.3 puts the server's time "outside the time interval specified by the
request (which is the Time Signed value plus/minus the Fudge value)" before it is
an error, so the fudge itself is the last second that is still inside. The suite
had a fudge test with three cases: 299 seconds, 301 seconds, and far in the past.
It steps over 300 without landing on it, and 300 is the only second where the
comparison can be wrong by one.

RFC 2931 §3.3 says a SIG(0)'s times "form a time bracket such that messages
outside that bracket can be ignored" — so the bracket's own edges are inside it.
The suite had a window test too, built from `now.AddHours(-2)` and
`now.AddHours(1)`. Hours either side of a boundary that is one second wide.

Both tests were right about what they asserted. Neither could see the line it was
aimed at.

The same shape a third time: the algorithm allow-list is four `||`s, and a chain
of ors goes wrong one link at a time. The suite asserted the mandatory
HMAC-SHA256 and a refused HMAC-MD5 — the two ends — and left SHA1, SHA384 and
SHA512 in the middle unwatched, where turning one `||` into an `&&` takes out two
of them at once.

### Two guards that look identical and are not

`RequestMAC.Length > 0` in `TSIGSigner` and `Request.Length > 0` in `SIG0Signer`
guard the same idea: fold the request in only when there is one. Mutating each to
`>= 0` changes one of them and not the other.

```csharp
// TSIG — the length goes in first, so an empty MAC writes 00 00
digestInput.WriteUInt16BE((UInt16) RequestMAC.Length);
digestInput.Write(RequestMAC, 0, RequestMAC.Length);

// SIG(0) — only the octets, so an empty request writes nothing at all
data.Write(Request, 0, Request.Length);
```

So a test that signs with an empty array and expects the same result as signing
without one kills the TSIG guard and cannot touch the SIG(0) one. Both assertions
are true and worth having; only one of them is evidence. This was predicted the
other way round before the run, and the run is what corrected it.

---

## The result: the record types

Measured against Hermod **`973fed31`**, `libs/Hermod/Hermod/DNS/ResourceRecords/**`,
judged by all seven conformance projects that need neither Docker nor WSL.

| | |
|---|---:|
| viable mutants | **585** |
| caught by the record tests | 171 |
| caught **only** by another project | 56 |
| caught by nothing | 358 |
| — of those, not really code | 118 |
| — of those, **real gaps** | **240** |

**Score as measured: 38.8 %. With the noise removed: 48.6 %.**

About half of the changes that can be made to Hermod's resource-record code go
unnoticed by every test in this repository.

---

## The result: the code every query passes through

Measured against Hermod **`e592b5e7`**, the files directly in
`libs/Hermod/Hermod/DNS/` — names, the message, the question, the zone file and
the shared reading helpers — judged by the same bench.

| | |
|---|---:|
| viable mutants | **375** |
| caught by the record tests | 110 |
| caught **only** by another project | 60 |
| caught by nothing | 203 |
| — of those, not really code | 71 |
| — of those, **real gaps** | **132** |
| not judged: three mutations of one operator on one line | 2 |

**Score as measured: 45.3 %. With the noise removed: 55.9 %.**

Slightly better than the record types, and the same order of magnitude: the code
every single query passes through is not better watched than the individual
record parsers. 103 of the 478 mutants did not compile, twice the record block's
share — a property of the code rather than of the tests, since `DomainName` and
`DNSPacket` hold more comparisons whose operands have only one legal shape.

The second pass earned its five hours here. Sixty of the 265 first-pass survivors
are caught by `WireFormat`, `Server`, `Client`, `SecureTransports`, `Edns` or
`Dnssec` — including 24 of `DNSPacket`'s 26, which is exactly right and would have
been reported as a gap by a one-project sweep.

Where the 132 were, and what became of each:

| file | gaps | mostly |
|---|---:|---|
| `DNSNamePattern.cs` | 21 | **closed** — 20 killed, 1 unreachable |
| `DNSInfo.cs` | 20 | **closed** — 19 killed, 1 a dead read |
| `DNSServiceName.cs` | 20 | **closed** — 18 killed, 2 equivalent |
| `DomainName.cs` | 19 | **closed** — 15 killed, 3 unreachable, 1 superseded by finding 57 |
| `DNSServiceInstanceName.cs` | 16 | **closed** — 15 killed, 1 unreachable |
| `DNSTools.cs` | 15 | **closed** — 11 killed, 4 unobservable |
| `DNSZoneFile.cs` | 11 | **closed** — 7 killed, 4 unreachable |
| `IDomainName.cs` | 2 | **closed** |
| `DNSQuestion.cs` | 5 | **closed** |
| `DNSPacket.cs` | 2 | **closed** |
| `DNSPadding.cs` | 1 | **closed** — unreachable |

`DNSInfo` was the one that read as a pattern rather than a list: twenty branches
and not one boundary or refusal. It decides which answer counts and what is
cached, and no test had taken both sides of any of those decisions.

The twenty split cleanly in two. RFC 1035 §4.1.1's header flags as the client
reads them — AA, RD and RA could each be inverted unnoticed, while TC, AD and CD
could not, because the truncation and DNSSEC rounds had already pinned those
three. A suite tests what it went looking for, and the sweep is what shows the
shape of that.

The other sixteen are `false` arguments in `TimedOut`, `Invalid` and `Failed` —
the flags of a result built when no response arrived at all. Each of them is a
claim about octets that never existed: a timeout reporting AA claims authority
for an answer nobody gave.

Nineteen fell. The twentieth is `var IS = (Byte2 & 128) == 128;` — the QR bit,
read into a local that nothing reads back. The identifier occurs twice in the
file and one of those is the licence header. Not checking it is conformant
besides: RFC 5452 §9.1 enumerates the six things a resolver MUST match a response
against — both addresses, the port, the ID, the name, the class and the type — and
QR is not among them. Finding 49 was about that list, which is why it was worth
looking up rather than assuming.






### The last eight, and what the block came to

A question is a name, a type and a class — RFC 1035 §4.1.2 — and `DNSQuestion`
had five gaps saying that all three of them are the question only if something
checks. Three were the `&&` chain in `Equals`, where turning any one link into an
`||` makes two questions that agree on one field agree altogether; RFC 5452 §9.1
is why that is not a tidiness point, since a resolver matches a response to its
query on the name, the class and the type. The other two were `CompareTo`'s
`if (c == 0)` pair, which is the rule that the name decides first and the class
last — visible only when the fields are made to disagree with one another, so each
case here has an earlier field saying one thing and a later field saying the
opposite.

`DNSPacket` had two, both in what a query means when it is not told: the short
`Query` overload sets RD (§4.1.1), and a query naming no type asks for ANY rather
than asking nothing. The mutant there turns `||` into `&&` and produces a message
with QDCOUNT 0, which is not a query.

`DNSPadding`'s one is real and cannot be observed, and the test that proves it was
already there. RFC 7830 §4's cap fires when the padded message would cross the
requestor's payload size; at the length where it lands exactly on it, both
readings answer the same, because `MaxLength - MeasuredLength` *is* `octets` when
the two are equal. `Block_Length_Arithmetic_A_Ceiling_On_The_Boundary_Does_Not_Bite`
pads 85 octets to 468 against a ceiling of 468 and still cannot tell them apart.

**The `core` block is closed.** 478 mutants, 203 survivors, 132 of them real gaps:
114 killed by a test, 17 shown unreachable or without observable effect, one line
replaced by a fix. Two blocks down — `records` and `core` — and five to go.

### The name with a rule about what a person may write in it

`DNSServiceInstanceName` is the fourth of Hermod's name types and the only one
whose rules are about a human-readable label. **No test in the suite had ever
named the type** — sixteen gaps, which is what a type with no tests looks like
from the outside.

RFC 6763 §4.1.1 is unusually easy to test against, because it states its one
restriction as an interval and an exception:

> MUST NOT contain ASCII control characters (byte values 0x00-0x1F and 0x7F)

An interval is the shape that gets implemented one character short at one end, so
both ends and the lone 0x7F are named separately — and the character just past the
interval, 0x20, is a space, which §4.1.1 explicitly allows. That gives the
boundary a side that must be refused and a side that must be accepted, which is
what makes it a boundary rather than a rule about control characters in general.

§4.1.1's other requirement is Net-Unicode: the name is stored as "canonical
precomposed UTF-8 ... (Unicode Normalization Form C)". `Cafe` + U+0301 and
`Café` are the same service, and a browser that composed its label differently
from the publisher would otherwise never find it.

Fifteen of the sixteen fell, and the sixteenth is a guard that is right to be
there and cannot fire: the refusal for a label `String.Normalize` cannot compose.
Every path into it runs `DNSServiceName`'s parser first, whose validator counts
the label's octets with a `UTF8Encoding` built to throw on invalid ones — and the
strings those two reject are the same strings, the unpaired surrogates. The
protected labels constructor would reach it, and nothing derives from this type.

The tests sit with the other name types rather than in the Multicast project,
because §4.1 is name syntax and not wire behaviour: the same instance name is used
over unicast DNS and over mDNS alike. RFC 6763's wire-facing halves — §6.1's
length limit and §6.4's key/value syntax — stay where the TXT record lives.

### The master file, and a test that passed twice without testing anything

`DNSZoneFile` reads RFC 1035 §5.1. Eleven gaps, ten tests, and the round is worth
recording for the middle of it rather than the end.

Seven fell: the two ways a `$ORIGIN` can be wrong, an owner name omitted on the
first line of a file where there is no previous record to take one from, a line
carrying nothing but a name, a line that is not a record at all, and both halves
of the escape state machine.

**The four that did not are one shape seen four times.** Every one of them is
`LogicalLines` asking whether something is empty at a point no empty thing can
reach: the initial value of `ownerOmitted`, which every path assigns before any
path reads; `line.Length > 0` before `line[0]`; `complete.Length > 0` before a
yield; and `joined.Length > 0` for the group a missing `)` left open. The
argument is the same each time and it is short: `depth` leaves zero only on a
line that has put a `(` into the builder, and the builder is cleared only where
`depth` is back to zero — so wherever these four are evaluated the builder is not
empty and the line is not blank. The guards are real; the cases they guard
against cannot arrive.

### The one that had to be written three times

`isEscaped = false` — the line that ends an escape after one character — survived
twice before a test caught it, and both failures are worth keeping.

**The first version asserted on the wrong property.** It fed the reader a line
whose comment should be stripped and checked that `TXT.Text` did not contain
"real comment". `Text` is the concatenation of the character-strings *without*
separators (RFC 7208 §3.3), so a swallowed comment arrives in it as
"andarealcomment" and the test found nothing and passed. It looked right. It
asserted nothing.

**The second version asserted on the right property and still could not see it.**
`Strings` does show the swallowed comment — except that the record parser strips
comments again downstream, so the record comes out identical either way. A
semicolon cannot distinguish this line at all, no matter what is asserted about
it.

**The third version uses the other character §5.1 gives a meaning to.**
Parentheses group data across a line boundary, and an escape that never ends
stops the reader counting them, so

```
esc  IN  TXT  has\;semi  (
     more
     )
```

is one record when the escape ends after one character and is cut off at the
first line when it does not. That one kills it.

Three versions, and the mutation run is what said so each time — which is the
whole point of running it against a test that has already gone green. A passing
test is evidence that the code does something; only a failing mutant is evidence
that the test would notice if it stopped.

### The helpers every message passes through

`DNSTools` is where Hermod meets octets somebody else wrote: reading a name and a
character-string off the wire, writing a name back, and finding where a message's
last record begins so a TSIG can be checked over everything in front of it. Its
boundaries are the ones that decide what a truncated or hostile message does, so
they are worth more than their count. Fifteen gaps, fifteen tests.

Eleven fell. **The four that did not are real mutations that no test can observe**,
and each for its own reason:

- `new UTF8Encoding(false, true)` — the first argument again, third file running.
  It decides what `GetPreamble()` returns and this encoding is only ever asked for
  `GetString`. The second argument is the one that matters, and a label whose
  octets are not UTF-8 now pins it.
- `Message.Length < 12` in `FindLastRecordOffset` (RFC 1035 §4.1.1's header). At
  exactly twelve both readings answer the same: with every count zero the walk
  ends where it started and returns -1, and with a count the message cannot keep,
  the walk runs off the end into an exception both callers catch. `TSIGSigner` and
  `SIG0Signer` check the length themselves before calling, so no caller can reach
  a difference.
- `while (total < buffer.Length)` — at equality the mutant asks for one more read
  of zero octets, which returns zero and breaks out on the next line. The same
  octets, one wasted call.
- `ConfigureAwait(false)` — a rule about library code, not about DNS, and a test
  host has no synchronization context for the two readings to differ about.

### A table that pointed at the wrong octet

The round's one real defect came out of asking a question that can be asked of any
serializer without knowing how it works: **a compression table is a promise about
where each name begins, so read the message at the offset and the name has to be
there.**

It was not. Writing `www.example.com.` through the text serializer left a table
saying `com` begins at octet 8, where the name actually begins at 12 — octet 8 is
the `m` of `example`, which as a length octet claims 109 more and runs off the end
of the message. An SOA left the same lie about its RNAME.

This is finding 9 exactly, in the copy of the code it was not fixed in: every
suffix measured from `CurrentOffset` rather than from where the label in front of
it ends, which is right for the first suffix and wrong for every one after. The
same line also identified a label by its text (`Array.IndexOf`), which finds the
wrong one in `example.com.example.com`.

**It is not a numbered finding, and the reason is worth writing down.** The entries
this table gets wrong are keyed without a trailing dot — `com`, because the text
comes from `EMail.ToString().Replace("@", ".")` — while `DomainName` and
`DNSServiceName` both look up keys that end in one, `com.`, case-folded. Two
disjoint key namespaces in one dictionary, so the wrong entries can only be read
by another text-path name whose whole text equals that suffix: a second SOA in the
same message whose RNAME is exactly `com`. Nothing produces that.

So the table was lying and the lie was unreachable, by an accident of spelling
rather than by design. It is fixed anyway, because "no caller does this today" is
an observation about callers and not about the code — which this plan already
learned once, from the parser that handled only A and OPT until a signed query
arrived (finding 16).

The same accident has a cost that is not a defect: an SOA's RNAME never compresses
against its own MNAME, because neither can find the other's keys. Unifying the
spelling would make messages smaller and is a deliberate change to what goes on
the wire, so it is reported here rather than made in passing.

### Two types for one name

`DomainName` and `DNSServiceName` were taken as one round rather than two,
because they are one subject written twice. The gaps stood almost line for line:
the null-receiver extension pair, the `offset <= 0x3FFF` compression guard, the
four ordering operators, the parse refusals. `IDomainName` carries that
extension pair a third time, so its two came along. Forty-one gaps, twenty-five
tests, and a test written for one type did keep killing mutants in the other —
which is what the shape of the list had predicted.

The split between the two types is real and worth stating, because it decides
what each of them is allowed to refuse. `DomainName` is host name syntax (RFC
1035 §2.3.1, RFC 1123 §2.1): letters, digits and hyphens, and nothing in a label
with a special meaning to escape. `DNSServiceName` is the presentation format of
§5.1, a strictly larger language, and it implements `\X` — `a\.b.example.` is two
labels there, `a.b` and `example`. That asymmetry had been sitting in PLAN.md as
an open question since the zone-file round; it is answered, and the answer is
that both types are right.

**What they disagreed about was length**, and that became
[finding 57](FINDINGS.md): `DomainName` counted characters where RFC 1035 §2.3.4
counts octets, in two guards neither of which saw the whole name, and accepted a
wildcard name of 256 wire octets. `DNSServiceName` had counted the wire form all
along. The line the sweep had measured no longer exists, so its verdict is
recorded as superseded — and the rule it carried was re-measured where the fix
put it and killed there.

Five mutations are real and no test can reach them, which is a different thing
from a gap:

- `new UTF8Encoding(false, true)` — the **first** argument decides only what
  `GetPreamble()` returns, and this encoding is only ever asked to count and
  write octets. The second argument is the one that matters, and an unpaired
  surrogate in a label now pins it.
- `Labels.Count == 0 || Labels.All(label => label.Length == 0)` in
  `DNSServiceName.Serialize` — the two readings differ only for a name that has
  labels and whose labels are all empty, and that name cannot be built: `All` is
  vacuously true over none, and every path into the type refuses an empty label.
  `DomainName` does reach that state, and its copy of the line was killed by the
  sweep.
- **Three in a row in `DomainName.TryParse`**: the label-length refusal, the
  hyphen check, and the hyphen check's own refusal. All three sit behind
  `DomainNameRegExpr`, whose label is at most 63 characters and must start and
  end with a letter or digit — so RFC 1035 §2.3.4's rule is enforced several
  lines earlier and these are the second guard on it. A condition that is never
  true reads the same as `&&` or `||`.

### A line that moved, and how it was followed

`DomainName.cs` had changed since the sweep measured it, so its line numbers had
moved — 380 of them. The verification did not assume an offset and did not trust
the old numbers: it read the file back out of git at the sweep's revision, lined
the two up with `difflib`, and mutated where the map said each line had gone,
with the anchor text checked on arrival as before. A line the fix replaced maps
to nothing and is reported as superseded rather than silently mutating whatever
now sits at that number.

### A rule the triage was missing

The first file taken up, `DNSNamePattern`, came back 20 killed of 22 — and one of
the two survivors was not a gap at all:

```csharp
public static Boolean IsNotNullOrEmpty([NotNullWhen(true)] this DNSNamePattern? X)
```

`[NotNullWhen(true)]` is compile-time and changing it changes nothing that runs.
The triage knew that and tested for it with `^\[`, which matches a line that
*begins* with an attribute — and this one begins with `public`. Five of the core
block's "real gaps" were that same extension method in five files. The rule now
searches the whole line, and the count moved from 137 to 132.

The records block is untouched by the change: none of its 240 had this shape,
which is why nobody noticed. And it was not found by reading the rule — it was
found by writing a test for the line and watching the mutation survive anyway.

### What the two numbers mean, and do not

The sweep is a **lower bound on the gap**. The operator catalogue is ten textual
rules — comparisons, boolean operators, boolean literals. It has no statement
deletion, no arithmetic, no LINQ or string operators. A richer tool would find
more.

It is also an **upper bound on the badness**. Some survivors are *equivalent
mutants*: `x > 0` → `x >= 0` where `x` is a length that cannot be negative is the
same program written twice. Those cannot be killed by any test, because there is
nothing to observe. Separating them needs a person, and that is the honest cost
of the technique rather than a defect in it.

The middle row is the one to keep in mind: **56 mutants were caught only because
a project other than the obvious one saw them.** A sweep judged by the record
tests alone would have reported 56 gaps that are not gaps. Scope the bench too
narrowly and the method manufactures work.

---

## The 240, by kind

The kinds matter more than the count, because they call for different tests.

### Rejection paths — 36

A parser told to *succeed* where it must refuse, and nothing notices. This is not
"a line is untested". It is **"this parser is never given input it has to
reject"** — which is where [findings 21 and 51](FINDINGS.md) lived.

The largest single group was APL: all nine of `APLItem.TryParse`'s refusals could
be turned into acceptance unnoticed. Those are now closed — fifteen malformed
items, both prefix limits from both sides, and the all-zero address. `TXT` and
`ADNSResourceRecord` still have theirs.

### Boundaries — 110

A comparison shifted by one. The test material exercises the middle of a range
and never its edge. Three of these are worth naming:

```
ADNSResourceRecord.cs:617   if (RData.Length > UInt16.MaxValue)          the RDLENGTH limit
ADNSResourceRecord.cs:832   if (unixTime < 0 || unixTime > UInt32.Max)   RRSIG times, both edges
TXT.cs:478                  if (byteCount > MaxCharacterStringLength)    the 255-octet limit
```

The first is the exact boundary that findings 2, 3 and 4 were about.

### Branches — 94

Conditions whose two sides are never both taken.

The full list, line by line, is `build/mutation/results/` — see below.

---

## Why not Stryker.NET

Stryker is the tool for this in .NET and it was tried first. Two obstacles, one
solved and one not:

1. **Solved.** Stryker's project analysis picked up the Visual Studio Build
   Tools' MSBuild, which has no `Microsoft.NET.Sdk`. Passing
   `--msbuild-path <dotnet sdk>/MSBuild.dll` fixes it.
2. **Not solved.** `NullReferenceException` inside Stryker's own mutation
   injector (`RoslynHelper.InjectMutation`), on a single file, at every mutation
   level, with the language version pinned — and in **4.16.0** as well as
   **5.0.0**, so not a regression in either but something about this codebase
   that the injector cannot place a mutation into.

The scripts here do the job instead, with a smaller catalogue. The one thing
they cannot do is Stryker's *mutation switching*: it compiles every mutant into
one assembly and selects at run time, while this rebuilds per mutant. Measured at
nine seconds a cycle, which is what makes 672 mutants a two-hour job rather than
a two-day one — and what makes re-running it a decision rather than a habit.

---

## How it runs

```
build/mutation/
  genmut.py       the catalogue: ten textual operators over a folder of C#
  sweep.py        pass 1 — mutate, build, run one test project, record
  sweep_wide.py   pass 2 — re-judge only the survivors against six more projects
  control.py      the self-test: does the bench notice a change it must notice
  report.py       triage and the gap list, read against the working tree
  classify.py     the same triage, pinned to the revision the sweep measured
  make_closed.py  the ledger of what each round closed
  standing.py     how much is closed, derived from files rather than typed
                  (takes a block name; defaults to 'records')

  sweep_folder.py       the same sweep, pointed at any of the six blocks
  sweep_wide_folder.py  and its second pass, over the rest of the bench
  classify_folder.py    and its triage, pinned to the block's own revision

  results/records-bounds2.tsv   the sixth round re-run: every boundary it
                                claims, mutated again and judged
  results/records-branch2.tsv   the seventh, over the branches and the last
                                rejections, in three passes
  results/        the raw verdicts, one row per mutant
```

`results/records-pass2.contaminated.tsv` is the run described below, before its
twenty spoiled verdicts were re-taken. It is kept rather than replaced, so the
correction can be checked instead of believed.

Each script finds the repository from its own location, so they run from
anywhere. Pass 1 first, then pass 2, then the report:

```bash
python build/mutation/sweep.py
```

```bash
python build/mutation/sweep_wide.py
```

```bash
python build/mutation/report.py
```

**Never run two of them at once, and never run one beside anything else that
builds.** They mutate files in place and restore them afterwards; a second
process building the same tree during that window gets a source file that belongs
to neither. That happened once here, and it cost twenty verdicts and an hour —
the run reported `BUILD-FAILED` for mutants that were perfectly viable, because
a *different* script had a broken file open at the time.

### The guards, and why each exists

Every one of these is here because its absence cost something, either in this
sweep or in an earlier hand-written one:

- **BASELINE.** Every project is run green before the first mutant. Without it,
  "no test failed" cannot be told from "no test ran". An earlier harness reported
  five mutants as surviving because its regex looked for per-test failure lines
  that `-v q` never prints.
- **The `/*MUTANT*/` marker, read back from disk.** Proof that the edit landed,
  not just that the write call returned.
- **The assembly timestamp.** `dotnet build` returning zero is not proof that the
  assembly the test host loads was rebuilt. Pass 2 omitted this check and had to
  have it supplied afterwards by `control.py`.
- **`control.py` itself.** A mutation that *must* be caught, sent through the
  same bench. It reports, per project, whether the assembly was refreshed and
  whether any test noticed. Run it after any change to the bench.

  Its own first attempt did not compile — `? 0 : 0` gives a conditional the
  natural type `int` where `UInt32` was needed — and the result was
  `build=False, refreshed=False, 0 failures` on all seven projects, which reads
  exactly like a broken bench. A control has to be verified before it is trusted,
  like anything else.

- **The project tree is not touched while a verification is running.** Not a
  guard but a rule the guards cannot cover: a sweep builds the whole solution for
  every mutant, and a test file added mid-run that does not compile produces a
  genuine `error CS` — which is exactly what the build guard reads as *the
  mutant's fault*. Every remaining line would be filed as not viable, and the one
  check able to notice would agree that it should be. This happened during the
  handler round; the file was pulled back out before the next build, and it did
  not in fact compile.

- **A verification leaves the last mutant in the build output.** Each mutant is
  restored in source, but the newest compiled assembly is the one built *with* it
  — nothing rebuilds afterwards. A suite run started straight after a sweep is
  therefore measuring a mutant, and the STALE-BINARY guard does not cover this: it
  watches the assembly within a run, not what is left lying about after one. It
  cost a diagnosis here. The last mutant of the pipeline round was the one turning
  a truncation bound from <= into <, a whole server suite was run against it, and
  the test that then failed was the very test written to catch that mutation —
  which reads exactly like a broken test. Rebuild before believing a suite run
  that follows a sweep.

### Four ways to mistake the machine for the code

The four guards above watch the code under test. The four below watch the
harness, and every one of them was added after it had already produced a wrong
number. They are one defect wearing four coats: **a statement the machine could
not make was recorded as a statement about the code.**

- **A mutant that never finishes is not a mutant that survives.**
  `subprocess.run(timeout=)` kills only the child, and `dotnet test` leaves a
  `testhost.exe` holding the inherited pipe, so the `communicate()` after the
  kill blocks for ever. One mutant in `DNSServer.cs` turned a thirty-minute
  bound into five and a half hours. The runner now kills the whole process tree,
  takes its bound from the measured baseline rather than a constant, and records
  `TIMED-OUT`, which is a verdict about neither the code nor the test.

- **A build that fails without a compiler error is not an unviable mutant.**
  `build().returncode != 0` was read as "the compiler rejected this mutation",
  and a locked output file reads identically. After one test run came back
  without a summary line, the server block's second pass wrote **179 consecutive
  lines** as "not a viable mutant" — every one of which had built in pass 1 and
  builds today. Both passes now look for `: error CS####` in the output and stop
  the run when there is none, because a sweep that cannot build produces
  something worse than nothing: plausible rows.

  What most likely locked it: MSBuild's reusable nodes. Fifteen of them were
  alive when the pass finished, started hours apart, each holding handles on
  assemblies it had written. Every build the sweep runs now passes
  `-nodeReuse:false`, which is not a speed setting.

- **A verdict the harness could not reach is not a non-entry.** The triage read
  only `SURVIVED-EVERYWHERE`, so every refusal and every timeout fell out of it
  silently, and a line the machine failed to measure looked exactly like a line
  the suite covers. Five such lines sat in four blocks reported closed. They are
  now `unmeasured-*` kinds, which count as neither gaps nor noise, and a block
  that carries one does not print "nothing is left".

- **A claim about one mutant is not a claim about its line.** `(file, line,
  operator)` never named a single mutant — a line can carry the same operator
  more than once — and neither the results file nor the ledger said so. Pass 2
  could not tell which occurrence had survived and refused; worse, ledger
  entries may be bare line numbers, so regenerating the closed files would have
  recorded three of the newly visible lines as *killed by rounds that never saw
  them*. The occurrence index is now written as a sixth column, and a line with
  no verdict is skipped before ledger matching.

  This is the one that matters most. The other three hide a question. This one
  manufactures an answer, in the file whose whole job is to record what was
  actually checked.

---

## Standing state

The results in `build/mutation/results/` are a **snapshot pinned to Hermod
`973fed31`**, not a live view. Line numbers move; a re-run is the only way to
refresh them.

Since the sweep, **182 of the 240 are closed** and **54 were declared equivalent
rather than chased**. **4 more are gone**: the lines their verdicts were measured
on were replaced by fixes, which is neither of the other two things.

That leaves **none**. Every mutant this sweep could not kill has since been
killed, shown unreachable, or had its line replaced.

Do not trust that sentence. Print it:

```bash
python build/mutation/standing.py
```

The count above was recomputed by hand four times and was wrong twice, both
times because the triage read a source tree that had moved under it while the
verdicts stayed pinned to the revision they were measured on. Two files now hold
what the source used to be asked for — `results/records-classified.tsv`, every
survivor classified against Hermod `973fed31`, and `results/records-closed.tsv`,
every gap since closed or declared equivalent, keyed the same way. `standing.py`
reads those two and nothing else, so it cannot drift no matter how far the code
moves.

Each closure was verified by a mutation taken from this output rather than
invented, and **every round so far has caught something the tests alone did
not**. Three rounds caught a test that closed its gap only halfway:

- APL's four-octet item was read back through the text reader, while the line at
  issue lives in the wire reader.
- TXT's quoted-string reader was started in the escaped state by a mutation that
  survived every test, because the escape flag is first read *inside* a string
  and every test began its first string with an ordinary character. Only an empty
  first string reaches it.
- ADNSResourceRecord's "this line has no RDATA" was asserted by looking for the
  word `RDATA` in the refusal — which the *other* refusal, "Could not parse
  RDATA", contains as well. The assertion read as a test and was not one. Two
  mutations died once it named `Missing RDATA` instead, and a third died once the
  message for an unknown type token had to name the token.

That last one is the pattern worth keeping: the mutation run did not only find
the gap. It found the part of the patch that was decoration.

The sixth round caught a different shape of the same thing: a test written to
kill NSEC3's base32 encoder came back SURVIVED, and it was right to. Whenever a
five-bit group is emitted it is still the k-th group of the stream, and the
trailing partial group is written with an expression that coincides with the
loop's at exactly the offset in question — the same string either way. The claim
in the test's own comment was wrong, and the run said so before the commit did.

Two rounds found a defect instead of a half-patch — `DNSSRVEndpoint`, whose
`Equals` and `CompareTo` answered unconditionally, and finding 54, where a field
read short was completed with zeros. Both were found the same way: by a survivor
no test could kill, because no input could reach it.

An equivalent mutant is not a gap. Chasing one produces a test that pins an
implementation detail, so each is recorded with the reason it cannot be observed
instead: a comparison against a length that is by construction equal, a branch
whose condition the caller has already excluded, a second operand that is never
different from the first.

The sixth round is where that mattered most: of the seventy-four boundaries it
took up, thirty-eight turned out to be unreachable rather than untested. Ten are
the same guard in ten record types — an RDATA length of 65535, checked for by a
type whose RDATA is domain names, which RFC 1035 §2.3.4 stops at 255 — and the
evidence for that one is a test in the suite rather than a sentence here.

The last pair to fall was the pair that looked least decidable, and it is worth
keeping as a warning about this kind of judgement. LOC writes `N` for a latitude
of exactly 2^31 and `E` for a longitude of exactly 2^31, and RFC 1876 §2 says
only that values *above* 2^31 are north and east. Both spellings read back as the
same octets, so the round trip cannot prefer one. They were left open here on the
grounds that the RFC declines to choose.

It does not. §5 of the same RFC publishes the conversion, and `loc_ntoa` reads:

```c
if (latval < 0) { northsouth = 'S'; latval = -latval; }
else              northsouth = 'N';
```

Strictly below zero is `S`; everything else, zero included, is `N`. The reference
point is northern and eastern because the RFC's own code says so, and every
implementation derived from that code agrees. The prose had been read and the
appendix had not — which is the same mistake as stopping at the first `grep`
result, one document larger.

The record block set out to find where this suite believed it was looking and was
not, and it has been walked end to end. Nothing is left in it to map — which is a
statement about one folder of six, and the map above says which.

Four defects came out of that walk, and none of them by a test failing.
[Findings 54, 55 and 56](FINDINGS.md), and `DNSSRVEndpoint`'s `Equals` and
`CompareTo` — recorded in [PLAN.md](PLAN.md) rather than numbered, because they
break a .NET contract rather than an RFC. Each was found the same way: a
survivor that no test could kill, and the reason was not a gap in the tests but
that no input could reach it.
