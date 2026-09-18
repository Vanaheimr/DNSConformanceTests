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
and run the suite. If no test fails, nothing in 1096 tests is watching that
line.

---

## Six blocks, two measured

The DNS code lives in six folders and the sweep was pointed at one of them. That
was not a judgement about the other five — it was where the work started, and
saying so is the difference between a measurement and a claim. The map, with the
cheapest test project that exercises each:

| block | folder | judged by | mutants | state |
|---|---|---|---:|---|
| `records` | `DNS/ResourceRecords` | ResourceRecords | 687 | measured, **closed** |
| `core` | `DNS` (the files directly in it) | ResourceRecords | 478 | measured, **closed** |
| `tsig` | `DNS/TSIG` | SecureTransports | 94 | measured, **1 open** |
| `dnssec` | `DNS/DNSSEC` | Dnssec | 227 | measured, **83 open** |
| `client` | `DNS/Client` | Client | 558 | not measured |
| `multicast` | `DNS/Multicast` | Multicast | 598 | not measured |
| `server` | `DNS/Server` | Server | 361 | not measured |

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

**The nineteenth is not one of them**, and separating it out is the point of doing
this by hand rather than by pattern:

```csharp
DomainName.ParseLenient(owner.Length == 0 ? "." : owner)
```

`DNSTools.ExtractName` returns `"."` for an empty name and never the empty string,
so the condition is dead and the expression always yields `owner`. But the mutation
inverts the condition rather than removing it, and the inverted version always
yields `"."` — which differs for any SIG whose owner name is not the root. That is
observable: `TryStripSIG0` hands the record back and `SIG.DomainName` is public.

It is left open rather than called equivalent, because it is not. Nothing in
Hermod reads that field, and RFC 2931 §3 puts the root there, so the only input
that tells the two apart is one the RFC does not describe. The cleaner answer is
that the ternary should go: it guards against something its own source cannot
produce, and `TSIGSigner` at the identical spot has no such guard. That is a change
to Hermod for tidiness rather than conformance, so it is recorded here and not
made.

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
