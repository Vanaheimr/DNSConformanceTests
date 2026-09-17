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
| `core` | `DNS` (the files directly in it) | ResourceRecords | 478 | measured, **8 open** |
| `client` | `DNS/Client` | Client | 558 | not measured |
| `multicast` | `DNS/Multicast` | Multicast | 551 | not measured |
| `server` | `DNS/Server` | Server | 361 | not measured |
| `dnssec` | `DNS/DNSSEC` | Dnssec | 202 | not measured |
| `tsig` | `DNS/TSIG` | SecureTransports | 70 | not measured |

One line of `sweep_folder.py` runs any of them. The `multicast` row is worth a
second look before anyone reads a number off it: its judge has **four tests** for
551 mutable places, so whatever that block eventually reports will be a statement
about the tests rather than about mDNS.

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

Where the 132 are — the first of them closed:

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
| `DNSQuestion.cs` 5, `DNSPacket.cs` 2, `DNSPadding.cs` 1 | 8 | |

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
