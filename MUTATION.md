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

## The result

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
  standing.py     how much is closed, derived from files rather than typed
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

Since the sweep, **80 of the 240 are closed** and **7 were declared equivalent
rather than chased**, leaving **153 open** — across APL, TXT, the base class, the
SRV identifiers, and the shortest RDATA that IPSECKEY, DHCID and the Extended DNS
Error option can carry.

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
invented, and **every one of the three rounds caught a test that closed the gap
only halfway**:

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

That last one is the pattern worth keeping: three times out of three, the
mutation run did not only find the gap. It found the part of the patch that was
decoration.

An equivalent mutant is not a gap. Chasing one produces a test that pins an
implementation detail, so each is recorded with the reason it cannot be observed
instead: a comparison against a length that is by construction equal, a branch
whose condition the caller has already excluded, a second operand that is never
different from the first.

The remaining 196 are not a backlog and are not sorted by importance. They are a
map of where this suite believes it is looking and is not.
