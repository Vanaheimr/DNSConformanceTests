# -*- coding: utf-8 -*-
"""Mechanical mutation generation for a folder of C# sources.

Stryker.NET crashes on this codebase (NullReferenceException inside its own
mutation injector, in 4.16 and 5.0 alike), so the operators are generated here
instead. The catalogue is deliberately small and textual: the four kinds that
can be applied to C# with a regex without understanding it, which is most of
the value and none of the ceremony.

This module only *counts and lists* mutants. Running them is the harness's job.
"""

import io
import os
import re
import sys

# (name, pattern, replacement) — applied to one occurrence at a time.
OPERATORS = [
    ("logical-and-to-or",      r"&&",            "||"),
    ("logical-or-to-and",      r"\|\|",          "&&"),
    ("equality-to-inequality", r"(?<![=!<>])== ", "!= "),
    ("inequality-to-equality", r"!= ",           "== "),
    ("less-to-less-or-equal",  r"(?<![<>=!])< ",  "<= "),
    ("greater-to-ge",          r"(?<![<>=!-])> ", ">= "),
    ("le-to-less",             r"<= ",           "< "),
    ("ge-to-greater",          r">= ",           "> "),
    ("true-to-false",          r"\btrue\b",      "false"),
    ("false-to-true",          r"\bfalse\b",     "true"),
]

COMMENT = re.compile(r"^\s*(//|/\*|\*)")


def is_code(line):
    """Cheap filter: skip comment lines and lines that are mostly a string."""
    if COMMENT.match(line):
        return False
    # A line whose only interesting content is inside quotes is not worth
    # mutating and is where a textual operator most often produces nonsense.
    without_strings = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)
    return without_strings.strip() not in ("", '""')


def strip_strings(line):
    """Blank out string contents so offsets stay aligned but matches inside
    literals are not found."""
    def blank(m):
        return '"' + " " * (len(m.group(0)) - 2) + '"'
    return re.sub(r'"(?:[^"\\]|\\.)*"', blank, line)


def mutants_for(path, rel):
    """Yield (file, line_no, operator, original_line, mutated_line)."""
    out = []
    lines = io.open(path, encoding="utf-8-sig").read().replace("\r\n", "\n").split("\n")

    for i, line in enumerate(lines, start=1):

        if not is_code(line):
            continue

        searchable = strip_strings(line)

        for name, pattern, repl in OPERATORS:
            for m in re.finditer(pattern, searchable):
                start, end = m.span()
                mutated = line[:start] + repl + line[end:]
                if mutated != line:
                    out.append((rel, i, name, line, mutated))

    return out


def main(root, prefix):

    everything = []

    for dirpath, _, filenames in os.walk(root):
        for filename in sorted(filenames):
            if not filename.endswith(".cs"):
                continue
            full = os.path.join(dirpath, filename)
            rel = os.path.relpath(full, prefix).replace("\\", "/")
            everything.extend(mutants_for(full, rel))

    by_file = {}
    by_op = {}
    for rel, line, op, _, _ in everything:
        by_file[rel] = by_file.get(rel, 0) + 1
        by_op[op] = by_op.get(op, 0) + 1

    print("%d mutants across %d files" % (len(everything), len(by_file)))
    print()
    print("by operator:")
    for op, n in sorted(by_op.items(), key=lambda kv: -kv[1]):
        print("  %-24s %4d" % (op, n))
    print()
    print("busiest files:")
    for rel, n in sorted(by_file.items(), key=lambda kv: -kv[1])[:12]:
        print("  %-52s %4d" % (rel, n))

    return everything


if __name__ == "__main__":
    _here  = os.path.dirname(os.path.abspath(__file__))
    _repo  = os.path.abspath(os.path.join(_here, "..", ".."))
    PREFIX = os.path.join(_repo, "libs", "Hermod", "Hermod")
    ROOT   = os.path.join(PREFIX, "DNS", "ResourceRecords")
    main(ROOT, PREFIX)
