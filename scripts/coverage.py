#!/usr/bin/env python3
"""Parse grcov LCOV output from stdin and show missed lines with source context.

Usage:
    grcov target/coverage --binary-path target/debug/ -s . --keep-only 'src/foo.rs' -t lcov | python3 scripts/coverage.py
"""
import sys
from pathlib import Path

current_file = None
missed = {}
total = {}
covered = {}

for line in sys.stdin:
    line = line.strip()
    if line.startswith("SF:"):
        current_file = line[3:]
        missed.setdefault(current_file, [])
        total.setdefault(current_file, 0)
        covered.setdefault(current_file, 0)
    elif line.startswith("DA:") and current_file:
        parts = line[3:].split(",")
        lineno, count = int(parts[0]), int(parts[1])
        total[current_file] += 1
        if count > 0:
            covered[current_file] += 1
        else:
            missed[current_file].append(lineno)

for filepath in sorted(missed):
    t = total[filepath]
    c = covered[filepath]
    pct = c * 100 // t if t else 0
    print(f"\n{filepath}: {c}/{t} ({pct}%)")
    if not missed[filepath]:
        continue
    try:
        source_lines = Path(filepath).read_text().splitlines()
    except FileNotFoundError:
        print(f"  missed lines: {missed[filepath]}")
        continue
    for lineno in missed[filepath]:
        if 1 <= lineno <= len(source_lines):
            src = source_lines[lineno - 1].rstrip()
            print(f"  {lineno:4d}: {src}")
        else:
            print(f"  {lineno:4d}: <out of range>")
