"""Publish a text report as annotations of the run (readable without admin rights).

Splits the file into chunks of about 3.5 KB at line breaks and prints them as
up to 10 notices and 10 warnings (GitHub's limit per step).
Usage: python emit_report.py <title> <file>
"""

import sys

LIMIT = 3500
title, path = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8", errors="replace") as f:
    lines = f.read().replace("\r", "").split("\n")

chunks, current = [], ""
for line in lines:
    line = line[:LIMIT]
    if len(current) + len(line) + 1 > LIMIT:
        chunks.append(current)
        current = ""
    current += line + "\n"
if current.strip():
    chunks.append(current)

total = len(chunks)
for i, chunk in enumerate(chunks[:20]):
    level = "notice" if i < 10 else "warning"
    body = chunk.replace("%", "%25").replace("\n", "%0A")
    print(f"::{level} title={title} {i + 1}/{total}::{body}")
if total > 20:
    print(f"::warning title={title}::{total - 20} more parts were cut")
