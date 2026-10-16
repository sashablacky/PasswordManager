"""Print the interesting part of a failed log as a GitHub error annotation.

Job logs need admin rights to read, annotations do not. A pytest log is cut
to its FAILURES section and the short summary (a crash: its last lines).
Usage: python annotate_failure.py <title> < log
"""

import re
import sys

LIMIT = 3800  # GitHub keeps about 4 KB of an annotation message

title = sys.argv[1] if len(sys.argv) > 1 else "Failed"
log = sys.stdin.read().replace("\r", "")

parts = []
summary = re.search(r"^=+ short test summary info =+$.*", log, re.M | re.S)
failures = re.search(r"^=+ (FAILURES|ERRORS) =+$(.*?)(?=^=+ (short test summary|warnings summary)|\Z)",
                     log, re.M | re.S)
if summary:
    parts.append(summary.group(0).strip())
if failures:
    parts.append(failures.group(0).strip())
text = "\n\n".join(parts) if parts else "\n".join(log.splitlines()[-60:])
if len(text) > LIMIT:
    text = text[:LIMIT] + "\n[...]"

print(f"::error title={title}::" + text.replace("%", "%25").replace("\n", "%0A"))
