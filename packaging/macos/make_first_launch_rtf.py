"""Turn first_launch.txt into an RTF document with large type for the .dmg.

Lines starting with "# " become the title, "## " headings; **text** is bold.
RTF is used because TextEdit opens it on every Mac and it needs no extra tools
to generate; non-ASCII letters are written as RTF unicode escapes.
Usage: python make_first_launch_rtf.py <output.rtf>
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BACKSLASH = chr(92)


def rtf_text(text: str) -> str:
    out = []
    for ch in text:
        code = ord(ch)
        if ch in (BACKSLASH, "{", "}"):
            out.append(BACKSLASH + ch)
        elif code < 128:
            out.append(ch)
        elif code <= 0xFFFF:
            # RTF wants a signed 16-bit number, followed by a fallback character
            out.append(BACKSLASH + "u" + str(code if code < 32768 else code - 65536) + "?")
        # characters outside the BMP are not used in the text
    return "".join(out)


def inline(text: str) -> str:
    parts = re.split(r"(\*\*[^*]+\*\*)", text)
    return "".join(
        "{" + BACKSLASH + "b " + rtf_text(p[2:-2]) + "}" if p.startswith("**") else rtf_text(p)
        for p in parts)


def convert(source: str) -> str:
    b = BACKSLASH
    body = []
    for line in source.splitlines():
        if line.startswith("# "):
            body.append("{" + b + "fs56" + b + "b " + inline(line[2:]) + "}" + b + "par" + b + "par")
        elif line.startswith("## "):
            body.append("{" + b + "fs44" + b + "b " + inline(line[3:]) + "}" + b + "par")
        elif not line.strip():
            body.append(b + "par")
        else:
            body.append(inline(line) + b + "par")
    header = (
        "{" + b + "rtf1" + b + "ansi" + b + "ansicpg1252" + b + "deff0" + b + "uc1"
        "{" + b + "fonttbl{" + b + "f0" + b + "fswiss Helvetica;}}"
        + b + "paperw11900" + b + "paperh16840" + b + "margl1200" + b + "margr1200"
        + b + "margt1200" + b + "margb1200" + b + "f0" + b + "fs36" + b + "sa120\n"
    )
    return header + "\n".join(body) + "\n}\n"


def main(out_path):
    with open(os.path.join(HERE, "first_launch.txt"), encoding="utf-8") as f:
        rtf = convert(f.read())
    with open(out_path, "w", encoding="ascii") as f:
        f.write(rtf)


if __name__ == "__main__":
    main(sys.argv[1])
