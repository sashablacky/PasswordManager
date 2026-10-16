"""Check a built macOS .app before it is shipped.

- Info.plist: CFBundleExecutable exists and is executable, the bundle id is a
  valid reverse-DNS name (only A-Z a-z 0-9 . -), LSMinimumSystemVersion is set.
- Every Mach-O file inside: its minimum macOS (LC_BUILD_VERSION or
  LC_VERSION_MIN_MACOSX) must not be newer than LSMinimumSystemVersion,
  otherwise the app silently fails to load that library on older systems.

Prints a summary of minimum versions; exits 1 on any problem.
Usage: python check_macos_bundle.py "dist/Password Manager.app"
"""

import collections
import os
import plistlib
import re
import struct
import sys

LC_VERSION_MIN_MACOSX = 0x24
LC_BUILD_VERSION = 0x32
CPU_NAMES = {0x1000007: "x86_64", 0x100000C: "arm64"}


def _version(packed):
    return (packed >> 16, (packed >> 8) & 0xFF)


def _thin(data, offset):
    magic = struct.unpack_from("<I", data, offset)[0]
    if magic not in (0xFEEDFACE, 0xFEEDFACF):
        return None
    cputype, _, _, ncmds, _, _ = struct.unpack_from("<iiIIII", data, offset + 4)
    pos = offset + (32 if magic == 0xFEEDFACF else 28)
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, pos)
        if cmd == LC_BUILD_VERSION:
            return cputype, _version(struct.unpack_from("<I", data, pos + 12)[0])
        if cmd == LC_VERSION_MIN_MACOSX:
            return cputype, _version(struct.unpack_from("<I", data, pos + 8)[0])
        pos += size
    return cputype, None


def macho_minimums(path):
    """[(cpu, (major, minor) or None)] for each architecture of a Mach-O file"""
    with open(path, "rb") as f:
        head = f.read(8)
        if len(head) < 8:
            return []
        if struct.unpack_from(">I", head)[0] not in (0xCAFEBABE,) and \
                struct.unpack_from("<I", head)[0] not in (0xFEEDFACE, 0xFEEDFACF):
            return []
        data = head + f.read()
    if struct.unpack_from(">I", data)[0] == 0xCAFEBABE:  # universal binary
        count = struct.unpack_from(">I", data, 4)[0]
        if count > 10:  # Java class files share the magic number
            return []
        offsets = [struct.unpack_from(">iiIII", data, 8 + 20 * i)[2] for i in range(count)]
        return [r for r in (_thin(data, o) for o in offsets) if r]
    result = _thin(data, 0)
    return [result] if result else []


def main(app):
    problems = []
    contents = os.path.join(app, "Contents")
    with open(os.path.join(contents, "Info.plist"), "rb") as f:
        info = plistlib.load(f)

    executable = os.path.join(contents, "MacOS", info.get("CFBundleExecutable", ""))
    if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
        problems.append(f"CFBundleExecutable {info.get('CFBundleExecutable')!r} is not an executable file")
    bundle_id = info.get("CFBundleIdentifier", "")
    if not re.fullmatch(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+", bundle_id):
        problems.append(f"CFBundleIdentifier {bundle_id!r} is not a valid reverse-DNS name")
    minimum_text = info.get("LSMinimumSystemVersion")
    if not minimum_text:
        problems.append("LSMinimumSystemVersion is missing")
        minimum_text = "99"
    minimum = tuple(int(x) for x in (minimum_text.split(".") + ["0"])[:2])
    print(f"Info.plist: {bundle_id} {info.get('CFBundleShortVersionString')}, "
          f"executable {info.get('CFBundleExecutable')!r}, LSMinimumSystemVersion {minimum_text}")

    summary = collections.defaultdict(set)
    for root, _, files in os.walk(app):
        for name in files:
            path = os.path.join(root, name)
            if os.path.islink(path):
                continue
            try:
                found = macho_minimums(path)
            except (OSError, struct.error):
                continue
            rel = os.path.relpath(path, contents)
            for cpu, version in found:
                label = "unknown" if version is None else "%d.%d" % version
                top = rel.split(os.sep)[1] if rel.startswith("Frameworks" + os.sep) else rel
                summary[(CPU_NAMES.get(cpu, hex(cpu)), label)].add(top)
                if version is not None and version > minimum:
                    problems.append(f"{rel} ({CPU_NAMES.get(cpu, cpu)}) needs macOS {label}")

    print("Minimum macOS of the Mach-O files:")
    for (cpu, label), tops in sorted(summary.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        print(f"  {cpu} {label}: {len(tops)} — {', '.join(sorted(tops)[:8])}{' …' if len(tops) > 8 else ''}")

    if problems:
        print("\nPROBLEMS:")
        for p in problems:
            print("  " + p)
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
