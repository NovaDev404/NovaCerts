#!/usr/bin/env python3
import plistlib
import sys
import zipfile
from pathlib import Path


def find_info_plist_path(names: list[str]) -> str:
    for name in names:
        if name.startswith("Payload/") and name.endswith(".app/Info.plist"):
            return name
    raise FileNotFoundError("Info.plist not found inside Payload/*.app")


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print(
            "usage: extract_ipa_metadata.py <ipa-path> [output-dir]",
            file=sys.stderr,
        )
        return 2

    ipa_path = Path(sys.argv[1])
    output_dir = Path(sys.argv[2]) if len(sys.argv) == 3 else ipa_path.parent

    if not ipa_path.is_file():
        print(f"IPA not found: {ipa_path}", file=sys.stderr)
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(ipa_path) as archive:
            info_plist_path = find_info_plist_path(archive.namelist())
            raw_plist = archive.read(info_plist_path)
    except (OSError, zipfile.BadZipFile, FileNotFoundError) as exc:
        print(f"Failed to read Info.plist from {ipa_path}: {exc}", file=sys.stderr)
        return 1

    try:
        plist_data = plistlib.loads(raw_plist)
    except (plistlib.InvalidFileException, ValueError) as exc:
        print(f"Failed to parse Info.plist from {ipa_path}: {exc}", file=sys.stderr)
        return 1

    stem = ipa_path.stem
    raw_output = output_dir / f"{stem}.Info.plist"
    xml_output = output_dir / f"{stem}.Info.plist.xml"

    raw_output.write_bytes(raw_plist)
    xml_output.write_bytes(plistlib.dumps(plist_data, fmt=plistlib.FMT_XML))

    version = str(
        plist_data.get("CFBundleShortVersionString")
        or plist_data.get("CFBundleVersion")
        or ""
    ).strip()
    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())