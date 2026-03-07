import sys
import zipfile


def has_bundle(names: list[str], target_name: str) -> bool:
    required_suffixes = (
        f"/signing-assets/{target_name}/cert.p12",
        f"/signing-assets/{target_name}/cert.mobileprovision",
        f"/signing-assets/{target_name}/cert.txt",
    )
    return all(any(name.endswith(suffix) for name in names) for suffix in required_suffixes)


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print(
            "usage: check_injected_signing_assets.py <ipa-path> [cert-name]",
            file=sys.stderr,
        )
        return 2

    ipa_path = sys.argv[1]
    cert_name = sys.argv[2] if len(sys.argv) == 3 else ""

    try:
        with zipfile.ZipFile(ipa_path) as archive:
            names = [
                name
                for name in archive.namelist()
                if name.startswith("Payload/") and ".app/signing-assets/" in name
            ]
    except (OSError, zipfile.BadZipFile):
        return 1

    if cert_name and has_bundle(names, cert_name):
        return 0

    candidates = set()
    for name in names:
        parts = name.split("/")
        try:
            index = parts.index("signing-assets")
        except ValueError:
            continue
        if index + 1 < len(parts):
            candidates.add(parts[index + 1])

    return 0 if any(has_bundle(names, candidate) for candidate in candidates) else 1


if __name__ == "__main__":
    raise SystemExit(main())