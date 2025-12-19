#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Updated certificate checker + README updater
Fix: correctly treat "🟢Good", "Good", "Valid", "Active" etc. as valid/signed
and avoid marking them as revoked just because they include emoji or different wording.
"""

import re
import requests
from bs4 import BeautifulSoup, NavigableString, Tag
from pathlib import Path
from datetime import datetime
import sys

BASE_URL = "https://check-p12.applep12.com/"

# -------------------------
# Helper / parsing utils
# -------------------------
def get_token(session):
    """Get the CSRF token from the check page."""
    r = session.get(BASE_URL, timeout=20)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    token_input = soup.find("input", {"name": "__RequestVerificationToken"})
    if not token_input:
        raise RuntimeError("Couldn't find __RequestVerificationToken on page")
    return token_input.get("value")

def submit_check(session, token, p12_path, p12_password, mp_path):
    """Submit files for checking."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Referer": BASE_URL,
        "Origin": "https://check-p12.applep12.com",
    }

    # Use context managers to ensure files are closed
    with open(p12_path, "rb") as p12_file, open(mp_path, "rb") as mp_file:
        files = [
            ("P12File", (p12_path.name, p12_file, "application/x-pkcs12")),
            ("P12PassWord", (None, p12_password)),
            ("MobileProvisionFile", (mp_path.name, mp_file, "application/octet-stream")),
            ("__RequestVerificationToken", (None, token)),
        ]

        r = session.post(BASE_URL, files=files, headers=headers, timeout=120)
        r.raise_for_status()
        return r.text

def split_kv(line):
    """Split on either ASCII colon ':' or full-width '：' and return (key, value)."""
    parts = re.split(r'[:：]\s*', line, maxsplit=1)
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip()
    return parts[0].strip(), ""

def clean_value(raw):
    """Clean and normalise values."""
    if raw is None:
        return ""
    v = re.sub(r'\s+', ' ', raw).strip()
    return v

def lines_from_alert_div(alert_div):
    """Extract text lines from the alert div in the HTML response."""
    lines = []
    cur = []
    for node in alert_div.children:
        if isinstance(node, NavigableString):
            txt = str(node).strip()
            if txt:
                cur.append(txt)
        elif isinstance(node, Tag):
            if node.name == "br":
                if cur:
                    joined = " ".join(cur).strip()
                    if joined:
                        lines.append(joined)
                cur = []
            else:
                txt = node.get_text(" ", strip=True)
                if txt:
                    cur.append(txt)
    if cur:
        joined = " ".join(cur).strip()
        if joined:
            lines.append(joined)
    return [re.sub(r'\s+', ' ', ln).strip() for ln in lines if ln.strip()]

def parse_html(html):
    """Parse the HTML response from the certificate checker and extract relevant fields."""
    soup = BeautifulSoup(html, "html.parser")
    alert_div = soup.find(lambda tag: tag.name == "div" and tag.get("class") and any("alert" in c for c in tag.get("class")))
    if not alert_div:
        return {"error": "No certificate info found in response"}
    lines = lines_from_alert_div(alert_div)

    data = {
        "certificate": {},
        "mobileprovision": {},
        "binding_certificate_1": {},
    }

    def find_index(prefixes, start=0):
        for i in range(start, len(lines)):
            for p in prefixes:
                if lines[i].startswith(p):
                    return i
        return None

    cert_idx = find_index(["CertName:", "CertName："])
    mp_idx = find_index(["MP Name:", "MP Name：", "MP Name"], start=0)
    binding_idx = find_index(["Binding Certificates:", "Binding Certificates：", "Binding Certificates"], start=(mp_idx or 0))

    # Parse mobileprovision block (dates come from here)
    if mp_idx is not None:
        end = binding_idx if binding_idx is not None else len(lines)
        for ln in lines[mp_idx:end]:
            k, v = split_kv(ln)
            v = clean_value(v)
            lk = k.lower()
            if lk.startswith("mp name"):
                data["mobileprovision"]["name"] = v
            elif lk.startswith("effective date"):
                data["mobileprovision"]["effective"] = v
            elif lk.startswith("expiration date"):
                data["mobileprovision"]["expiration"] = v

    # Parse certificate status (inside binding certificates block)
    if binding_idx is not None:
        cert1_idx = find_index(["Certificate 1:", "Certificate 1：", "Certificate 1"], start=binding_idx)
        if cert1_idx is not None:
            end = find_index(["Certificate 2:", "Certificate 2：", "Certificate 2"], start=cert1_idx+1) or len(lines)
            for ln in lines[cert1_idx+1:end]:
                k, v = split_kv(ln)
                v = clean_value(v)
                lk = k.lower()
                if lk.startswith("certificate status"):
                    data["binding_certificate_1"]["status"] = v

    # Fallback: sometimes the page prints certificate info straight without those markers
    # We'll try to search for "Certificate Status" anywhere
    if not data["binding_certificate_1"].get("status"):
        for ln in lines:
            if ln.lower().startswith("certificate status"):
                _, v = split_kv(ln)
                data["binding_certificate_1"]["status"] = clean_value(v)
                break

    return data

def convert_to_dd_mm_yy(date_str):
    """Convert date to DD/MM/YY HH:mm format if possible, otherwise return original."""
    if not date_str:
        return date_str
    date_str = re.sub(r'\(.*?\)', '', date_str).strip()
    date_formats = [
        "%m/%d/%y %H:%M",
        "%d/%m/%y %H:%M",
        "%Y/%m/%d %H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%d %b %Y %H:%M",
        "%b %d, %Y %H:%M",
        "%m/%d/%Y %H:%M",
        "%d/%m/%Y %H:%M",
        "%Y-%m-%d %H:%M",
        "%d %b %Y",
        "%b %d, %Y",
    ]
    for fmt in date_formats:
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.strftime("%d/%m/%y %H:%M")
        except ValueError:
            continue

    # Try regex extraction fallback
    date_patterns = [
        r'(\d{1,2})/(\d{1,2})/(\d{2,4})\s+(\d{1,2}):(\d{2})',
        r'(\d{1,2})/(\d{1,2})/(\d{2,4})',
        r'(\d{4})-(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})',
    ]
    for pattern in date_patterns:
        match = re.search(pattern, date_str)
        if match:
            groups = match.groups()
            try:
                if len(groups) >= 5:
                    # try to detect ordering; default assume MM/DD/YY unless impossible
                    if len(groups[2]) == 4 and int(groups[0]) > 12:
                        # probably DD/MM/YYYY
                        day = int(groups[0]); month = int(groups[1]); year = int(groups[2])
                    else:
                        month = int(groups[0]); day = int(groups[1]); year = int(groups[2])
                    hour = int(groups[3]) if len(groups) > 3 else 0
                    minute = int(groups[4]) if len(groups) > 4 else 0
                    dt = datetime(year if year > 31 else (2000 + year if year < 100 else year), month, day, hour, minute)
                else:
                    # no time
                    month = int(groups[0]); day = int(groups[1]); year = int(groups[2])
                    dt = datetime(year if year > 31 else (2000 + year if year < 100 else year), month, day)
                return dt.strftime("%d/%m/%y %H:%M")
            except Exception:
                pass
    return date_str

def normalize_status_str(raw_status):
    """
    Normalize the raw status string coming from applep12.
    Removes emoji and non-letter characters and returns a canonical status.
    Returns tuple: (canonical_status_of_api, mapped_status_for_readme)
    """
    if raw_status is None:
        return ("unknown", "Unknown")

    # Extract alphabetic chunks (this removes emoji and other symbols)
    words = re.findall(r'[A-Za-z]+', raw_status)
    if not words:
        cleaned = raw_status.strip().lower()
    else:
        cleaned = " ".join(words).lower()

    # Map common positive and negative words to canonical values
    positive = {"good", "valid", "active", "signed", "ok", "okay"}
    negative = {"revoked", "revocation", "invalid", "expired", "revokedcert", "revoke"}

    # If any positive token present -> valid
    for token in positive:
        if token in cleaned:
            return (cleaned, "Valid")
    for token in negative:
        if token in cleaned:
            # If explicitly expired, still consider "Revoked" as not valid for README mapping
            if "expired" in cleaned:
                return (cleaned, "Revoked")
            return (cleaned, "Revoked")

    # Fallback: if it contains 'good' as substring or startswith '🟢' etc.
    if "good" in cleaned:
        return (cleaned, "Valid")

    # Unknown fallback
    return (cleaned, "Unknown")

# -------------------------
# README parsing/updating
# -------------------------
def parse_readme_table(readme_content):
    """
    Parse the markdown table from README.md.
    Returns (certificates_list, lines) where certificates_list is list of dicts:
    { company, type, status, valid_from, valid_to, download, line_index }
    """
    lines = readme_content.splitlines()
    table_start = -1
    header_regex = re.compile(r'^\|\s*Company\s*\|\s*Type\s*\|\s*Status\s*\|\s*Valid From\s*\|\s*Valid To\s*\|\s*Download', re.IGNORECASE)

    for i, line in enumerate(lines):
        if header_regex.search(line):
            table_start = i
            break

    if table_start == -1:
        return [], lines

    certificates = []
    # table rows start after header and the separator line (so +2)
    for i in range(table_start + 2, len(lines)):
        line = lines[i].rstrip()
        if not line.startswith('|'):
            break
        # Split row into cells
        cells = [cell.strip() for cell in line.split('|')[1:-1]]  # ignore leading and trailing empty entries
        if len(cells) < 5:
            # skip malformed rows
            continue

        cert_info = {
            "company": cells[0],
            "type": cells[1] if len(cells) > 1 else "",
            "status": cells[2] if len(cells) > 2 else "",
            "valid_from": cells[3] if len(cells) > 3 else "",
            "valid_to": cells[4] if len(cells) > 4 else "",
            "download": cells[5] if len(cells) > 5 else "",
            "line_index": i
        }
        certificates.append(cert_info)

    return certificates, lines

def build_table_row(cert):
    """
    Build a markdown table row from cert dict:
    { company, type, status_display, valid_from, valid_to, download }
    """
    # Ensure fields exist
    company = cert.get("company", "").strip()
    ctype = cert.get("type", "").strip()
    status_display = cert.get("status_display", cert.get("status", "")).strip()
    valid_from = cert.get("valid_from", "").strip()
    valid_to = cert.get("valid_to", "").strip()
    download = cert.get("download", "").strip()

    return f"| {company} | {ctype} | {status_display} | {valid_from} | {valid_to} | {download} |"

def update_readme_table(certificates, lines):
    """
    Replace rows in lines (list of file lines) with updated certificate rows.
    """
    updated_lines = list(lines)  # copy
    for cert in certificates:
        idx = cert.get('line_index')
        if idx is None or idx < 0 or idx >= len(updated_lines):
            continue

        # Construct new row preserving download link if not provided
        if not cert.get('download'):
            # attempt to reuse existing download cell
            existing_cells = [c.strip() for c in updated_lines[idx].split('|')[1:-1]]
            download = existing_cells[5] if len(existing_cells) > 5 else ""
            cert['download'] = download

        # Determine status_display as emoji + text
        status_map = {
            "Valid": "✅ Signed",
            "Revoked": "❌ Revoked",
            "Unknown": "⚠️ Unknown"
        }
        cert['status_display'] = status_map.get(cert.get('status', ''), cert.get('status', '⚠️ Unknown'))

        # If the dates are 'Unknown', keep existing ones in README
        existing_cells = [c.strip() for c in updated_lines[idx].split('|')[1:-1]]
        if cert.get('valid_from') in (None, "", "Unknown"):
            cert['valid_from'] = existing_cells[3] if len(existing_cells) > 3 else ""
        if cert.get('valid_to') in (None, "", "Unknown"):
            cert['valid_to'] = existing_cells[4] if len(existing_cells) > 4 else ""

        updated_lines[idx] = build_table_row(cert)

    return updated_lines

# Optional: update the "Recommend Certificate" section if you want
def update_recommended_cert(lines, certificates, recommended_name="China Telecommunications Corporation V2"):
    """
    Update the Recommend Certificate line for a specific cert (if found).
    """
    for i, line in enumerate(lines):
        if 'Recommend Certificate' in line or 'Recommend Certificate' in line.replace(" ", ""):
            # Next non-empty line should hold the recommendation
            j = i + 1
            while j < len(lines) and lines[j].strip() == "":
                j += 1
            if j < len(lines):
                # find the current recommended cert; if we have its status, update it
                for cert in certificates:
                    if recommended_name in cert.get('company', ''):
                        status = cert.get('status', '').lower()
                        if status == 'valid':
                            lines[j] = f"**{recommended_name} - ✅ Signed**"
                        elif status == 'revoked':
                            lines[j] = f"**{recommended_name} - ❌ Revoked**"
                        else:
                            lines[j] = f"**{recommended_name} - ⚠️ Unknown**"
                        break
            break
    return lines

# -------------------------
# Certificate status check
# -------------------------
def get_certificate_status(cert_name):
    """Check the status of a single certificate directory and return a dict."""
    cert_dir = Path(cert_name)
    if not cert_dir.is_dir():
        print(f"❌ Skipping {cert_name}: not a directory")
        return None

    # Find .p12 and .mobileprovision
    p12_files = list(cert_dir.glob("*.p12"))
    mp_files = list(cert_dir.glob("*.mobileprovision"))

    if not p12_files or not mp_files:
        print(f"❌ Missing files for {cert_name}")
        return None

    p12_path = p12_files[0]
    mp_path = mp_files[0]

    password_file = cert_dir / "password.txt"
    if password_file.exists():
        password = password_file.read_text(encoding='utf-8').strip()
    else:
        password = "nezushub.vip"

    try:
        with requests.Session() as session:
            token = get_token(session)
            html = submit_check(session, token, p12_path, password, mp_path)
            data = parse_html(html)

            raw_status = data.get("binding_certificate_1", {}).get("status", "Unknown")
            raw_status_clean, mapped = normalize_status_str(raw_status)

            effective = data.get("mobileprovision", {}).get("effective", "Unknown")
            expiration = data.get("mobileprovision", {}).get("expiration", "Unknown")

            if effective and effective != "Unknown":
                effective = convert_to_dd_mm_yy(effective)
            if expiration and expiration != "Unknown":
                expiration = convert_to_dd_mm_yy(expiration)

            # Map mapped -> 'Valid'/'Revoked'/'Unknown' for internal use
            status_for_readme = mapped  # already "Valid"/"Revoked"/"Unknown"

            return {
                "status": status_for_readme,
                "raw_status": raw_status,
                "raw_status_clean": raw_status_clean,
                "effective": effective,
                "expiration": expiration,
                "company": cert_name,
                "download": "",  # placeholder - will be filled from README parsing if needed
            }
    except Exception as e:
        print(f"❌ Error checking {cert_name}: {str(e)}")
        return None

# -------------------------
# Main routine
# -------------------------
def main():
    readme_path = Path("README.md")
    if not readme_path.exists():
        print("❌ README.md not found in current directory.")
        return

    readme_content = readme_path.read_text(encoding='utf-8')
    certificates, lines = parse_readme_table(readme_content)
    if not certificates:
        print("🔎 No certificate rows found in README.md table.")
        return

    print(f"Found {len(certificates)} certificates in README.md")

    updated_certs = []
    for cert_info in certificates:
        company = cert_info['company']
        # The repository layout usually has directories matching the company names
        # But some README rows may contain extra characters; try to find matching directory
        possible_dirs = list(Path(".").glob(f"{company}*"))
        target_dir = None
        if len(possible_dirs) == 1:
            target_dir = possible_dirs[0]
        else:
            # try exact match
            exact = Path(company)
            if exact.exists() and exact.is_dir():
                target_dir = exact
            else:
                # fallback: try replacing encoded spaces
                alt = Path(company.replace("%20", " ").strip())
                if alt.exists() and alt.is_dir():
                    target_dir = alt

        if target_dir is None:
            print(f"⚠️  Could not find directory for '{company}', skipping check (will keep existing README row).")
            # preserve existing row info
            cert_info['status'] = cert_info.get('status', '')
            updated_certs.append(cert_info)
            continue

        print(f"Checking {company}...")
        result = get_certificate_status(str(target_dir))
        if result:
            cert_info['status'] = result['status']
            cert_info['valid_from'] = result['effective'] or cert_info.get('valid_from', '')
            cert_info['valid_to'] = result['expiration'] or cert_info.get('valid_to', '')
            cert_info['download'] = cert_info.get('download', '')
            updated_certs.append(cert_info)

            status_emoji = '✅' if result['status'] == 'Valid' else ('❌' if result['status'] == 'Revoked' else '⚠️')
            print(f"  {status_emoji} Status: {result['status']} (raw: {result.get('raw_status')})")
            print(f"  📅 Valid From: {cert_info['valid_from']}")
            print(f"  📅 Valid To:   {cert_info['valid_to']}")
        else:
            print(f"  ⚠️  Could not check status for {company}")
            updated_certs.append(cert_info)

    # Now update lines and write back README.md
    updated_lines = update_readme_table(updated_certs, lines)
    updated_lines = update_recommended_cert(updated_lines, updated_certs)

    readme_path.write_text("\n".join(updated_lines), encoding='utf-8')
    print("\n✅ README.md updated successfully!")

if __name__ == "__main__":
    main()
