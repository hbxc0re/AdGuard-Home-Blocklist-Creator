import subprocess
import sys

# Auto-install missing dependencies
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package, "--break-system-packages"])

try:
    import requests
except ImportError:
    print("'requests' module not found. Installing...")
    install("requests")
    import requests

from typing import List, Optional

# --- CONFIGURATION ---
OUTPUT_FILE = "adguard_blocklist.txt"

# Add || prefix and ^ suffix for AdGuard Home domain blocking (recommended)
ADD_PREFIX = True

# Curated blocklists — add or remove URLs as needed
BLOCKLIST_URLS = {
    "EasyList":                  "https://easylist.to/easylist/easylist.txt",
    "EasyPrivacy":               "https://easylist.to/easylist/easyprivacy.txt",
    "AdGuard Base":              "https://filters.adtidy.org/extension/ublock/filters/2.txt",
    "AdGuard Tracking":          "https://filters.adtidy.org/extension/ublock/filters/3.txt",
    "AdGuard Mobile Ads":        "https://filters.adtidy.org/extension/ublock/filters/11.txt",
    "Peter Lowe's Ad & Tracking":"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    "Fanboy Annoyances":         "https://easylist.to/easylist/fanboy-annoyance.txt",
    "Dan Pollock Hosts":         "https://someonewhocares.org/hosts/hosts",
    "Hagezi Ultimate":           "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt",
    "Data Brokers (ABP)":        "https://badblock.celenity.dev/abp/data-brokers.txt",
    "Data Brokers (Wildcards)":  "https://badblock.celenity.dev/wildcards-star/data-brokers.txt",
}

# --- FUNCTIONS ---

def download_filterlist(name: str, url: str) -> str:
    """Downloads the raw filterlist content from a URL."""
    try:
        print(f"📥 Downloading: {name} ...")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"⚠️  Failed to download {name} ({url}): {e}")
        return ""


def parse_domains(content: str, add_prefix: bool = True) -> List[str]:
    """
    Parses a blocklist and returns AdGuard Home-compatible rules.
    Handles ABP (||domain^), hosts file, wildcard, and plain domain formats.
    """
    rules = []
    for line in content.splitlines():
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#") or line.startswith("!") or line.startswith(";"):
            continue

        # Already a valid AdGuard/ABP rule — keep as-is
        if line.startswith("||") or line.startswith("@@") or line.startswith("##") or line.startswith("/"):
            rules.append(line)

        # Wildcard format: *.example.com → ||example.com^
        elif line.startswith("*."):
            domain = line[2:].strip()
            if domain and "." in domain:
                rules.append(f"||{domain}^" if add_prefix else domain)

        # Hosts file format: 0.0.0.0 or 127.0.0.1 example.com
        elif line.startswith(("0.0.0.0 ", "127.0.0.1 ")):
            parts = line.split()
            if len(parts) >= 2:
                domain = parts[1].strip()
                if domain not in ("localhost", "0.0.0.0", "127.0.0.1") and "." in domain:
                    rules.append(f"||{domain}^" if add_prefix else domain)

        # Plain domain (no spaces, no slashes, must contain a dot)
        elif "." in line and " " not in line and "/" not in line:
            rules.append(f"||{line}^" if add_prefix else line)

    return rules


def save_blocklist(blocklists: dict, output_file: str, add_prefix: bool = True):
    """Downloads all lists, deduplicates, and saves to a single AdGuard-compatible file."""
    all_rules = []
    seen = set()

    for name, url in blocklists.items():
        content = download_filterlist(name, url)
        if not content:
            continue

        rules = parse_domains(content, add_prefix)
        new_rules = [r for r in rules if r not in seen]
        seen.update(new_rules)
        all_rules.extend(new_rules)
        print(f"   ✅ {len(new_rules)} new rules from {name} (total so far: {len(all_rules)})")

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("# AdGuard Home Combined Blocklist\n")
        f.write(f"# Sources: {', '.join(blocklists.keys())}\n")
        f.write(f"# Total rules: {len(all_rules)}\n\n")
        f.write("\n".join(all_rules))
        f.write("\n")

    print(f"\n✅ Saved {len(all_rules)} deduplicated rules to: {output_file}")


def main():
    print("🚀 Starting AdGuard Home blocklist creator...\n")
    save_blocklist(BLOCKLIST_URLS, OUTPUT_FILE, ADD_PREFIX)


if __name__ == "__main__":
    main()