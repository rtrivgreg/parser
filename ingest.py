"""
Programmatically resolve MCSB information for a set of Azure Policy
policyDefinitionId GUIDs that live inside the NIST SP 800-53 Rev 5
regulatory compliance initiative.

Step 1: Download the NIST SP 800-53 R5 initiative JSON and the MCSB
        (AzureSecurityCenter) initiative JSON from the Azure/azure-policy repo.
Step 2: Resolve each input GUID -> policy name + NIST 800-53 R5 control group(s).
Step 3: Check if that same policyDefinitionId is ALSO assigned in the MCSB
        initiative (direct technical overlap - works for automated/Azure-Policy
        backed controls).
Step 4: If there's no direct overlap (true for "CMA_" manual attestation
        policies, which cover paperwork/process controls like AC-1 "Policy and
        Procedures" that Azure Policy can't technically enforce), fall back to
        Microsoft's published NIST-r5-to-MCSB-v2 crosswalk, which today only
        exists as prose "Control mapping" bullets on each MCSB v2 domain page
        (there is no downloadable CSV/JSON for it yet) - so this step scrapes
        those pages and builds a NIST-control -> MCSB-control reverse index.

Usage:
    python nist_to_mcsb.py <policyDefinitionId-guid> [<guid> ...]
"""
import csv
import json
import os
import re
import sys
import time
import urllib.request

from bs4 import BeautifulSoup

NIST_R5_URL = (
    "https://raw.githubusercontent.com/Azure/azure-policy/master/"
    "built-in-policies/policySetDefinitions/Regulatory%20Compliance/"
    "NIST_SP_800-53_R5.json"
)
MCSB_URL = (
    "https://raw.githubusercontent.com/Azure/azure-policy/master/"
    "built-in-policies/policySetDefinitions/Security%20Center/"
    "AzureSecurityCenter.json"
)

# MCSB v2 (preview) domain pages - each contains "Control mapping" bullets
# with lines like "NIST SP 800-53 Rev.5: AC-2, AC-3, ..." per control.
MCSB_V2_DOMAIN_PAGES = [
    "network-security", "identity-management", "privileged-access",
    "data-protection", "asset-management", "logging-threat-detection",
    "incident-response", "posture-vulnerability-management",
    "endpoint-security", "backup-recovery", "devops-security",
    "artificial-intelligence-security",
]
MCSB_V2_BASE = "https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-v2-{}"


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "python"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def load_policy_defs(url):
    data = fetch_json(url)
    return data["properties"]["policyDefinitions"]


def resolve_nist(guid, nist_defs):
    for d in nist_defs:
        if d["policyDefinitionId"].lower().endswith(guid.lower()):
            return d.get("groupNames", [])
    return None


def in_mcsb(guid, mcsb_defs):
    for d in mcsb_defs:
        if d["policyDefinitionId"].lower().endswith(guid.lower()):
            return d.get("groupNames", [])
    return None


def fetch_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as r:
        return r.read().decode("utf-8", errors="ignore")


# Matches an MCSB control heading, e.g. "IM-1: Centralize identity ..."
_CONTROL_HEADING_RE = re.compile(r"^([A-Z]{2,3}-\d+):\s*(.+)$")

# Microsoft's own pages are inconsistent about spacing/punctuation in this
# label - confirmed variants in the wild: "NIST SP 800-53 Rev.5" (most
# domains) vs "NIST SP 800-53 Rev. 5" (Artificial Intelligence Security page).
# Normalize whitespace so both collapse to the same framework-label key.
_NIST_R5_LABEL_RE = re.compile(r"^NIST SP 800-53 Rev\.?\s*5$", re.I)
NIST_R5_LABEL = "NIST SP 800-53 Rev.5"


def _normalize_framework_label(label):
    collapsed = re.sub(r"\s+", " ", label).strip()
    if _NIST_R5_LABEL_RE.match(collapsed):
        return NIST_R5_LABEL
    return collapsed


def parse_mcsb_v2_page(html):
    """
    Parse a single MCSB v2 domain page's real DOM structure:

        <h2 id="im-1">IM-1: Centralize identity ...</h2>
          ... (Azure Policy links, Security principle, Risk to mitigate, ...)
          <h3 id="control-mapping">Control mapping</h3>
          <ul>
            <li><strong>NIST SP 800-53 Rev.5:</strong> AC-2, AC-3, AC-4, ...</li>
            <li><strong>PCI-DSS v4:</strong> ...</li>
            ...
          </ul>
        <h2 id="im-2">IM-2: ...</h2>
        ...

    Each control's <h2> and its "Control mapping" <ul> were confirmed by
    inspecting the live page source - this is far more reliable than regex
    over raw text, since it anchors on real tag boundaries instead of
    guessing where a control section starts/ends.

    Returns: { "IM-1": {"name": "...", "frameworks": {"NIST SP 800-53 Rev.5": [...], ...}}, ... }
    """
    soup = BeautifulSoup(html, "html.parser")
    results = {}
    for h2 in soup.find_all("h2"):
        m = _CONTROL_HEADING_RE.match(h2.get_text(strip=True))
        if not m:
            continue
        control_id, control_name = m.group(1), m.group(2)

        # Walk forward siblings until the next <h2> (= next control, or end
        # of the control-by-control section of the page). Collect EVERY
        # "Control mapping" <h3> that's immediately followed by a <ul> - do
        # not stop at the first "Control mapping" heading found, because some
        # pages (e.g. Backup and Recovery) render a duplicate, empty
        # "Control mapping" <h3> right before the real one that actually has
        # the <ul> beneath it (confirmed in the live page source: ids
        # "control-mapping"/"control-mapping-1" pairs, only the second has
        # content). Merging every valid hit also survives controls whose
        # mapping is split across more than one list.
        mapping_uls = []
        node = h2.find_next_sibling()
        while node is not None and node.name != "h2":
            if node.name == "h3" and "control mapping" in node.get_text(strip=True).lower():
                nxt = node.find_next_sibling()
                if nxt is not None and nxt.name == "ul":
                    mapping_uls.append(nxt)
            node = node.find_next_sibling()
        if not mapping_uls:
            continue

        frameworks = {}
        for mapping_ul in mapping_uls:
            for li in mapping_ul.find_all("li"):
                strong = li.find("strong")
                if strong is None:
                    continue
                label = _normalize_framework_label(strong.get_text(strip=True).rstrip(":"))
                full_text = li.get_text(strip=True)
                ids_part = full_text[len(strong.get_text(strip=True)):].lstrip(":").strip()
                ids = [x.strip() for x in ids_part.split(",") if x.strip()]
                frameworks.setdefault(label, [])
                for i in ids:
                    if i not in frameworks[label]:
                        frameworks[label].append(i)

        results[control_id] = {"name": control_name, "frameworks": frameworks}
    return results


def build_nist_r5_to_mcsb_v2_index(sleep_seconds=0.5, verbose=False, log=print):
    """
    Fetch every MCSB v2 domain page, parse it with parse_mcsb_v2_page(), and
    build the reverse index:
        { "AC-2": {"IM-1", "IM-2", "PA-1", ...}, "AC-1": set(), ... }

    This is the fallback used when a policy GUID has no automated Azure
    Policy presence in MCSB (e.g. manual/CMA_ attestation policies like the
    AC-1 "policy and procedures" family) - Microsoft doesn't publish a
    downloadable CSV/JSON for this crosswalk, only these per-domain articles,
    so this is the closest thing to a programmatic API for it today.

    NIST control enhancement suffixes are normalized to their base control
    for the index keys (e.g. "AC-6(1)" -> "AC-6"), since the Rev 5 initiative
    JSON groupNames use base-plus-enhancement IDs while callers usually want
    to match on the base control. Call parse_mcsb_v2_page() directly on a
    single page's HTML if you need the raw, un-normalized enhancement IDs.
    """
    index = {}
    for slug in MCSB_V2_DOMAIN_PAGES:
        url = MCSB_V2_BASE.format(slug)
        try:
            html = fetch_text(url)
        except Exception as e:
            if verbose:
                log(f"  [warn] failed to fetch {url}: {e}")
            continue
        page_controls = parse_mcsb_v2_page(html)
        if verbose:
            log(f"  parsed {slug}: {len(page_controls)} controls")
        for control_id, info in page_controls.items():
            nist_ids = info["frameworks"].get(NIST_R5_LABEL, [])
            for raw_id in nist_ids:
                base_id = raw_id.split("(")[0].strip()
                index.setdefault(base_id, set()).add(control_id)
        time.sleep(sleep_seconds)  # be polite to learn.microsoft.com
    return index


def compute_results(guids, log=print):
    """
    Resolve every guid to its NIST 800-53 R5 control(s), and to MCSB control(s)
    either via direct policyDefinitionId overlap or the scraped crosswalk
    fallback. `log` is called with progress messages (pass a no-op lambda to
    silence them, e.g. for --csv output going to stdout).

    Returns a flat list of row dicts, one row per (guid, nist_control) pair -
    this is the single source of truth both the text report and --csv render
    from, so the two output modes can never drift out of sync:
        {
            "policy_guid": str,
            "nist_control": str,       # "" when the guid wasn't found at all
            "match_type": str,         # not_found | direct_mcsb_policy |
                                        # crosswalk_fallback | no_mcsb_mapping
            "mcsb_controls": [str, ...],
        }
    """
    log("Downloading NIST SP 800-53 R5 initiative ...")
    nist_defs = load_policy_defs(NIST_R5_URL)
    log("Downloading MCSB (AzureSecurityCenter) initiative ...")
    mcsb_defs = load_policy_defs(MCSB_URL)

    # Resolve every guid's NIST control(s) first, so we only build the (slower,
    # ~12-page) web-scraped fallback index if at least one guid actually needs it.
    resolved = []
    needs_fallback = False
    for guid in guids:
        groups = resolve_nist(guid, nist_defs)
        mcsb_groups = in_mcsb(guid, mcsb_defs) if groups is not None else None
        if groups is not None and not mcsb_groups:
            needs_fallback = True
        resolved.append((guid, groups, mcsb_groups))

    fallback_index = {}
    if needs_fallback:
        log("Building NIST-r5 -> MCSB v2 crosswalk from learn.microsoft.com "
            "(no direct policy overlap found for at least one GUID) ...")
        fallback_index = build_nist_r5_to_mcsb_v2_index(verbose=True, log=log)

    rows = []
    for guid, groups, mcsb_groups in resolved:
        if groups is None:
            rows.append({"policy_guid": guid, "nist_control": "",
                         "match_type": "not_found", "mcsb_controls": []})
            continue
        nist_controls = sorted({g.replace("NIST_SP_800-53_R5_", "") for g in groups})

        if mcsb_groups:
            for nist_id in nist_controls:
                rows.append({"policy_guid": guid, "nist_control": nist_id,
                             "match_type": "direct_mcsb_policy",
                             "mcsb_controls": list(mcsb_groups)})
            continue

        for nist_id in nist_controls:
            base_id = nist_id.split("(")[0].strip()
            mcsb_controls = fallback_index.get(base_id)
            if mcsb_controls:
                rows.append({"policy_guid": guid, "nist_control": nist_id,
                             "match_type": "crosswalk_fallback",
                             "mcsb_controls": sorted(mcsb_controls)})
            else:
                rows.append({"policy_guid": guid, "nist_control": nist_id,
                             "match_type": "no_mcsb_mapping", "mcsb_controls": []})
    return rows


_MATCH_TYPE_TEXT = {
    "not_found": "Not found in the NIST SP 800-53 R5 initiative.",
    "direct_mcsb_policy": "Direct MCSB policy overlap",
    "crosswalk_fallback": "Crosswalk fallback",
    "no_mcsb_mapping": "Crosswalk fallback",
}


def print_report(rows):
    """Human-readable console report (the original default output format)."""
    by_guid = {}
    for row in rows:
        by_guid.setdefault(row["policy_guid"], []).append(row)

    for guid, guid_rows in by_guid.items():
        print(f"\n=== {guid} ===")
        if guid_rows[0]["match_type"] == "not_found":
            print(f"  {_MATCH_TYPE_TEXT['not_found']}")
            continue

        nist_controls = [r["nist_control"] for r in guid_rows]
        print(f"  NIST 800-53 R5 control(s): {', '.join(nist_controls)}")

        if guid_rows[0]["match_type"] == "direct_mcsb_policy":
            print(f"  Direct MCSB policy overlap - MCSB groups: {guid_rows[0]['mcsb_controls']}")
            continue

        print("  No direct Azure-Policy overlap with MCSB (likely a manual/"
              "CMA_ attestation policy).")
        for r in guid_rows:
            if r["match_type"] == "crosswalk_fallback":
                print(f"  Crosswalk fallback - {r['nist_control']} -> MCSB v2: "
                      f"{', '.join(r['mcsb_controls'])}")
            else:
                print(f"  Crosswalk fallback - {r['nist_control']} -> "
                      f"no MCSB v2 control maps to it.")


def write_csv(rows, dest):
    """
    Write the same rows as a flat CSV: one line per (guid, nist_control) pair.
    mcsb_controls is semicolon-joined (commas are the CSV delimiter, so a
    comma-joined list inside a field would need quoting - semicolons keep it
    readable without relying on the reader to unquote correctly).
    `dest` is a file path, or "-" for stdout.
    """
    fieldnames = ["policy_guid", "nist_control", "match_type", "mcsb_controls"]
    out = sys.stdout if dest == "-" else open(dest, "w", newline="", encoding="utf-8")
    try:
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                "policy_guid": row["policy_guid"],
                "nist_control": row["nist_control"],
                "match_type": row["match_type"],
                "mcsb_controls": ";".join(row["mcsb_controls"]),
            })
    finally:
        if out is not sys.stdout:
            out.close()


def main(guids, csv_dest=None):
    # When writing CSV to stdout, keep progress/log noise out of that stream
    # (it would corrupt the CSV) by sending it to stderr instead.
    log = (lambda *a: print(*a, file=sys.stderr)) if csv_dest else print
    rows = compute_results(guids, log=log)
    if csv_dest:
        write_csv(rows, csv_dest)
    else:
        print_report(rows)


_GUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def load_guids_from_file(path):
    """
    Read policy GUIDs out of a text file - one per line, or comma/whitespace
    separated, blank lines and '#' comments ignored. Also tolerates GUIDs
    embedded in longer strings (e.g. full policyDefinitionId resource paths
    like ".../providers/Microsoft.Authorization/policyDefinitions/<guid>")
    by pulling out anything that matches the GUID pattern.
    """
    text = sys.stdin.read() if path == "-" else open(path, "r", encoding="utf-8").read()
    guids = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()  # drop comments
        if not line:
            continue
        guids.extend(_GUID_RE.findall(line))
    return guids


def parse_args(argv):
    """
    Supported invocations:
        python nist_to_mcsb.py <guid> [<guid> ...]         # GUIDs as args
        python nist_to_mcsb.py --file guids.txt            # GUIDs from a file
        python nist_to_mcsb.py -f guids.txt
        python nist_to_mcsb.py guids.txt                   # bare path also works
        cat guids.txt | python nist_to_mcsb.py --file -    # or from stdin

        # add --csv (writes to stdout) or --csv=<path> (writes to a file) to
        # any of the above to get CSV output instead of the text report:
        python nist_to_mcsb.py --file guids.txt --csv
        python nist_to_mcsb.py --file guids.txt --csv=results.csv

    Returns (guids_or_None, csv_dest_or_None). csv_dest is "-" for stdout,
    a file path, or None to use the default human-readable text report.
    """
    guids = []
    csv_dest = None
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--csv":
            csv_dest = "-"
            i += 1
        elif arg.startswith("--csv="):
            csv_dest = arg.split("=", 1)[1]
            i += 1
        elif arg in ("--file", "-f"):
            if i + 1 >= len(argv):
                sys.exit("Usage: python nist_to_mcsb.py --file <path-to-guids.txt>")
            guids.extend(load_guids_from_file(argv[i + 1]))
            i += 2
        else:
            guids.append(arg)
            i += 1

    if len(guids) == 1 and (guids[0] == "-" or os.path.isfile(guids[0])):
        guids = load_guids_from_file(guids[0])

    return (guids or None), csv_dest


if __name__ == "__main__":
    guids, csv_dest = parse_args(sys.argv[1:])
    guids = guids or [
        "59f7feff-02aa-6539-2cf7-bea75b762140",
        "b1666a13-8f67-9c47-155e-69e027ff6823",
        "1a2a03a4-9992-5788-5953-d8f6615306de",
        "03d550b4-34ee-03f4-515f-f2e2faf7a413",
        "623b5f0a-8cbd-03a6-4892-201d27302f0c",
        "4c6df5ff-4ef2-4f17-a516-0da9189c603b",
        "a08b18c7-9e0a-89f1-3696-d80902196719",
    ]
    if not guids:
        sys.exit("No GUIDs found in input.")
    main(guids, csv_dest=csv_dest)
