#!/usr/bin/env python3
"""
Extract MCSB control IDs for Azure built-in policy definitions.

- Fetches the "List of built-in policy definitions" doc page
  (the central built-in policy index).
- Parses the table to map policy GUID -> link to GitHub "Source".
- Downloads the policy JSON from GitHub for the GUIDs you care about.
- Extracts Microsoft cloud security benchmark (MCSB) control IDs
  from the policy metadata.
- Writes a CSV: policyId, mcsbId, policyName, policyDisplayName, mcsbSource

Note: 
- This script intentionally uses only HTTP/HTML/JSON and GitHub's raw URLs;
  it does not call Azure Resource Manager.
- You may need to adjust the MCSB extraction logic once you inspect
  the metadata shapes in your tenant.

Requirements:
    pip install requests beautifulsoup4
"""

import csv
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup

# ----------------------------
# CONFIGURATION
# ----------------------------

# Microsoft docs index of built-in policy definitions.
BUILTIN_INDEX_URL = (
    # This is the canonical "List of built-in policy definitions" index
    "https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies"
)

# GitHub repo & branch that host the built-in policies
GITHUB_REPO_RAW_ROOT = (
    "https://raw.githubusercontent.com/Azure/azure-policy/master"
)

# Output file
OUTPUT_CSV = "policy_mcsb_mapping.csv"

# List of policy definition IDs (GUIDs) for which to extract MCSB IDs.
# You can move this to a text file and read it if you prefer.
POLICY_IDS_OF_INTEREST = [
    "72650e9f-97bc-4b2a-ab5f-9781a9fcecbc",
    "fc9b3da7-8347-4380-8e70-0a0361d8dedd",
    "bed48b13-6647-468e-aa2f-1af1d3f4dd40",
    "e6955644-301c-44b5-a4c4-528577de6861",
    "5b054a0d-39e2-4d53-bea3-9734cad2c69b",
    # ... keep the rest of your GUID list here ...
    "20762f1e-85fb-31b0-a600-e833633f10fe",
]


# ----------------------------
# HTML / INDEX PARSING
# ----------------------------

def fetch(url: str, session: Optional[requests.Session] = None) -> requests.Response:
    s = session or requests.Session()
    resp = s.get(url)
    resp.raise_for_status()
    return resp


def parse_builtin_index(html: str) -> Dict[str, Dict[str, str]]:
    """
    Parse the built-in policy index page and produce:

        { policyGuid: {"name": ..., "description": ..., "source_href": ...} }

    Assumptions (based on current docs structure):

    - The page contains one or more tables listing:
        Name | Description | Effect(s) | Source
    - The policy GUID is embedded in the Source link URL (GitHub path) or
      in a '.../policyDefinitions/<guid>' part of the portal URL.
    """
    soup = BeautifulSoup(html, "html.parser")
    guid_map: Dict[str, Dict[str, str]] = {}

    # Find all HTML tables in the document and scan rows
    tables = soup.find_all("table")
    for table in tables:
        # Heuristic: look at the header to see if it matches the built-in policy layout
        header = table.find("thead")
        if not header:
            continue
        th_texts = [th.get_text(strip=True).lower() for th in header.find_all("th")]
        # Expect columns like "name", "description", "effect(s)", "source"
        if not ("name" in th_texts and "source" in th_texts):
            continue

        # Map column index -> logical name
        col_map = {}
        for idx, text in enumerate(th_texts):
            if "name" in text:
                col_map["name"] = idx
            elif "description" in text:
                col_map["description"] = idx
            elif "source" in text:
                col_map["source"] = idx

        # Now parse all body rows
        for row in table.find_all("tr"):
            tds = row.find_all("td")
            if not tds or len(tds) < len(col_map):
                continue

            name = tds[col_map["name"]].get_text(strip=True) if "name" in col_map else ""
            description = (
                tds[col_map["description"]].get_text(strip=True)
                if "description" in col_map
                else ""
            )

            source_href = ""
            if "source" in col_map:
                source_cell = tds[col_map["source"]]
                a = source_cell.find("a", href=True)
                if a:
                    source_href = a["href"]

            if not source_href:
                continue

            # Try to extract policy GUID from the source link (or name link if needed)
            guid = extract_guid_from_url(source_href)
            if not guid:
                # As a fallback, also look for GUID in the name link (portal URL)
                name_link = tds[col_map["name"]].find("a", href=True)
                if name_link:
                    guid = extract_guid_from_url(name_link["href"])

            if not guid:
                continue

            guid_map[guid.lower()] = {
                "name": name,
                "description": description,
                "source_href": source_href,
            }

    return guid_map


GUID_REGEX = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def extract_guid_from_url(url: str) -> Optional[str]:
    """Extract a GUID from a URL string, if present."""
    m = GUID_REGEX.search(url)
    if m:
        return m.group(0)
    return None


# ----------------------------
# GITHUB POLICY JSON FETCH
# ----------------------------

def resolve_github_raw_url_from_source(source_href: str) -> Optional[str]:
    """
    Convert the docs 'Source' link into a raw GitHub URL for the policy JSON.

    Current docs usually point either to:
      - the GitHub web path (e.g., https://github.com/Azure/azure-policy/blob/master/...)
      - or a docs redirection that ultimately points there.

    Strategy:
      - If it already looks like a GitHub blob URL, convert it to raw.
      - If it's relative, prepend the Azure docs domain (requests will follow redirects).
      - If the final URL after redirects is GitHub, convert to raw.
    """
    # If it's already a GitHub raw URL, just return it.
    if source_href.startswith("https://raw.githubusercontent.com/"):
        return source_href

    # If it's a GitHub web URL
    if "github.com/Azure/azure-policy" in source_href:
        return github_blob_to_raw(source_href)

    # Otherwise, try to resolve via HTTP to see where it redirects
    try:
        resp = requests.get(source_href, allow_redirects=True)
        resp.raise_for_status()
        final_url = resp.url
        if "github.com/Azure/azure-policy" in final_url:
            return github_blob_to_raw(final_url)
    except Exception as e:
        print(f"Warning: failed to resolve GitHub URL for {source_href}: {e}", file=sys.stderr)

    return None


def github_blob_to_raw(url: str) -> str:
    """
    Convert a GitHub 'blob' URL to the corresponding 'raw' URL.

    Example:
        https://github.com/Azure/azure-policy/blob/master/built-in-policies/policy.json
      -> https://raw.githubusercontent.com/Azure/azure-policy/master/built-in-policies/policy.json
    """
    # Simple transformation
    url = url.replace("https://github.com/", "https://raw.githubusercontent.com/")
    url = url.replace("/blob/", "/")
    return url


def fetch_policy_json(raw_url: str) -> Optional[dict]:
    try:
        resp = requests.get(raw_url)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"Warning: failed to fetch/parse policy json from {raw_url}: {e}", file=sys.stderr)
        return None


# ----------------------------
# MCSB EXTRACTION
# ----------------------------

def extract_mcsb_ids_from_metadata(meta: dict) -> Tuple[List[str], str]:
    """
    Extract MCSB control IDs from the policy 'metadata' object.

    This function is intentionally conservative and checks a variety of
    likely patterns/keys. You may need to adjust this based on actual
    policy definitions in the MCSB mapping docs, e.g.:

        metadata["microsoft_cloud_security_benchmark"]
        metadata["securityBenchmark"] / ["controls"]
        metadata["categories"]["mcsb"]
        metadata["standards"] / ["Microsoft cloud security benchmark"]

    Returns:
        (list_of_ids, source_hint_string)
    """
    ids: List[str] = []
    source_hint_parts: List[str] = []

    if not isinstance(meta, dict):
        return ids, ""

    # 1. Obvious dedicated keys (fictional examples – adjust as needed)
    candidate_keys = [
        "mcsb",
        "microsoft_cloud_security_benchmark",
        "microsoftCloudSecurityBenchmark",
        "benchmark",
        "benchmarks",
        "securityBenchmark",
        "securityBenchmarks",
        "standards",
        "compliance",
    ]

    def _collect_ids_from_value(val, path: str):
        nonlocal ids, source_hint_parts
        if isinstance(val, str):
            # E.g., "MC_1.1, MC_1.2" or "MCAS-1"
            # Use a loose pattern: alnum, dash, dot, underscore
            raw = val.strip()
            if raw:
                # Could be comma/semicolon separated
                for token in re.split(r"[;, ]+", raw):
                    if token:
                        ids.append(token)
                source_hint_parts.append(path)
        elif isinstance(val, list):
            for idx, item in enumerate(val):
                _collect_ids_from_value(item, f"{path}[{idx}]")
        elif isinstance(val, dict):
            for k, v in val.items():
                _collect_ids_from_value(v, f"{path}.{k}")

    for key in candidate_keys:
        if key in meta:
            _collect_ids_from_value(meta[key], f"metadata.{key}")

    # Deduplicate
    ids = sorted(set(ids))

    # Build a human-readable hint
    source_hint = ", ".join(sorted(set(source_hint_parts)))
    return ids, source_hint


# ----------------------------
# MAIN FLOW
# ----------------------------

def main():
    print(f"Fetching built-in policy index from {BUILTIN_INDEX_URL} ...")
    index_html = fetch(BUILTIN_INDEX_URL).text
    index_map = parse_builtin_index(index_html)
    print(f"Parsed {len(index_map)} built-in policies from index.")

    # Ensure GUID keys are lowercase
    index_map = {k.lower(): v for k, v in index_map.items()}

    # Prepare CSV output
    out_path = Path(OUTPUT_CSV)
    out_file = out_path.open("w", newline="", encoding="utf-8")
    writer = csv.writer(out_file)

    # CSV header:
    #   1. policyId
    #   2. mcsbId (comma-separated if multiple)
    #   3. policyName (from index)
    #   4. policyDisplayName (from JSON properties.displayName)
    #   5. mcsbSource (where in metadata it was found)
    #   6. githubRawUrl (for debugging)
    writer.writerow(
        [
            "policyId",
            "mcsbId",
            "policyName",
            "policyDisplayName",
            "mcsbSource",
            "githubRawUrl",
        ]
    )

    for pid in POLICY_IDS_OF_INTEREST:
        pid_l = pid.lower()
        info = index_map.get(pid_l)

        if not info:
            print(f"Warning: policy id {pid} not found in built-in index; leaving row mostly blank.", file=sys.stderr)
            writer.writerow([pid, "", "", "", "", ""])
            continue

        source_href = info.get("source_href", "")
        github_raw_url = resolve_github_raw_url_from_source(source_href)
        if not github_raw_url:
            print(f"Warning: could not resolve GitHub raw URL for {pid} from {source_href}", file=sys.stderr)
            writer.writerow([pid, "", info.get("name", ""), "", "", ""])
            continue

        policy_json = fetch_policy_json(github_raw_url)
        if not policy_json:
            writer.writerow([pid, "", info.get("name", ""), "", "", github_raw_url])
            continue

        # Policy displayName is usually under properties.displayName
        display_name = ""
        if isinstance(policy_json, dict):
            props = policy_json.get("properties", {})
            if isinstance(props, dict):
                display_name = props.get("displayName", "")

            metadata = props.get("metadata", {})
        else:
            metadata = {}

        mcsb_ids, mcsb_source = extract_mcsb_ids_from_metadata(metadata)

        row = [
            pid,
            ",".join(mcsb_ids),
            info.get("name", ""),
            display_name,
            mcsb_source,
            github_raw_url,
        ]
        writer.writerow(row)

    out_file.close()
    print(f"Done. Wrote mapping to {out_path.resolve()}")


if __name__ == "__main__":
    main()
