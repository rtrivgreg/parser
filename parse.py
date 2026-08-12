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
  
"fc9b3da7-8347-4380-8e70-0a0361d8dedd",
"bed48b13-6647-468e-aa2f-1af1d3f4dd40",
"e6955644-301c-44b5-a4c4-528577de6861",
"5b054a0d-39e2-4d53-bea3-9734cad2c69b",
"da0f98fe-a24b-4ad5-af69-bd0400233661",
"4ceb8dc2-559c-478b-a15b-733fbf1e3738",
"5752e6d6-1206-46d8-8ab1-ecc2f71a8112",
"630c64f9-8b6b-4c64-b511-6544ceff6fd6",
"237b38db-ca4d-4259-9e47-7882441ca2c0",
"ea53dbee-c6c9-4f0e-9f9e-de0039b7802",
"bf16e0bb-31e1-4646-8202-60a235cc7e74",
"a2d0e922-65d0-40c4-8f87-ea6da2d307a2",
"f6ec09a3-78bf-4f8f-99dc-6c77182d0f99",
"383856f8-de7f-44a2-81fc-e5135b5c2aa4",
"f9be5368-9bf5-4b84-9e0a-7850da98bb46",
"f8d36e2f-389b-4ee4-898d-21aeb69a0f45",
"b4330a05-a843-4bc8-bf9a-cacce50c67f4",
"34f95f76-5386-4de7-b824-0d8478470c9d",
"cf820ca0-f99e-4f3e-84fb-66e913812d21",
"83a214f7-d01a-484b-91a9-ed54470c9a6a",
"057ef27e-665e-4328-8ea3-04b3122bd9fb",
"c95c74d9-38fe-4f0d-af86-0c7d626a315c",
"428256e6-1fac-4f48-a757-df34c2b3336d",
"febd0533-8e55-448f-b837-bd0e06f16469",
"95edb821-ddaf-4404-9732-666045e056b4",
"233a2a17-77ca-4fb1-9b6b-69223d272a44",
"e345eecc-fa47-480f-9e88-67dcc122b164",
"f06ddb64-5fa3-4b77-b166-acb36f7f6042",
"1c6e92c9-99f0-4e55-9cf2-0c234dc48f99",
"47a1ee2f-2a2a-4576-bf2a-e0e36709c2b8",
"df49d893-a74c-421d-bc95-c663042e5b80",
"1a5b4dca-0b6f-4cf5-907c-56316bc1bf3d",
"c26596ff-4d70-4e6a-9a30-c2506bd2f80c",
"511f5417-5d12-434d-ab2e-816901e72a5e",
"82985f06-dc18-4a48-bc1c-b9f4f0098cfe",
"098fc59e-46c7-4d99-9b16-64990e543d75",
"b6e2945c-0b7b-40f5-9233-7a5323b5cdc6",
"a6fb4358-5bf4-4ad7-ba82-2cd2f41ce5e9",
"ef619a2c-cc4d-4d03-b2ba-8c94a834d85b",
"b54ed75b-3e1a-44ac-a333-05ba39b99ff0",
"71ef260a-8f18-47b7-abcb-62d0673d94dc",
"055aa869-bc98-4af8-bafc-23f1ab6ffe2c",
"564feb30-bf6a-4854-b4bb-0d2d2d1e6c66",
"862e97cf-49fc-4a5c-9de4-40d4e2e7c8eb",
"d9da03a1-f3c3-412a-9709-947156872263",
"617c02be-7f02-4efd-8836-3180d47b6c68",
"0b60c0b2-2dc2-4e1c-b5c9-abbed971de53",
"1e66c121-a66a-4b1f-9b83-0fd99bf0fc2d",
"0a075868-4c26-42ef-914c-5bc007359560",
"98728c90-32c7-4049-8429-847dc0f4fe37",
"152b15f7-8e1f-4c1f-ab71-8c010ba5dbc0",
"ec068d99-e9c7-401f-8cef-5bdde4e6ccf1",
"c349d81b-9985-44ae-a8da-ff98d108ede8",
"3657f5a0-770e-44a3-b44e-9431ba1e9735",
"b4ac1030-89c5-4697-8e00-28b5ba6a8811",
"ea0dfaed-95fb-448c-934e-d6e713ce393d",
"3a58212a-c829-4f13-9872-6371df2fd0b4",
"24fba194-95d6-48c0-aea7-f65bf859c598",
"4733ea7b-a883-42fe-8cac-97454c2a9e4a",
"f4b53539-8df9-40e4-86c6-6b607703bd4e",
"41425d9f-d1a5-499a-9932-f8ed8453932c",
"fc4d8e41-e223-45ea-9bf5-eada37891d87",
"86efb160-8de7-451d-bc08-5d475b0aadae"

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
    Parse the current Microsoft built-in policy index page.

    Expected current layout:
      | Name (Azure portal) | Description | Effect(s) | Version (GitHub) |

    Returns:
        {
            policy_guid: {
                "name": <portal link text>,
                "description": <description text>,
                "source_href": <GitHub source link from Version column>,
                "portal_href": <Azure portal link>,
                "version": <version text>,
            }
        }
    """
    soup = BeautifulSoup(html, "html.parser")
    guid_map: Dict[str, Dict[str, str]] = {}

    for table in soup.find_all("table"):
        rows = table.find_all("tr")
        if not rows:
            continue

        header_cells = rows[0].find_all(["th", "td"])
        headers = [c.get_text(" ", strip=True).lower() for c in header_cells]

        # Current docs usually use these columns.
        # Be tolerant to wording changes such as Source vs Version.
        has_name = any("name" in h for h in headers)
        has_description = any("description" in h for h in headers)
        has_version_or_source = any(("version" in h) or ("source" in h) for h in headers)

        if not (has_name and has_description and has_version_or_source):
            continue

        def find_col(*needles: str) -> Optional[int]:
            for i, h in enumerate(headers):
                if all(n in h for n in needles):
                    return i
            return None

        name_idx = find_col("name")
        desc_idx = find_col("description")
        version_idx = find_col("version")
        if version_idx is None:
            version_idx = find_col("source")

        if name_idx is None or desc_idx is None or version_idx is None:
            continue

        for row in rows[1:]:
            cells = row.find_all("td")
            if len(cells) <= max(name_idx, desc_idx, version_idx):
                continue

            name_cell = cells[name_idx]
            desc_cell = cells[desc_idx]
            version_cell = cells[version_idx]

            portal_a = name_cell.find("a", href=True)
            source_a = version_cell.find("a", href=True)

            portal_href = portal_a["href"].strip() if portal_a else ""
            source_href = source_a["href"].strip() if source_a else ""

            # Prefer extracting GUID from the portal link first.
            guid = extract_guid_from_url(portal_href)
            if not guid and source_href:
                guid = extract_guid_from_url(source_href)

            if not guid:
                continue

            guid_map[guid.lower()] = {
                "name": name_cell.get_text(" ", strip=True),
                "description": desc_cell.get_text(" ", strip=True),
                "source_href": source_href,
                "portal_href": portal_href,
                "version": version_cell.get_text(" ", strip=True),
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
