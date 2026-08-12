#!/usr/bin/env python3
"""
Extract MCSB control IDs for Azure built-in policy definitions.

FIXED VERSION
-------------
The original script tried to find MCSB control IDs inside each individual
built-in policy definition's `properties.metadata` object. That never works:
individual policy definitions (e.g. AzureWindowsBaseline_AINE.json) do NOT
contain MCSB/benchmark info anywhere in their metadata.

The MCSB (Microsoft cloud security benchmark) control mapping actually lives
in a single, separate policy SET (initiative) definition file in the same
Azure/azure-policy repo:

    built-in-policies/policySetDefinitions/Security Center/MCSBv2.json

That file has a `properties.policyDefinitions` array where each entry looks
like:

    {
      "policyDefinitionId": ".../policyDefinitions/<GUID>",
      "policyDefinitionReferenceId": "...",
      "groupNames": ["Azure_Security_Benchmark_v3.0_PV-4", ...]
    }

`groupNames` IS the list of MCSB control IDs for that policy. So instead of
trying to parse each policy's metadata, we fetch MCSBv2.json ONCE, build a
GUID -> groupNames lookup table, and use that for every policy ID.

Everything else (docs-index scraping for policyName/githubRawUrl, and
per-policy JSON fetch for displayName/description) is kept from the original
script. A policyDescription column (pulled from properties.description in
the GitHub JSON, falling back to the docs-index description) has been added.

A cmaId column has also been added. Some frameworks (like NIST 800-53) have
controls automated cloud scanners can't check (e.g. manual background checks,
physical key storage). Microsoft covers these by injecting manual-attestation
policies -- prefixed CMA_#### -- into the relevant Regulatory Compliance
initiative. Each CMA_#### policy is a real, separately GUID-identified policy
definition (see built-in-policies/policyDefinitions/Regulatory Compliance/ in
the repo) whose metadata.additionalMetadataId and description both carry the
CMA_#### token, which is what gets extracted into the cmaId column.

CMA_#### policies are NOT listed on the docs built-in-policies index page, so
resolving them (or any other policy missing from that index) requires a
GitHub personal access token in the GITHUB_TOKEN or GH_TOKEN environment
variable, used to call GitHub's code-search API as a fallback lookup. Without
a token, such policies are simply skipped and cmaId is left blank.

Requirements:
    pip install requests beautifulsoup4
"""

import argparse
import csv
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote

import requests
from bs4 import BeautifulSoup

# ----------------------------
# CONFIGURATION
# ----------------------------

BUILTIN_INDEX_URL = (
    "https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies"
)

GITHUB_REPO_RAW_ROOT = "https://raw.githubusercontent.com/Azure/azure-policy/master"

# The single source of truth for MCSB control-id mappings.
MCSB_INITIATIVE_RAW_URL = (
    GITHUB_REPO_RAW_ROOT
    + "/built-in-policies/policySetDefinitions/"
    + quote("Security Center/MCSBv2.json")
)

OUTPUT_CSV = "policy_mcsb_mapping.csv"

# Default input file: one policy GUID per line. Blank lines and lines
# starting with # are ignored. Override with --input on the command line.
DEFAULT_POLICY_IDS_FILE = "policy_ids.txt"

GUID_REGEX = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def load_policy_ids(path: Path) -> List[str]:
    """
    Read policy GUIDs from a text file, one per line.

    - Blank lines are skipped.
    - Lines starting with '#' are treated as comments and skipped.
    - Trailing inline comments ("GUID  # some note") are stripped.
    - Lines that don't contain a valid GUID are skipped with a warning.
    """
    if not path.exists():
        print(f"Error: policy ID file not found: {path}", file=sys.stderr)
        sys.exit(1)

    ids: List[str] = []
    for lineno, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        m = GUID_REGEX.search(line)
        if not m:
            print(f"Warning: line {lineno} in {path} has no valid GUID, skipping: {raw_line!r}", file=sys.stderr)
            continue
        ids.append(m.group(0))

    if not ids:
        print(f"Error: no valid policy GUIDs found in {path}", file=sys.stderr)
        sys.exit(1)

    return ids


# ----------------------------
# MCSB LOOKUP (THE FIX)
# ----------------------------

def build_mcsb_lookup(session: Optional[requests.Session] = None) -> Dict[str, List[str]]:
    """
    Fetch the MCSB initiative (policy set) definition once and build a
    {guid_lowercase: [mcsb_control_id, ...]} lookup.
    """
    s = session or requests.Session()
    resp = s.get(MCSB_INITIATIVE_RAW_URL, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    lookup: Dict[str, List[str]] = {}
    for pd in data["properties"]["policyDefinitions"]:
        m = GUID_REGEX.search(pd.get("policyDefinitionId", ""))
        if not m:
            continue
        guid = m.group(0).lower()
        group_names = pd.get("groupNames", [])
        # A policy can appear more than once (rare); merge if so.
        lookup.setdefault(guid, [])
        for g in group_names:
            if g not in lookup[guid]:
                lookup[guid].append(g)
    return lookup


# ----------------------------
# HTML / INDEX PARSING (unchanged from original)
# ----------------------------

def fetch(url: str, session: Optional[requests.Session] = None) -> requests.Response:
    s = session or requests.Session()
    resp = s.get(url, timeout=30)
    resp.raise_for_status()
    return resp


def extract_guid_from_url(url: str) -> Optional[str]:
    m = GUID_REGEX.search(url)
    return m.group(0) if m else None


def parse_builtin_index(html: str) -> Dict[str, Dict[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    guid_map: Dict[str, Dict[str, str]] = {}

    for table in soup.find_all("table"):
        rows = table.find_all("tr")
        if not rows:
            continue

        header_cells = rows[0].find_all(["th", "td"])
        headers = [c.get_text(" ", strip=True).lower() for c in header_cells]

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
        version_idx = find_col("version") or find_col("source")
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

            guid = extract_guid_from_url(portal_href) or extract_guid_from_url(source_href)
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


GITHUB_SEARCH_API_URL = "https://api.github.com/search/code"
GITHUB_TOKEN_ENV_VARS = ("GITHUB_TOKEN", "GH_TOKEN")


def get_github_token() -> Optional[str]:
    for var in GITHUB_TOKEN_ENV_VARS:
        tok = os.environ.get(var)
        if tok:
            return tok
    return None


def find_policy_path_via_github_search(guid: str, token: str, session: Optional[requests.Session] = None) -> Optional[str]:
    """
    Fallback for policy GUIDs that aren't listed on the docs built-in-policies
    index page. This notably includes EVERY manual-attestation CMA_####
    policy (Microsoft doesn't list those on that page), plus any newly added
    or deprecated policies the docs page hasn't caught up with.

    Uses GitHub's code search API to find the policyDefinitions/*.json file
    containing this GUID. Requires a GitHub personal access token (set
    GITHUB_TOKEN or GH_TOKEN in the environment) -- GitHub's code search API
    rejects unauthenticated requests.
    """
    s = session or requests.Session()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    params = {"q": f"{guid} repo:Azure/azure-policy"}
    try:
        resp = s.get(GITHUB_SEARCH_API_URL, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        items = resp.json().get("items", [])
    except Exception as e:
        print(f"Warning: GitHub code search failed for {guid}: {e}", file=sys.stderr)
        return None

    # Prefer an actual policy DEFINITION file over a policy SET (initiative)
    # that merely references this GUID among hundreds of others.
    def_paths = [it["path"] for it in items if "/policyDefinitions/" in it.get("path", "")]
    if def_paths:
        return def_paths[0]
    return items[0]["path"] if items else None


def github_blob_to_raw(url: str) -> str:
    url = url.replace("https://github.com/", "https://raw.githubusercontent.com/")
    url = url.replace("/blob/", "/")
    return url


def resolve_github_raw_url_from_source(source_href: str) -> Optional[str]:
    if source_href.startswith("h
