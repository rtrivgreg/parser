# Azure Policy → MCSB / CMA Mapping

Extracts Microsoft cloud security benchmark (MCSB) control IDs and manual
attestation (CMA) IDs for a list of Azure built-in policy definition GUIDs.

## What it does

For each policy GUID you provide, the script produces a CSV row with:

| Column | Source |
|---|---|
| `policyId` | Your input GUID |
| `mcsbId` | MCSB control ID(s) (e.g. `Azure_Security_Benchmark_v3.0_PV-4`), looked up from the [MCSB v2 initiative definition](https://raw.githubusercontent.com/Azure/azure-policy/master/built-in-policies/policySetDefinitions/Security%20Center/MCSBv2.json) |
| `cmaId` | Manual-attestation control ID (e.g. `CMA_0024`, `CMA_C1725`), extracted from the policy's own metadata/description |
| `policyName` | From the [Microsoft docs built-in policy index](https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies) |
| `policyDisplayName` | `properties.displayName` from the policy's JSON on GitHub |
| `policyDescription` | `properties.description` from the policy's JSON on GitHub |
| `mcsbSource` | URL of the MCSB initiative file used for the mapping |
| `githubRawUrl` | Raw GitHub URL of the resolved policy definition JSON |

## Key things to know

- **MCSB only covers automated policies.** Manual attestation (`CMA_####` /
  `CMA_C####`) policies are never in the MCSB initiative, so `mcsbId` is
  correctly blank for them — that's expected, not a bug.
- **CMA policies aren't listed on the Microsoft docs index page.** To resolve
  their display name, description, and `cmaId`, the script falls back to
  GitHub's code-search API, which requires a personal access token.

## Usage

```bash
pip install requests beautifulsoup4

# One GUID per line in policy_ids.txt (# comments / blank lines OK)
python3 parse.py

# Custom input/output paths
python3 parse.py -i my_guids.txt -o out.csv

# Set a token to resolve CMA / index-missing policies too
GITHUB_TOKEN=<your_personal_access_token> python3 parse.py
```

`GITHUB_TOKEN` (or `GH_TOKEN`) is optional — without it, policies missing
from the docs index (all CMA ones) are skipped with a warning and their
`cmaId`/`policyDisplayName`/`policyDescription`/`githubRawUrl` are left blank.

## Files

- `parse.py` — the script
- `policy_ids.txt` — the production list of policy GUIDs to process
- `sample_output.csv` — small demo output (7 example GUIDs, including one of
  each variety: automated MCSB-mapped, unmapped, and both CMA_#### /
  CMA_C#### manual-attestation formats) showing what each column looks like.
  This is NOT the output of running against the full `policy_ids.txt` list —
  run `parse.py` yourself (ideally with `GITHUB_TOKEN` set) to generate that.
