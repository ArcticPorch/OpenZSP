"""
Build app/connectors/aws/data/action_levels.json from AWS's Service Reference.

AWS publishes machine-readable service authorization data at
https://servicereference.us-east-1.amazonaws.com/ -- one JSON per service, with
every IAM action annotated by access level (the same classification the IAM
Service Authorization Reference shows). This script fetches it once and writes
a compact table, per service: each action's access level and the resource
types it can target, and each resource type's ARN formats. Level is one of

    L  List
    R  Read            (none of the other flags set)
    W  Write
    P  Permissions management
    T  Tagging

The engine never fetches anything: the table is committed data, so analysis is
deterministic and works offline. Re-run this to refresh it:

    ./venv/Scripts/python.exe tools/build_aws_action_levels.py

Standard library only (urllib), like the rest of the project.
"""

import json
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BASE = "https://servicereference.us-east-1.amazonaws.com/v1"
OUT = Path(__file__).resolve().parent.parent / "app" / "connectors" / "aws" / "data" / "action_levels.json"


def fetch(url: str):
    with urllib.request.urlopen(url, timeout=60) as response:
        return json.load(response)


def level(action: dict) -> str:
    props = action.get("Annotations", {}).get("Properties", {})
    if props.get("IsPermissionManagement"):
        return "P"
    if props.get("IsTaggingOnly"):
        return "T"
    if props.get("IsWrite"):
        return "W"
    if props.get("IsList"):
        return "L"
    return "R"


def service_levels(entry: dict):
    data = fetch(entry["url"])
    actions = {
        a["Name"].lower(): [level(a), sorted({r["Name"] for r in a.get("Resources") or ()})]
        for a in data.get("Actions", [])
    }
    resources = {r["Name"]: r.get("ARNFormats", []) for r in data.get("Resources", [])}
    return entry["service"], {"actions": dict(sorted(actions.items())), "resources": resources}


def main() -> int:
    services = fetch(f"{BASE}/service-list.json")
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = dict(pool.map(service_levels, services))
    table = dict(sorted(results.items()))
    payload = {
        "source": f"{BASE}/service-list.json",
        "levels": {"L": "List", "R": "Read", "W": "Write", "P": "Permissions management", "T": "Tagging"},
        "services": table,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, separators=(",", ":"), sort_keys=False), encoding="utf-8")
    actions = sum(len(s["actions"]) for s in table.values())
    print(f"wrote {OUT} -- {len(table)} services, {actions} actions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
