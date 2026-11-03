"""Reclaim only this full-image build's cache before Docker unpacks its image."""
import json
import subprocess
import sys

subprocess.run(["docker", "image", "inspect", "kali-mcp:everything"], check=True, stdout=subprocess.DEVNULL)
output = subprocess.check_output(["docker", "buildx", "du", "--format=json"], text=True)
records = {r["ID"]: r for line in output.splitlines() if line.strip() for r in [json.loads(line)]}
selected = {key for key, row in records.items() if
            "kali-linux-everything" in row.get("Description", "") or
            "build-catalog.py" in row.get("Description", "")}
while True:
    children = {key for key, row in records.items() if any(parent in selected for parent in row.get("Parents") or [])}
    if children <= selected:
        break
    selected |= children
selected = {key for key in selected if records[key].get("Reclaimable")}
if "--dry-run" in sys.argv:
    for key in sorted(selected):
        print(key, records[key].get("Size"), records[key].get("Description"))
    raise SystemExit(0)
print("Reclaiming", len(selected), "Kali build cache records; runtime images are retained", flush=True)
while selected:
    leaves = {key for key in selected if not any(key in (records[child].get("Parents") or []) for child in selected)}
    if not leaves:
        raise RuntimeError("Unexpected build-cache dependency cycle")
    for key in sorted(leaves):
        subprocess.run(["docker", "buildx", "prune", "--force", "--filter", "id=" + key], check=True)
    selected -= leaves
