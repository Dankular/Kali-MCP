"""Server-owned installed package discovery; clients need no package definitions."""
import json
import os
from pathlib import Path
from profiles import guidance, PROFILES

_cached_stamp = None
_cached_packages = None


def packages():
    global _cached_stamp, _cached_packages
    base = Path("/opt/kali-mcp")
    default = next((base / name for name in ("kali-catalog.everything.json", "kali-catalog.slim.json")
                    if (base / name).is_file()), base / "kali-catalog.json")
    path = Path(os.environ.get("MCP_KALI_CATALOG_PATH", str(default)))
    stamp = (str(path.resolve()), path.stat().st_mtime_ns)
    if stamp != _cached_stamp:
        _cached_packages = json.loads(path.read_text())["packages"]
        _cached_stamp = stamp
    return _cached_packages


def search(query="", offset=0, limit=25):
    if not 0 <= offset or not 1 <= limit <= 100:
        raise ValueError("offset must be nonnegative; limit must be 1-100")
    if len(query) > 512:
        raise ValueError("query is limited to 512 characters")
    query = query.strip().casefold()
    ranked = []
    for package in packages():
        commands = {Path(path).name.casefold() for path in package["executables"]}
        extra = " ".join(PROFILES[name]["purpose"] for name in commands if name in PROFILES)
        text = (package["name"] + " " + package["summary"] + " " + " ".join(commands) + " " + extra).casefold()
        if query and not all(word in text for word in query.split()):
            continue
        score = (100 if query in commands else 90 if query == package["name"].casefold()
                 else 70 if query and any(name.startswith(query) for name in commands)
                 else 50 if query and query in package["name"].casefold() else 10)
        ranked.append((score, package))
    ranked.sort(key=lambda row: (-row[0], row[1]["name"]))
    matches = [package for _, package in ranked]
    rows = []
    for package in matches[offset:offset+limit]:
        rows.append({**package, "executables": package["executables"][:40],
                     "executables_total": len(package["executables"])})
    return {"total": len(matches), "offset": offset, "packages": rows,
            "next_offset": offset + limit if offset + limit < len(matches) else None}


def command_info(command):
    if not command or command.startswith("-") or len(command) > 512:
        raise ValueError("command must name an installed executable")
    matches = []
    for package in packages():
        paths = [path for path in package["executables"]
                 if path == command or ("/" not in command and Path(path).name == command)]
        if paths:
            matches.append({"package": package["name"], "version": package["version"],
                            "summary": package["summary"], "paths": paths})
    if not matches:
        raise ValueError("command is not in the installed executable catalog; use kali_search")
    return {"command": command, "matches": matches,
            "guidance": guidance(command),
            "usage": "Use kali_run with args such as ['--help']. Network is off unless a target is declared."}


def executable(command):
    info = command_info(command)
    paths = sorted({path for match in info["matches"] for path in match["paths"]})
    # Prefer normal PATH entries over utility scripts below /usr/share.
    return next((path for path in paths if str(Path(path).parent) in
                 ("/usr/bin", "/usr/sbin", "/bin", "/sbin")), paths[0])
