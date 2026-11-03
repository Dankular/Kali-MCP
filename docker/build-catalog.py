"""Build an installed-package and executable catalog inside the worker image."""
import json
import os
from pathlib import Path
import subprocess
import sys

if "--strip-capabilities" in sys.argv:
    # Let the per-call Docker capability profile govern every binary, including
    # dumpcap/ping helpers that otherwise fail exec under a reduced bounding set.
    output = subprocess.check_output(["getcap", "-r", "/usr", "/opt"], text=True, stderr=subprocess.DEVNULL)
    for row in output.splitlines():
        marker = row.find(" cap_")
        if marker >= 0:
            os.removexattr(row[:marker], "security.capability")

packages = []
owners = {}
package_lists = {}
for listing in Path("/var/lib/dpkg/info").glob("*.list"):
    name = listing.name.removesuffix(".list").partition(":")[0]
    package_lists.setdefault(name, []).append(listing)
output = subprocess.check_output(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${binary:Summary}\n"], text=True)
for row in output.splitlines():
    name, version, summary = row.split("\t", 2)
    package = {"name": name, "version": version, "summary": summary, "executables": []}
    paths = []
    lists = package_lists.get(name, [])
    for listing in lists:
        for value in listing.read_text(errors="replace").splitlines():
            owners[value] = package
            path = Path(value)
            if value.startswith(("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/share/", "/opt/")) and path.is_file() and os.access(path, os.X_OK):
                paths.append(value)
    package["executables"] = paths
    packages.append(package)
# update-alternatives creates commands (for example java) not listed as owned
# paths in dpkg. Associate these aliases with the package owning their target.
for directory in ("/usr/bin", "/usr/sbin", "/bin", "/sbin"):
    for alias in Path(directory).iterdir():
        if alias.is_file() and os.access(alias, os.X_OK):
            resolved = str(alias.resolve())
            package = owners.get(str(alias)) or owners.get(resolved) or owners.get(resolved.removeprefix("/usr"))
            if package:
                package["executables"].append(str(alias))
for package in packages:
    package["executables"] = sorted(set(package["executables"]))
print(json.dumps({"packages": packages}, separators=(",", ":")))
