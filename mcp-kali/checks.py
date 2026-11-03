"""Repeatable startup and functional checks on isolated, offline fixtures."""
import json
import threading
import time

import catalog
import provider
import runtime

_image_lock = threading.Lock()
_image_cache = (0, None)


def image_id():
    global _image_cache
    with _image_lock:
        if time.monotonic() - _image_cache[0] > 10 or _image_cache[1] is None:
            value = provider._run(["docker", "image", "inspect", "-f", "{{.Id}}", provider.IMAGE]).stdout.strip()
            _image_cache = (time.monotonic(), value)
        return _image_cache[1]


STARTUP = {
    "ffuf": (["-V"], [0]), "hashcat": (["--version"], [0]),
    "whatweb": (["--version"], [0]), "tshark": (["--version"], [0]),
    "dumpcap": (["--version"], [0]), "searchsploit": (["--json", "kali-mcp-validation-nonexistent"], [0]),
    "java": (["-version"], [0]),
}
FUNCTIONAL = ("nmap", "hydra", "sqlmap", "nikto", "gobuster", "john", "nuclei")
DEFAULT_CHECKS = list(FUNCTIONAL) + list(STARTUP)

# This HTTP fixture lives inside the same network-disabled worker as the tool.
# It has no host mounts, external traffic, exposed ports or persistent services.
FIXTURE = r'''
import base64, hashlib, http.server, json, os, sqlite3, subprocess, threading
from urllib.parse import urlsplit, parse_qs
command = COMMAND
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "KaliMCPFixture/1.0"
    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == "/private":
            expected = "Basic " + base64.b64encode(b"fixture:fixture-pass").decode()
            if self.headers.get("Authorization") != expected:
                self.send_response(401); self.send_header("WWW-Authenticate", 'Basic realm="fixture"'); self.end_headers(); return
        if url.path == "/user":
            con = sqlite3.connect(":memory:")
            con.execute("CREATE TABLE users(id INTEGER, name TEXT)")
            con.execute("INSERT INTO users VALUES(1,'fixture')")
            try:
                rows = con.execute("SELECT id,name FROM users WHERE id=" + parse_qs(url.query).get("id",["1"])[0]).fetchall()
                body = json.dumps({"rows":rows}).encode(); status = 200
            except Exception as exc:
                body = str(exc).encode(); status = 500
            con.close()
        else:
            status = 200 if url.path in ("/", "/admin", "/private") else 404
            body = b"kali-mcp-fixture" if status == 200 else b"missing"
        self.send_response(status); self.send_header("Content-Type","text/html"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*args): pass
httpd = http.server.ThreadingHTTPServer(("127.0.0.1",18080),Handler)
threading.Thread(target=httpd.serve_forever,daemon=True).start()
open("/tmp/words","w").write("wrong\nfixture-pass\n")
open("/tmp/paths","w").write("admin\nmissing\n")
open("/tmp/nuclei-proof.yaml","w").write("id: kali-mcp-self-test\ninfo:\n  name: Kali MCP fixture\n  author: kali-mcp\n  severity: info\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}/admin'\n    matchers:\n      - type: word\n        words:\n          - kali-mcp-fixture\n")
cases = {
 "nmap": (["nmap","-sT","-n","-Pn","-p","18080","127.0.0.1"], "18080/tcp open"),
 "hydra": (["hydra","-I","-l","fixture","-P","/tmp/words","-s","18080","-t","1","-f","127.0.0.1","http-get","/private"], "password: fixture-pass"),
 "sqlmap": (["sqlmap","-u","http://127.0.0.1:18080/user?id=1","--batch","--dbms=SQLite","--technique=BEU","--banner","--timeout=5","--retries=0","--output-dir=/tmp/sqlmap"], "injectable"),
 "nikto": (["nikto","-h","http://127.0.0.1:18080","-nocheck","-nointeractive","-ask","no","-maxtime","12"], "KaliMCPFixture"),
 "gobuster": (["gobuster","dir","-u","http://127.0.0.1:18080","-w","/tmp/paths","-t","1","--no-progress","-q"], "admin"),
 "nuclei": (["nuclei","-u","http://127.0.0.1:18080","-t","/tmp/nuclei-proof.yaml","-duc","-ni","-dr","-jsonl","-silent","-nc"], "kali-mcp-self-test"),
}
if command == "john":
    open("/tmp/hashes","w").write(hashlib.sha256(b"fixture-pass").hexdigest()+"\n")
    argv = ["john","--format=raw-sha256","--wordlist=/tmp/words","--pot=/tmp/john.pot","/tmp/hashes"]
    first = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    assert first.returncode == 0, first.stderr
    argv = ["john","--format=raw-sha256","--pot=/tmp/john.pot","--show","/tmp/hashes"]
    expected = "fixture-pass"
else:
    argv, expected = cases[command]
result = subprocess.run(argv, capture_output=True, text=True, timeout=90)
print(result.stdout); print(result.stderr)
assert result.returncode == 0, result.returncode
assert expected in result.stdout, "Missing expected functional evidence: " + expected
print("FUNCTIONAL_OK:" + command)
'''


def validate_commands(commands):
    commands = commands if commands is not None else DEFAULT_CHECKS
    if not commands or len(commands) > 16 or any(name not in (*FUNCTIONAL, *STARTUP, "msfrpcd") for name in commands):
        raise ValueError("Choose supported self-test commands: " + ", ".join([*FUNCTIONAL, *STARTUP, "msfrpcd"]))
    return list(dict.fromkeys(commands))


def run_suite(commands=None):
    commands = validate_commands(commands)
    image, results = image_id(), []
    for index, command in enumerate(commands):
        runtime.check_cancelled()
        runtime.progress(f"Checking {command} ({index+1}/{len(commands)})")
        level = "functional" if command in (*FUNCTIONAL,"msfrpcd") else "startup"
        try:
            catalog.executable(command)
            if command=="msfrpcd":
                import metasploit
                result=metasploit.probe()
                passed=result.exit_code==0 and '"rpc": "ready"' in result.stdout
            elif command in FUNCTIONAL:
                script = FIXTURE.replace("COMMAND", repr(command), 1)
                result = provider.run_sandboxed(["python3", "-"], "offline", [], network_mode="none",
                                               stdin_text=script, timeout_s=110)
                passed = result.exit_code == 0 and f"FUNCTIONAL_OK:{command}" in result.stdout
            else:
                args, codes = STARTUP[command]
                result = provider.run_sandboxed([catalog.executable(command), *args], "offline", [], network_mode="none",
                                               timeout_s=30,memory_mb=512)
                passed = result.exit_code in codes and bool(result.stdout or result.stderr)
            runtime.check_cancelled()
            detail = f"exit_code={result.exit_code}; duration_ms={result.duration_ms}"
            if not passed:
                detail += "; " + (result.stdout + result.stderr)[-700:]
        except runtime.Cancelled:
            raise
        except Exception as exc:
            passed, detail = False, str(exc)
        runtime.record_validation(command, image, level, passed, detail)
        results.append({"command": command, "level": level, "passed": passed, "detail": detail})
    return {"image": image, "passed": all(row["passed"] for row in results), "checks": results}


def health():
    try:
        image, error = image_id(), None
    except Exception as exc:
        image, error = None, str(exc)
    installed = catalog.packages()
    tested = runtime.validations(image) if image else []
    orphans = len(runtime.stale_workers())
    return {"status": "degraded" if error or orphans or any(not row["passed"] for row in tested) else "ready",
            "image": provider.IMAGE, "image_id": image, "image_error": error,
            "installed_packages": len(installed), "installed_commands": len({path for p in installed for path in p["executables"]}),
            "everything_installed": any(p["name"] == "kali-linux-everything" for p in installed),
            "validation_note": "Installation does not imply runtime readiness. Checks apply only to the listed commands and image ID.",
            "checks": tested, "queue": runtime.queue_status(),
            "orphan_workers": orphans, "artifact_retention_s": 86400,
            "background_jobs": "portable MCP tools; job IDs survive client disconnects"}
