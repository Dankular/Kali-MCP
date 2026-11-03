"""Linux Docker executor; firewall rules exist before tool processes start."""
from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import json
import os
import secrets
import re
import socket
import subprocess
import time
import shlex
from functools import wraps
from pathlib import Path
from dataclasses import asdict, dataclass, field
import runtime
from results import parse_findings

IMAGE = os.environ.get("MCP_KALI_IMAGE", "kali-mcp:everything" if
                       Path("/opt/kali-mcp/kali-catalog.everything.json").is_file() else "kali-mcp:1")
SCAN_NETWORK = os.environ.get("MCP_KALI_SCAN_NETWORK", "mcp-scan-net")
LOCK_PATH = "/run/lock/kali-mcp.lock"
DEFAULT_TIMEOUT_S = 120


class PolicyError(ValueError):
    pass


class ProviderError(RuntimeError):
    pass


@dataclass
class ExecResult:
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    target_host: str
    target_ip: str
    allowed_ports: list[int]
    sandbox: dict = field(default_factory=dict)
    timed_out: bool = False
    allowed_udp_ports: list[int] = field(default_factory=list)
    cancelled: bool = False
    queue_wait_ms: int = 0
    artifacts: list[dict] = field(default_factory=list)
    artifact_errors: list[str] = field(default_factory=list)

    def evidence(self):
        result = asdict(self)
        result["target_ip_resolved"] = result.pop("target_ip")
        result["output_sha256"] = hashlib.sha256(
            (self.stdout + self.stderr).encode()).hexdigest()
        result["findings"] = parse_findings(self.stdout, self.argv)
        for key in ("stdout", "stderr"):
            raw = result[key].encode()
            result[key + "_truncated"] = len(raw) > 65536
            if len(raw) > 65536:
                result[key] = raw[:65536].decode(errors="replace")
        return result


def _run(cmd, *, timeout=30, check=True):
    result = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
    if check and result.returncode:
        raise ProviderError(f"{cmd[0]} failed: {result.stderr.strip()}")
    return result


def _iptables(*args, check=True):
    return _run(["iptables", "-w", "10", *args], check=check)


def _ebtables(*args):
    return _run(["ebtables", "-t", "nat", *args])


class _IptablesLock:
    def __enter__(self):
        self.fh = open(LOCK_PATH, "a")
        fcntl.flock(self.fh, fcntl.LOCK_EX)
        return self

    def __exit__(self, *args):
        self.fh.close()


def resolve_target(host: str, allow_private: bool) -> str:
    if os.environ.get("MCP_KALI_ALLOW_PRIVATE", "1") != "1":
        allow_private = False
    if not host or host.startswith("-") or any(c.isspace() for c in host) or any(c in host for c in "/:@\\"):
        raise PolicyError("target must be a single IPv4 address or DNS hostname")
    try:
        ip = ipaddress.IPv4Address(socket.gethostbyname(host))
    except (OSError, ValueError) as exc:
        raise PolicyError(f"cannot resolve target: {host}") from exc
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified or ip in ipaddress.ip_network("0.0.0.0/8"):
        raise PolicyError(f"target {ip} is in a blocked range")
    if not ip.is_global and not allow_private:
        raise PolicyError(f"target {ip} requires allow_private=True")
    return str(ip)


def _network():
    result = _run(["docker", "network", "inspect", SCAN_NETWORK], check=False)
    if result.returncode:
        _run(["docker", "network", "create", "--opt", "com.docker.network.bridge.enable_icc=false", SCAN_NETWORK])
        result = _run(["docker", "network", "inspect", SCAN_NETWORK])
    network = json.loads(result.stdout)[0]
    if network.get("Driver") != "bridge" or network.get("EnableIPv6"):
        raise ProviderError("scan network must be an IPv4-only Docker bridge")
    subnet = ipaddress.ip_network(network["IPAM"]["Config"][0]["Subnet"])
    bridge = network.get("Options", {}).get("com.docker.network.bridge.name") or "br-" + network["Id"][:12]
    parent = "MKNET" + network["Id"][:12]
    if _iptables("-S", parent, check=False).returncode:
        _iptables("-N", parent)
        _iptables("-A", parent, "-s", str(subnet), "-m", "conntrack",
                  "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
        _iptables("-A", parent, "-j", "DROP")
    hook = ["-i", bridge, "-j", parent]
    if _iptables("-C", "DOCKER-USER", *hook, check=False).returncode:
        _iptables("-I", "DOCKER-USER", "1", *hook)
    rule = ["-i", bridge, "-m", "comment", "--comment", "kali-mcp-default-deny", "-j", "DROP"]
    if _iptables("-C", "INPUT", *rule, check=False).returncode:
        _iptables("-I", "INPUT", "1", *rule)
    network["_mcp_chain"] = parent
    if _run(["sysctl", "-n", "net.bridge.bridge-nf-call-iptables"]).stdout.strip() != "1":
        raise ProviderError("bridge-nf-call-iptables must be 1")
    return network


def scheduled(function):
    @wraps(function)
    def execute(*args, **kwargs):
        memory = kwargs.get("memory_mb", 512)
        if type(memory) is not int or not 128 <= memory <= 2048:
            raise PolicyError("memory_mb must be between 128 and 2048")
        with runtime.admission(memory) as waited:
            runtime.progress("Executing command")
            result = function(*args, **kwargs)
            result.queue_wait_ms = waited
            return result
    return execute


def validate_artifact_paths(paths):
    if len(paths) > 10:
        raise PolicyError("At most 10 artifact paths may be retained")
    for path in paths:
        if not isinstance(path, str) or len(path) > 512 or not path.startswith("/tmp/") or any(
                part in ("", ".", "..") for part in path.split("/")[1:]) or "\x00" in path:
            raise PolicyError("Artifacts must be explicit regular-file paths below /tmp, without dot segments")


def _capture_artifact(name, path):
    # Read inside the still-running namespace: tmpfs disappears when Docker stops.
    # No archive extraction, host mount, links or unbounded output is involved.
    script = '''import os,stat,sys
p, maximum = sys.argv[1], int(sys.argv[2])
assert os.path.realpath(p).startswith('/tmp/'), 'Path resolves outside /tmp'
fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(fd,'rb') as stream:
    info = os.fstat(stream.fileno())
    assert stat.S_ISREG(info.st_mode) and info.st_size <= maximum, 'Not a bounded regular file'
    data = stream.read(maximum+1)
    assert len(data) <= maximum, 'File grew beyond limit'
    sys.stdout.buffer.write(data)
'''
    maximum = int(os.environ.get("MCP_KALI_ARTIFACT_MAX_BYTES", "8388608"))
    result = subprocess.run(["docker", "exec", name, "python3", "-c", script, path, str(maximum)],
                            capture_output=True, timeout=15)
    if result.returncode:
        raise ValueError(result.stderr.decode(errors="replace")[-250:])
    return runtime.save_artifact(Path(path).name, result.stdout)


@scheduled
def run_sandboxed(argv, target_host, target_ports, *, allow_private=False,
                  extra_caps=None, timeout_s=DEFAULT_TIMEOUT_S, network_mode="allowlist",
                  stdin_text=None, memory_mb=512, target_udp_ports=None, artifact_paths=None):
    artifact_paths = artifact_paths or []
    validate_artifact_paths(artifact_paths)
    if network_mode not in ("allowlist", "none"):
        raise PolicyError("invalid network mode")
    if not 1 <= timeout_s <= 600:
        raise PolicyError("timeout_s must be between 1 and 600")
    if type(memory_mb) is not int or not 128 <= memory_mb <= 2048:
        raise PolicyError("memory_mb must be between 128 and 2048")
    ports = sorted(set(target_ports))
    udp_ports = sorted(set(target_udp_ports or []))
    if network_mode == "allowlist" and ((not ports and not udp_ports) or
            any(type(p) is not int or not 1 <= p <= 65535 for p in ports + udp_ports)):
        raise PolicyError("ports must be between 1 and 65535")
    caps = extra_caps or []
    if any(c != "NET_RAW" for c in caps):
        raise PolicyError("only NET_RAW may be granted")
    target_ip = resolve_target(target_host, allow_private) if network_mode == "allowlist" else "0.0.0.0"
    argv = [a.replace("{target_ip}", target_ip) for a in argv]
    name = "kali-mcp-" + secrets.token_hex(8)
    chain = "MK" + secrets.token_hex(8)
    container_ip = None
    veth = parent = None
    created = hooked = chain_created = False
    l2_created = l2_hooked = False
    started = time.monotonic()
    exit_marker = "/tmp/.kali-exit-" + secrets.token_hex(16)
    release_marker = exit_marker + "-release"
    runtime.register_worker(name, chain)
    base = ["docker", "create", "--pull", "never", "--name", name, "--label", "app=kali-mcp",
            "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m",
            "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
            "--pids-limit", "256", "--memory", f"{memory_mb}m", "--cpus", "1",
            "--log-opt", "max-size=2m", "--log-opt", "max-file=1", "--env", "HOME=/tmp"]
    for cap in caps:
        base.extend(["--cap-add", cap])
    if os.environ.get("MCP_KALI_CGROUP_PARENT"):
        base.extend(["--cgroup-parent", os.environ["MCP_KALI_CGROUP_PARENT"]])
    if stdin_text is not None:
        base.append("--interactive")
    try:
        with _IptablesLock():
            if network_mode == "allowlist":
                network = _network()
                cfg = network["IPAM"]["Config"][0]
                net = ipaddress.ip_network(cfg["Subnet"])
                used = {v["IPv4Address"].split("/")[0] for v in network["Containers"].values()}
                used.add(cfg.get("Gateway"))
                container_ip = next((str(ip) for ip in net.hosts() if str(ip) not in used), None)
                if container_ip is None:
                    raise ProviderError("scan network has no free IPv4 addresses")
                _iptables("-N", chain)
                chain_created = True
                for protocol, allowed in (("tcp", ports), ("udp", udp_ports)):
                    for offset in range(0, len(allowed), 15):
                        _iptables("-A", chain, "-s", container_ip, "-d", target_ip, "-p", protocol,
                                  "-m", "multiport", "--dports",
                                  ",".join(map(str, allowed[offset:offset + 15])), "-j", "ACCEPT")
                _iptables("-A", chain, "-j", "DROP")
                # Docker's embedded DNS otherwise forwards via the host, outside
                # per-container forwarding rules. Localhost is this worker's
                # namespace; explicit DNS requests can still use declared UDP ports.
                base.extend(["--network", SCAN_NETWORK, "--ip", container_ip, "--dns", "127.0.0.1"])
            else:
                base.extend(["--network", "none"])
            # Only this fixed bootstrap runs before physical-interface policy is
            # attached. The default bridge chain blocks all new traffic meanwhile.
            bootstrap = 'while [ ! -f /tmp/.kali-ready ]; do sleep 0.05; done; ' if network_mode == "allowlist" else ""
            if artifact_paths:
                bootstrap += ('"$@"; code=$?; touch ' + exit_marker + '; while [ ! -f ' + release_marker +
                              ' ]; do sleep 0.1; done; exit "$code"')
                entry = ["sh", "-c", bootstrap, "runner", *argv]
            elif bootstrap:
                entry = ["sh", "-c", bootstrap + 'exec "$@"', "runner", *argv]
            else:
                entry = argv
            _run([*base, IMAGE, *entry])
            created = True
            _run(["docker", "start", name])
            if network_mode == "allowlist":
                interface = _run(["docker", "exec", name, "sh", "-c",
                    "cat /sys/class/net/eth0/iflink /sys/class/net/eth0/address"]).stdout.splitlines()
                link_index, mac = int(interface[0]), interface[1]
                links = json.loads(_run(["ip", "-j", "link", "show"]).stdout)
                veth = next(link["ifname"] for link in links if link["ifindex"] == link_index)
                parent = network["_mcp_chain"]
                _ebtables("-N", chain)
                l2_created = True
                _ebtables("-A", chain, "-s", mac, "-p", "ARP", "--arp-ip-src", container_ip, "-j", "RETURN")
                _ebtables("-A", chain, "-s", mac, "-p", "IPv4", "-j", "RETURN")
                _ebtables("-A", chain, "-j", "DROP")
                # PREROUTING is before bridge MAC learning as well as IP routing.
                _ebtables("-I", "PREROUTING", "1", "-i", veth, "-j", chain)
                l2_hooked = True
                _iptables("-I", parent, "1", "-m", "physdev", "--physdev-in", veth, "-j", chain)
                hooked = True
                _run(["docker", "exec", name, "touch", "/tmp/.kali-ready"])
        timed_out = was_cancelled = False
        runtime.check_cancelled()
        try:
            if stdin_text is not None:
                proc = subprocess.Popen(["docker", "attach", name], stdin=subprocess.PIPE,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                proc = subprocess.Popen(["docker", "wait", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline, first = time.monotonic() + timeout_s, True
            try:
                while True:
                    if runtime.cancelled():
                        was_cancelled = True
                        _run(["docker", "kill", name])
                        break
                    if time.monotonic() >= deadline:
                        timed_out = True
                        _run(["docker", "kill", name])
                        break
                    if artifact_paths and _run(["docker", "exec", name, "test", "-f", exit_marker], check=False).returncode == 0:
                        break
                    try:
                        proc.communicate(stdin_text.encode() if stdin_text is not None and first else None, timeout=0.25)
                        break
                    except subprocess.TimeoutExpired:
                        first = False
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.communicate()
        except runtime.Cancelled:
            was_cancelled = True
            _run(["docker", "kill", name])
        artifacts, artifact_errors = [], []
        if artifact_paths and not timed_out and not was_cancelled:
            try:
                for path in artifact_paths:
                    try:
                        artifacts.append(_capture_artifact(name, path))
                    except Exception as exc:
                        artifact_errors.append(f"{path}: {exc}")
            finally:
                _run(["docker", "exec", name, "touch", release_marker])
                _run(["docker", "wait", name], timeout=30)
        elif artifact_paths:
            artifact_errors = [f"{path}: unavailable after timeout/cancellation" for path in artifact_paths]
        state = json.loads(_run(["docker", "inspect", "-f", "{{json .State}}", name]).stdout)
        if state["Running"]:
            raise ProviderError("container input stream ended before the process exited")
        logs = _run(["docker", "logs", name], check=False)
        for filename, output in (("stdout.txt", logs.stdout), ("stderr.txt", logs.stderr)):
            if len(output.encode()) > 65536:
                try:
                    artifacts.append(runtime.save_artifact(filename, output.encode()))
                except ValueError as exc:
                    artifact_errors.append(f"{filename}: {exc}")
        denied = 0
        l2_denied = 0
        if chain_created:
            rules = _iptables("-L", chain, "-n", "-v", "-x").stdout.splitlines()
            denied = sum(int(row.split()[0]) for row in rules if " DROP " in row)
        if l2_created:
            rules = _ebtables("-L", chain, "--Lc").stdout.splitlines()
            l2_denied = sum(int(match.group(1)) for row in rules if "-j DROP" in row
                            for match in re.finditer(r"pcnt\s*=\s*(\d+)", row))
        return ExecResult(argv, 130 if was_cancelled else 124 if timed_out else state["ExitCode"], logs.stdout,
                          logs.stderr, int((time.monotonic()-started)*1000), target_host,
                          target_ip, ports, {"image": IMAGE, "network_mode": network_mode,
                          "caps": caps, "read_only_rootfs": True, "container": name,
                          "container_ip": container_ip, "memory_mb": memory_mb,
                          "egress_denied_packets": denied, "layer2_denied_packets": l2_denied,
                          "network_interface": veth},
                          timed_out, allowed_udp_ports=udp_ports, cancelled=was_cancelled,
                          artifacts=artifacts, artifact_errors=artifact_errors)
    finally:
        try:
            # Remove the container before lifting restrictions. Failure leaves its rules in place.
            if created:
                _run(["docker", "rm", "-f", name])
            with _IptablesLock():
                if hooked:
                    _iptables("-D", parent, "-m", "physdev", "--physdev-in", veth, "-j", chain)
                if chain_created:
                    _iptables("-F", chain)
                    _iptables("-X", chain)
                if l2_hooked:
                    _ebtables("-D", "PREROUTING", "-i", veth, "-j", chain)
                if l2_created:
                    _ebtables("-F", chain)
                    _ebtables("-X", chain)
        except BaseException:
            runtime.orphan_worker(name)
            raise
        else:
            runtime.unregister_worker(name)


def reap_orphans():
    """Remove only registered workers whose owner died or whose cleanup failed."""
    for worker in runtime.stale_workers():
        name, chain = worker["name"], worker["chain_name"]
        if not re.fullmatch(r"kali-mcp-[0-9a-f]{16}", name) or not re.fullmatch(r"MK[0-9a-f]{16}", chain):
            continue
        with _IptablesLock():
            # Removing the worker first preserves default-deny isolation throughout.
            found = _run(["docker", "inspect", name], check=False)
            if found.returncode == 0:
                _run(["docker", "rm", "-f", name])
            elif "No such" not in found.stderr:
                raise ProviderError(found.stderr)
            rules = _run(["iptables-save", "-t", "filter"]).stdout
            for line in rules.splitlines():
                if line.startswith("-A "):
                    args = shlex.split(line)
                    if any(args[i:i+2] == ["-j", chain] for i in range(len(args)-1)):
                        _iptables("-D", *args[1:])
            if _iptables("-S", chain, check=False).returncode == 0:
                _iptables("-F", chain)
                _iptables("-X", chain)
            table = None
            for line in _run(["ebtables-save"]).stdout.splitlines():
                if line.startswith("*"):
                    table = line[1:]
                if table == "nat" and line.startswith("-A "):
                    args = shlex.split(line)
                    if any(args[i:i+2] == ["-j", chain] for i in range(len(args)-1)):
                        _ebtables("-D", *args[1:])
            if _run(["ebtables", "-t", "nat", "-L", chain], check=False).returncode == 0:
                _ebtables("-F", chain)
                _ebtables("-X", chain)
            runtime.unregister_worker(name)
