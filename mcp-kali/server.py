"""Thin, typed MCP tools over the per-call Docker provider. stdout is MCP only."""
from __future__ import annotations

import re
import os
from functools import partial, wraps
import anyio
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
import provider
import catalog
import runtime
import checks
import nuclei
import metasploit
from results import ExecutionEvidence, JobStatus, MetasploitWorkspace, MetasploitResponse
from typing import Any

from mcp.server.transport_security import TransportSecuritySettings

mcp = FastMCP("kali-mcp", stateless_http=True, json_response=True,
              transport_security=TransportSecuritySettings(
                  allowed_hosts=os.environ.get("MCP_KALI_ALLOWED_HOSTS", "127.0.0.1:*,localhost:*").split(","),
                  allowed_origins=os.environ.get("MCP_KALI_ALLOWED_ORIGINS", "http://127.0.0.1:*,http://localhost:*").split(",")))


def threaded(function):
    """Keep Docker execution and catalog reads off the HTTP event loop."""
    @wraps(function)
    async def invoke(*args, **kwargs):
        return await anyio.to_thread.run_sync(partial(function, *args, **kwargs))
    return invoke


def parse_ports(value: str) -> list[int]:
    if not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", value):
        raise ValueError("ports must be comma-separated ports or inclusive ranges")
    ports = set()
    for item in value.split(","):
        bounds = list(map(int, item.split("-")))
        start, end = bounds[0], bounds[-1]
        if not 1 <= start <= end <= 65535:
            raise ValueError("ports must be ascending and between 1 and 65535")
        ports.update(range(start, end + 1))
    if len(ports) > 4096:
        raise ValueError("at most 4096 ports per call")
    return sorted(ports)


def _port(value):
    if not 1 <= value <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return value


def _wordlist(value):
    if not value.strip() or len(value.encode()) > 65536 or "\x00" in value:
        raise ValueError("wordlist must contain 1 to 65536 bytes without NULs")
    return value.rstrip() + "\n"


@mcp.tool()
@threaded
def nmap_scan(target: str, ports: str = "1-1000", scan_type: Literal["connect", "syn"] = "connect",
              allow_private: bool = False, timeout_s: int = 90) -> ExecutionEvidence:
    """Scan TCP ports on one authorized target. Private lab targets require allow_private."""
    port_list = parse_ports(ports)
    return provider.run_sandboxed(
        ["nmap", "-sS" if scan_type == "syn" else "-sT", "-n", "-Pn", "-p", ports, "{target_ip}"],
        target, port_list, allow_private=allow_private,
        extra_caps=["NET_RAW"] if scan_type == "syn" else [], timeout_s=timeout_s).evidence()


@mcp.tool()
@threaded
def hydra_bruteforce(target: str, service: Literal["ssh", "ftp", "http-get", "https-get"],
                     username: str, password_list_inline: str, port: int,
                     allow_private: bool = False, timeout_s: int = 120) -> ExecutionEvidence:
    """Test caller-supplied passwords for one username on an authorized service."""
    if not username or username.startswith("-") or "\x00" in username:
        raise ValueError("invalid username")
    words = _wordlist(password_list_inline)
    argv = ["sh", "-c", 'cat > /tmp/passwords; exec hydra "$@"', "hydra",
            "-l", username, "-P", "/tmp/passwords", "-t", "4", "-f", "-s", str(_port(port)),
            "{target_ip}", service]
    return provider.run_sandboxed(argv, target, [port], allow_private=allow_private,
                                  timeout_s=timeout_s, stdin_text=words).evidence()


@mcp.tool()
@threaded
def sqlmap_scan(url: str, target_host: str, port: int, allow_private: bool = False,
                timeout_s: int = 180) -> ExecutionEvidence:
    """Check one authorized HTTP URL for SQL injection and retrieve its DB banner."""
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or parsed.hostname != target_host.lower() or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("URL must be HTTP(S), match target_host, and have no credentials or fragment")
    if (parsed.port or (443 if parsed.scheme == "https" else 80)) != _port(port):
        raise ValueError("URL port must match port")
    pinned = urlunsplit((parsed.scheme, "{target_ip}:" + str(port), parsed.path or "/", parsed.query, ""))
    argv = ["sqlmap", "-u", pinned, "--host", parsed.netloc, "--batch", "--banner",
            "--technique=BEU", "--timeout=10", "--retries=0", "--ignore-redirects",
            "--output-dir=/tmp/sqlmap", "--flush-session"]
    return provider.run_sandboxed(argv, target_host, [port], allow_private=allow_private,
                                  timeout_s=timeout_s).evidence()


@mcp.tool()
@threaded
def nikto_scan(target: str, port: int = 80, allow_private: bool = False, timeout_s: int = 60) -> ExecutionEvidence:
    """Check an authorized HTTP service with Nikto."""
    argv = ["nikto", "-h", f"http://{{target_ip}}:{_port(port)}", "-vhost", target,
            "-nocheck", "-nointeractive", "-ask", "no", "-maxtime", str(max(1, timeout_s - 5))]
    return provider.run_sandboxed(argv, target, [port], allow_private=allow_private,
                                  timeout_s=timeout_s).evidence()


@mcp.tool()
@threaded
def gobuster_dir(target: str, port: int = 80, wordlist_inline: str = "admin\nbackup\n",
                 allow_private: bool = False, timeout_s: int = 60) -> ExecutionEvidence:
    """Find paths on an authorized HTTP service using caller-supplied words."""
    words = _wordlist(wordlist_inline)
    argv = ["sh", "-c", 'cat > /tmp/words; exec gobuster "$@"', "gobuster", "dir",
            "-u", f"http://{{target_ip}}:{_port(port)}", "-H", f"Host: {target}",
            "-w", "/tmp/words", "-q", "-t", "4", "--no-progress"]
    return provider.run_sandboxed(argv, target, [port], allow_private=allow_private,
                                  timeout_s=timeout_s, stdin_text=words).evidence()


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True,idempotentHint=True,openWorldHint=False))
@threaded
def nuclei_templates(query: str = "", severity: list[str] | None = None, tags: list[str] | None = None,
                     offset: int = 0, limit: int = 25) -> dict:
    """Discover pinned HTTP Nuclei template IDs, names, severities and tags on the server."""
    return nuclei.search(query,severity,tags,offset,limit)


@mcp.tool()
@threaded
def nuclei_scan(url: str, template_ids: list[str] | None = None, template_yaml: str | None = None,
                rate_limit: int = 10, concurrency: int = 2, timeout_s: int = 180,
                headers: dict[str,str] | None = None) -> JobStatus:
    """Queue an HTTP Nuclei scan with up to 32 selected template IDs or an inline HTTP template.

    Poll kali_job_result for exit code, parsed findings.nuclei and the JSONL report.
    Target DNS is pinned; redirects, OAST and runtime updates are disabled. HTTP
    templates only; no code/headless/network templates. Rate limit is 1–50 req/s.
    """
    return nuclei.submit(url=url,template_ids=template_ids,template_yaml=template_yaml,
                         rate_limit=rate_limit,concurrency=concurrency,timeout_s=timeout_s,headers=headers)


@mcp.tool()
@threaded
def metasploit_open(target: str | None = None, ports: str = "80,443", udp_ports: str = "",
                    memory_mb: int = 1536, lease_s: int = 600) -> MetasploitWorkspace:
    """Queue an isolated Metasploit RPC workspace and return its secret workspace ID.

    Poll metasploit_status until ready. Network is off unless one public target
    and its TCP/UDP ports are declared. The 60–600 second lease includes startup;
    reserved memory counts against the global budget until closed or expired.
    RPC runs inside the worker, with no published RPC port and no msfconsole argv.
    """
    return metasploit.open_workspace(target,ports,udp_ports,memory_mb,lease_s)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True,idempotentHint=True,openWorldHint=False))
@threaded
def metasploit_status(workspace_id: str) -> MetasploitWorkspace:
    """Get RPC readiness, version, job state and lease expiry for your workspace."""
    return metasploit.status(workspace_id)


@mcp.tool()
@threaded
def metasploit_rpc(workspace_id: str, method: str, params: list[Any] | None = None,
                   offset: int = 0, limit: int = 100, timeout_s: int = 30) -> MetasploitResponse:
    """Call Metasploit's MessagePack RPC API in an existing workspace; no console argv parsing.

    Examples: core.version []; module.info ['auxiliary','scanner/http/http_version'];
    module.options ['auxiliary','scanner/http/http_version']; module.execute
    ['auxiliary','scanner/http/http_version',{'RHOSTS':'TARGET','RPORT':443,'SSL':true}];
    job.list []; session.list []. Module jobs/sessions belong only to this workspace.
    params excludes the internal RPC token. Large results are paginated or retained
    as artifacts. Database methods need a configured DB; no DB/listeners are exposed.
    """
    return metasploit.rpc(workspace_id,method,params,offset,limit,timeout_s)


@mcp.tool()
@threaded
def metasploit_close(workspace_id: str) -> MetasploitWorkspace:
    """Request workspace shutdown, cancelling its job and removing its container and network rules."""
    return metasploit.close_workspace(workspace_id)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False))
@threaded
def kali_search(query: str = "", offset: int = 0, limit: int = 25) -> dict:
    """Discover installed Kali packages and executable commands by name or purpose.

    Search runs on the MCP server's live image catalog. Paginate with next_offset;
    no per-package configuration is needed in the MCP client.
    """
    return {"image": provider.IMAGE, **catalog.search(query, offset, limit)}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False))
@threaded
def kali_command_info(command: str) -> dict:
    """Find an installed command's package, version and executable paths before running it."""
    info = catalog.command_info(command)
    image = checks.image_id()
    info["validation"] = next((row for row in runtime.validations(image)
                               if row["command"] == command.rsplit("/", 1)[-1]),
                              {"level": "installed", "passed": None, "note": "No recorded runtime check for this image"})
    return info


@mcp.tool()
@threaded
def kali_run(command: str, args: list[str] | None = None, target: str | None = None,
             ports: str = "80,443", timeout_s: int = 120, memory_mb: int = 512,
             needs_net_raw: bool = False, stdin_text: str | None = None, udp_ports: str = "",
             artifact_paths: list[str] | None = None) -> ExecutionEvidence:
    """Run any installed Kali command discovered through kali_search/command_info.

    Args are an argv array, not a shell command. Network is disabled by default.
    For network tools declare one target and TCP ports/udp_ports, and use {target_ip}
    inside args for the pinned target address. stdin_text supplies input data.
    Retain explicit regular files below /tmp using artifact_paths (8 MiB per file,
    24-hour retention). Output and process exit code are returned as evidence. GUI applications and
    tools needing physical radio/GPU devices or persistent services may require
    infrastructure beyond this headless, ephemeral container executor.
    """
    if stdin_text is not None and len(stdin_text.encode()) > 65536:
        raise ValueError("stdin_text is limited to 64 KiB")
    if args and (len(args) > 256 or sum(len(arg.encode()) for arg in args) > 65536):
        raise ValueError("args are limited to 256 items and 64 KiB")
    if needs_net_raw and target is None:
        raise ValueError("needs_net_raw requires a declared network target")
    argv = [catalog.executable(command), *(args or [])]
    return provider.run_sandboxed(argv, target or "offline", parse_ports(ports) if target and ports else [],
        network_mode="allowlist" if target else "none", timeout_s=timeout_s,
        memory_mb=memory_mb, extra_caps=["NET_RAW"] if needs_net_raw else [],
        stdin_text=stdin_text, target_udp_ports=parse_ports(udp_ports) if target and udp_ports else [],
        artifact_paths=artifact_paths).evidence()


@mcp.tool()
@threaded
def kali_submit(command: str, args: list[str] | None = None, target: str | None = None,
                ports: str = "80,443", timeout_s: int = 120, memory_mb: int = 512,
                needs_net_raw: bool = False, stdin_text: str | None = None,
                udp_ports: str = "", artifact_paths: list[str] | None = None) -> JobStatus:
    """Queue a durable background kali_run job. Keep the returned secret ID.

    Poll kali_job_status; retrieve evidence with kali_job_result; stop work using
    kali_job_cancel. Jobs survive client disconnects and expire after 24 hours.
    Execution errors after submission appear in job status or command evidence.
    """
    catalog.executable(command)
    if not 1 <= timeout_s <= 600 or not 128 <= memory_mb <= min(2048, runtime.limits()["memory_mb"]):
        raise ValueError("Invalid timeout or memory budget")
    if args and (len(args) > 256 or sum(len(arg.encode()) for arg in args) > 65536):
        raise ValueError("args are limited to 256 items and 64 KiB")
    if stdin_text is not None and len(stdin_text.encode()) > 65536:
        raise ValueError("stdin_text is limited to 64 KiB")
    if needs_net_raw and target is None:
        raise ValueError("needs_net_raw requires a target")
    if target:
        provider.resolve_target(target, False)
        if ports:
            parse_ports(ports)
        if udp_ports:
            parse_ports(udp_ports)
        if not ports and not udp_ports:
            raise ValueError("Declare TCP or UDP ports")
    provider.validate_artifact_paths(artifact_paths or [])
    return runtime.submit("run", dict(command=command, args=args, target=target, ports=ports,
                          timeout_s=timeout_s, memory_mb=memory_mb, needs_net_raw=needs_net_raw,
                          stdin_text=stdin_text, udp_ports=udp_ports, artifact_paths=artifact_paths))


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False))
@threaded
def kali_job_status(job_id: str) -> JobStatus:
    """Get state and progress for your secret job ID; does not enumerate others' jobs."""
    return runtime.job_status(job_id)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False))
@threaded
def kali_job_result(job_id: str) -> JobStatus:
    """Retrieve completed command evidence or self-test results; pending jobs return result=null."""
    return runtime.job_status(job_id, include_result=True)


@mcp.tool()
@threaded
def kali_job_cancel(job_id: str) -> JobStatus:
    """Cancel a queued job or request that a running job stop and remove its worker."""
    return runtime.cancel_job(job_id)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False))
@threaded
def kali_health() -> dict:
    """Report image identity, installed counts, recorded test levels, queue load and orphan cleanup."""
    return checks.health()


@mcp.tool()
@threaded
def kali_self_test(commands: list[str] | None = None) -> JobStatus:
    """Queue known startup/functional checks on offline fixtures; poll the returned job ID.

    Defaults test nmap, hydra, sqlmap, nikto, gobuster, john, nuclei, ffuf, hashcat,
    whatweb, tshark, dumpcap, searchsploit, java. msfrpcd is opt-in (RPC startup).
    Successful functional checks verify fixture-specific evidence, not just exit codes.
    """
    return runtime.submit("selftest", {"commands": checks.validate_commands(commands)})


@mcp.resource("kali://artifacts/{artifact_id}", mime_type="application/octet-stream")
@threaded
def kali_artifact(artifact_id: str) -> bytes:
    """Read a retained artifact using its unguessable ID before its expiry."""
    return runtime.read_artifact(artifact_id)[1]


@mcp.resource("kali://catalog")
@threaded
def kali_catalog_summary() -> dict:
    """Current worker image and dynamically discovered package inventory size."""
    packages = catalog.packages()
    return {"image": provider.IMAGE, "installed_packages": len(packages),
            "executables": len({path for package in packages for path in package["executables"]}),
            "everything_installed": any(p["name"] == "kali-linux-everything" for p in packages)}


import native_tasks
native_tasks.install(mcp, kali_submit.__wrapped__)


if __name__ == "__main__":
    mcp.run(transport="stdio")
