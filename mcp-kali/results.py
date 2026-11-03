"""Explicit MCP output schemas and conservative parsers for common CLI output."""
from __future__ import annotations

import re
import json
from typing import Any
from typing import Literal
from pydantic import BaseModel, Field


class PortFinding(BaseModel):
    port: int
    protocol: str
    state: str
    service: str | None = None


class PathFinding(BaseModel):
    path: str
    status: int


class CredentialFinding(BaseModel):
    service: str
    host: str
    username: str
    password: str


class NucleiFinding(BaseModel):
    template_id: str
    name: str
    severity: str
    matched_at: str
    protocol: str | None = None
    matcher_name: str | None = None
    extracted_results: list[str] = Field(default_factory=list)


class Findings(BaseModel):
    parser: str | None = None
    ports: list[PortFinding] = Field(default_factory=list)
    paths: list[PathFinding] = Field(default_factory=list)
    credentials: list[CredentialFinding] = Field(default_factory=list)
    injection_types: list[str] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)
    nuclei: list[NucleiFinding] = Field(default_factory=list)
    note: str = "Parsed fields are a summary; consult raw output for complete evidence."


class Artifact(BaseModel):
    id: str
    name: str
    size: int
    sha256: str
    created: float
    expires: float
    uri: str
    url: str


class ExecutionEvidence(BaseModel):
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    target_host: str
    target_ip_resolved: str
    allowed_ports: list[int]
    allowed_udp_ports: list[int] = Field(default_factory=list)
    sandbox: dict
    timed_out: bool = False
    cancelled: bool = False
    output_sha256: str
    queue_wait_ms: int = 0
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    findings: Findings = Field(default_factory=Findings)
    artifacts: list[Artifact] = Field(default_factory=list)
    artifact_errors: list[str] = Field(default_factory=list)


class JobStatus(BaseModel):
    id: str
    kind: str
    state: Literal["queued", "running", "completed", "failed", "cancelled"]
    created: float
    updated: float
    expires: float
    progress: str | None = None
    error: str | None = None
    cancel_requested: bool
    poll_after_s: int
    result: dict | None = None


class MetasploitWorkspace(BaseModel):
    workspace_id: str
    job: JobStatus
    ready: bool = False
    phase: str
    lease_expires: float | None = None
    version: dict | None = None
    startup_detail: str | None = None
    transport: str = "MessagePack RPC over container-local HTTP"


class MetasploitResponse(BaseModel):
    workspace_id: str
    method: str
    result: Any
    error: bool = False
    total: int | None = None
    next_offset: int | None = None
    truncated: bool = False
    artifact: Artifact | None = None


def parse_findings(stdout, argv):
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", stdout)
    command = next((name for name in ("nmap", "hydra", "sqlmap", "nikto", "gobuster", "nuclei")
                    if any(arg.rsplit("/", 1)[-1] == name for arg in argv)), None)
    result = Findings(parser=command)
    if command == "nmap":
        for match in re.finditer(r"(?m)^(\d+)/(tcp|udp)\s+(\S+)\s*(\S*)", text):
            result.ports.append(PortFinding(port=int(match[1]), protocol=match[2], state=match[3], service=match[4] or None))
    elif command == "hydra":
        pattern = r"\[\d+\]\[([^]]+)\]\s+host:\s+(\S+)\s+login:\s+(.*?)\s+password:\s*(.*)"
        for match in re.finditer(pattern, text):
            result.credentials.append(CredentialFinding(service=match[1], host=match[2], username=match[3], password=match[4].rstrip()))
    elif command == "gobuster":
        for match in re.finditer(r"(?m)^(/?\S+)\s+\(Status:\s*(\d{3})\)", text):
            result.paths.append(PathFinding(path="/" + match[1].lstrip("/"), status=int(match[2])))
    elif command == "sqlmap":
        result.injection_types = list(dict.fromkeys(re.findall(r"(?m)^\s*Type:\s*(.+)$", text)))
    elif command == "nikto":
        result.observations = [line[2:] for line in text.splitlines() if line.startswith("+ ")][:200]
    elif command == "nuclei":
        parsed_bytes=0
        for line in text.splitlines():
            try:
                row = json.loads(line)
                info = row.get("info", {})
                if not row.get("template-id"):
                    continue
                finding=NucleiFinding(template_id=str(row["template-id"])[:128],
                    name=str(info.get("name", ""))[:1024], severity=str(info.get("severity", "unknown")),
                    matched_at=str(row.get("matched-at", ""))[:2048], protocol=row.get("type"),
                    matcher_name=row.get("matcher-name"),
                    extracted_results=[str(value)[:512] for value in row.get("extracted-results", [])[:5]])
                parsed_bytes+=len(finding.model_dump_json().encode())
                if parsed_bytes>16000: break
                result.nuclei.append(finding)
                if len(result.nuclei) >= 100:
                    break
            except (ValueError, TypeError, AttributeError):
                continue
    return result.model_dump()
