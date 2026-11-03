# Kali MCP

Remote Kali Linux tools for MCP-compatible agents, served over HTTPS.
Use the public server at **https://kali.khosa.co:9443/mcp**, or
[self-host your own instance](#self-host-your-own-server) using this repository.
The public server is available for users and agents without an account or API key.

The active Docker image includes `kali-linux-everything` (4,374 installed
packages at initial deployment). Each execution creates and removes a fresh
Kali container. Agents discover packages on the server without maintaining a
hardcoded package list.

## Use the public MCP server

Public Streamable HTTP endpoint: **https://kali.khosa.co:9443/mcp**.
No authentication, token, SSH connection, or local Kali installation is required.
Use the complete URL, including port `9443` and path `/mcp`.
This is an MCP API endpoint; opening it in a browser does not display a website.

For clients using an `mcpServers` configuration:

```json
{
  "mcpServers": {
    "kali": {
      "url": "https://kali.khosa.co:9443/mcp"
    }
  }
}
```

For a client with an "Add MCP server" form, choose remote HTTP / Streamable HTTP,
enter the endpoint above, and leave authentication unset. Clients must support
Streamable HTTP; an SSE-only client is not sufficient. Allow up to 650 seconds
for tool requests if the client offers a request-timeout setting, since commands
can run for up to 600 seconds.

[mcp-http-config.example.json](mcp-http-config.example.json) shows the client
configuration. Codex discovers tools through MCP's `tools/list`; only the server
URL belongs in client configuration. Package and command discovery is provided
by the MCP server through `kali_search`, `kali_command_info`, and `kali_run`.
The HTTPS service starts
automatically at boot, with automatic certificate renewal on HTTPS port 9443.

## Instructions for connecting agents

1. Initialize an MCP session at the endpoint and request `tools/list`.
2. Call `kali_search` with a package name or purpose to discover installed tools.
   Follow `next_offset` to paginate results. Read `kali://catalog` for the current
   image and installed-package count.
3. Call `kali_command_info` with the command name to inspect its package,
   version, and executable paths.
4. Execute it with `kali_run`, passing arguments as a JSON array. Inspect
   `exit_code`, `timed_out`, `stdout`, and `stderr` to determine success.
   An MCP response alone does not mean the command succeeded.

Example tool calls for a connection check:

```json
{"name": "kali_search", "arguments": {"query": "nmap"}}
{"name": "kali_command_info", "arguments": {"command": "nmap"}}
{"name": "kali_run", "arguments": {"command": "nmap", "args": ["--version"], "timeout_s": 30}}
```

These are MCP `tools/call` parameter examples, not standalone HTTP request bodies.
The MCP client handles initialization, headers, and JSON-RPC transport.

Available MCP tools:

| Tool | Purpose |
| --- | --- |
| `kali_search` | Search the installed package and command catalog. |
| `kali_command_info` | Look up a command's package, version, and paths. |
| `kali_run` | Execute a discovered command with an argument array. |
| `kali_submit` | Queue a background execution and return its job ID. |
| `kali_job_status` | Check a job's state and progress. |
| `kali_job_result` | Retrieve retained execution evidence. |
| `kali_job_cancel` | Cancel queued or running work. |
| `kali_health` | Inspect image identity, queue load, and recorded test coverage. |
| `kali_self_test` | Queue startup and functional checks on offline fixtures. |
| `nmap_scan` | Scan TCP ports on one target. |
| `hydra_bruteforce` | Test supplied passwords for one username and service. |
| `sqlmap_scan` | Check an HTTP URL for SQL injection. |
| `nikto_scan` | Check an HTTP service with Nikto. |
| `gobuster_dir` | Find HTTP paths using a supplied word list. |

Network access is disabled by default for `kali_run`. For an authorized network
task, declare one public `target` and the required TCP `ports` and/or `udp_ports`.
Use `{target_ip}` in command arguments for the server-resolved address. Run tools
only against systems you own or have permission to test. Installed GUI programs,
physical-device tools, and persistent services may need additional infrastructure.

## Discovery and readiness

Search ranks exact command matches before package and description matches.
`kali_command_info` includes server-owned execution guidance where available:
examples, suggested memory, network requirements, timeouts, and limitations.
Unprofiled commands remain discoverable and executable; their guidance explicitly
reports unknown requirements. No package definitions belong in client configuration.

`kali_health` distinguishes installation from recorded startup and functional
checks. Records are tied to the actual Docker image ID and include timestamps;
rebuilding the image does not inherit an older image's readiness claims.
`kali_self_test` runs six functional fixtures (Nmap, Hydra, SQLMap, Nikto,
Gobuster, John) and seven startup checks by default. Metasploit startup is opt-in
with `{"commands":["msfconsole"]}`. Tests use disposable, network-disabled
workers. A successful check covers its particular fixture, not every command mode.

## Background jobs and execution queue

Use `kali_submit` for long commands or busy periods. It accepts the same execution
arguments as `kali_run` and immediately returns a job ID. Call `kali_job_status`
with `{"job_id":"RETURNED_ID"}`, respect `poll_after_s`, and retrieve evidence
with `kali_job_result`. Use `kali_job_cancel` to stop queued or running work.
There is no public job listing; retain your unguessable ID to retrieve your result.

Jobs and results are stored in SQLite for 24 hours. They survive client
disconnects. Queued jobs survive a service restart, and completed results remain
retrievable. Work interrupted by a process crash is marked failed and is never
automatically repeated; resubmit explicitly if appropriate. A completed job means
execution finished: inspect the result's `exit_code` and `timed_out` too.

The server also supports native Tasks from MCP **2025-11-25** for `kali_run`:
request task augmentation using `params.task`, then use `tasks/get`,
`tasks/result`, and `tasks/cancel`. The tool advertises `taskSupport: optional`.
Clients without that capability use the portable job tools above. The separate
draft `io.modelcontextprotocol/tasks` extension is not advertised.

Execution admission is FIFO with at most two running containers and a combined
2,048 MiB of declared memory. A 2,048 MiB command runs alone. Discovery and job
status do not consume execution slots. The queue admits 32 waiting executions;
background work also has a 32-job outstanding limit and a 1,000-job retention
limit. A synchronous queue wait expires after 1,200 seconds, separately from
the command timeout. Prefer background jobs when the queue is busy.

## Results and report artifacts

Execution tools publish an explicit output schema. Existing argv, stdout,
stderr, exit code, timeout and sandbox fields remain available. New fields include
`queue_wait_ms`, `cancelled`, truncation flags, artifact references, and parsed
`findings`: Nmap ports/services, Hydra credentials, SQLMap injection types,
Gobuster paths/status codes, and Nikto observations. Parsing is a summary;
raw output remains the evidence and unsupported formats can have empty findings.

To retain a generated report, pass explicit `artifact_paths` to `kali_run` or
`kali_submit`, for example `["/tmp/report.json"]`. Only regular files below `/tmp`
are accepted, with at most ten paths and 8 MiB per file. Directories, links and
oversized files are rejected with `artifact_errors`; command results are still
returned. No container filesystem is extracted onto the host.

Artifacts expire after 24 hours and share a 1 GiB storage budget. Each reference
includes its size, SHA-256, expiry, an HTTPS download URL, and an MCP resource URI
(`kali://artifacts/ID`). Downloads require no authentication; anyone with the
unguessable URL or ID can retrieve the file before expiry. Do not publish IDs for
reports you intend to keep private. Output above 64 KiB per stream is truncated
inline and retained as a separate artifact when storage permits; the output hash
covers the full captured streams. Docker's existing bounded log retention still applies.

The service checks every 30 seconds for expired data and registered orphan
workers. It removes containers before their firewall rules. Cleanup only targets
registered Kali workers whose owner died or whose previous cleanup failed.

## Access limits

HTTP callers cannot enable private-network scanning, even by
passing `allow_private=true`. Requests use TLS, have a
128 KiB body limit, and the HTTP worker accepts at most 64 concurrent
connections. Execution concurrency is controlled separately by the queue.
Host and Origin headers are checked against the configured domain.
Agents connect through HTTP only. SSH is used for host administration and deployment.

## Self-host your own server

Use a dedicated Linux host with root access, systemd, Python 3.12+, rootful Docker
Engine with Buildx, and the iptables `DOCKER-USER` chain. Debian 13 is the tested
host platform. The wrapper runs on the host and creates disposable Kali worker
containers; it is not a single Docker Compose service.

You also need `git`, `python3-venv`, `iptables`, `ebtables`, `iproute2`, `kmod`,
and `util-linux`. Point a DNS hostname at the host. Permit inbound TCP 9443 for
MCP and TCP 80 for certificate issuance and renewal. Port 80 must be free when
Certbot's standalone challenge runs. Leave sufficient RAM for the host in
addition to the default 2 GiB worker budget.

Run as root after installing the prerequisites:

```sh
git clone https://github.com/Dankular/Kali-MCP.git /opt/kali-mcp
cd /opt/kali-mcp

# Enable and persist bridge firewall processing.
modprobe br_netfilter
printf 'br_netfilter\n' > /etc/modules-load.d/kali-mcp.conf
printf 'net.bridge.bridge-nf-call-iptables=1\n' > /etc/sysctl.d/90-kali-mcp.conf
sysctl -p /etc/sysctl.d/90-kali-mcp.conf

# Build the smaller core-tools image and install the Python runtime.
sh deploy.sh

# Replace this hostname with your own DNS name.
sh deploy-http.sh mcp.example.com
```

Your MCP URL is then **`https://mcp.example.com:9443/mcp`**. In the client
configuration above, replace the public URL with your own endpoint. This setup
also runs without authentication. `deploy-http.sh` configures TLS, the domain
checks, artifact download URLs, automatic startup, and certificate renewal.

To install the full `kali-linux-everything` package set:

```sh
cd /opt/kali-mcp
sh build-everything.sh
sh activate-everything.sh
```

The full build requires at least **85 GiB free disk space** before it starts and
can take hours. Start with the smaller image to validate the host first. The
existing HTTP service stays available while the full image builds; activation
switches the image and package catalog together.

Check the deployment with `systemctl status kali-mcp-http`, `GET /healthz`, and
the `kali_health` MCP tool. Run `kali_self_test` to validate supported commands
against disposable offline fixtures. Keep `/opt/kali-mcp/state` across upgrades
to retain background jobs, reports, and health records until their expiry.

## Deploy source updates from Windows

On Windows with PuTTY and tar installed:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy.ps1 -Server root@YOUR_HOST -Key C:\path\to\key.ppk -HostKey "SHA256:YOUR_HOST_FINGERPRINT"
# Add -SkipBuild to upload source changes without rebuilding the image.
```

Files install under `/opt/kali-mcp`. `deploy.sh` creates a Python virtual
environment and builds `kali-mcp:1` using `docker/Dockerfile.mcp`.
The server pins MCP SDK 1.27.2, using FastMCP's Streamable HTTP API.

To provision HTTPS on the host, run `sh deploy-http.sh kali.khosa.co` after the
base deployment. DNS must point at this server and port 80 must be free for
certificate challenges. The script installs a separate Certbot environment,
obtains the certificate, writes `http.env`, and enables the HTTP service and
twice-daily certificate-renewal timer. For code updates, upload with `-SkipBuild`
and run `systemctl restart kali-mcp-http`. The service runs the Python wrapper
on the host and invokes the existing per-call Docker worker.

The full toolset is built with `sh build-everything.sh` using
`docker/Dockerfile.everything`, which installs `kali-linux-everything` and its
recommended dependencies. The build exports an installed-package/executable
catalog from the image. Run `sh activate-everything.sh` after the full build is
ready to select the full image and its matching catalog and restart the service.
`kali://catalog` reports the active image, inventory counts, and whether the
everything metapackage is installed. The full build does not stop the live API.
Explicit image and catalog environment settings take precedence over defaults.

Install `kali-mcp-workers.slice` in `/etc/systemd/system/` and set
`MCP_KALI_CGROUP_PARENT=kali-mcp-workers.slice` to cap the aggregate Docker worker
budget at 2 GiB RAM, 512 MiB swap, two CPU cores, and 1024 processes.

Runtime state lives in `/opt/kali-mcp/state` (directory mode 0700). Keep this
directory across source deployments. Optional environment settings include:

| Setting | Default |
| --- | --- |
| `MCP_KALI_STATE_DIR` | `/opt/kali-mcp/state` |
| `MCP_KALI_MAX_RUNNING` | `2` |
| `MCP_KALI_MEMORY_BUDGET_MB` | `2048` |
| `MCP_KALI_MAX_QUEUED` | `32` |
| `MCP_KALI_QUEUE_TIMEOUT_S` | `1200` |
| `MCP_KALI_MAX_RETAINED_JOBS` | `1000` |
| `MCP_KALI_ARTIFACT_MAX_BYTES` | `8388608` |
| `MCP_KALI_ARTIFACT_BUDGET_BYTES` | `1073741824` |
| `MCP_KALI_PUBLIC_URL` | `https://kali.khosa.co:9443` |

Keep the admission budget at or below the aggregate systemd worker budget.
`GET /healthz` is a lightweight HTTP readiness view; detailed checks are in
`kali_health`. Self-tests are explicit background jobs, not automatic package scans.

## Tool behavior

- Targets are single IPv4 addresses or DNS hostnames, resolved once and pinned
  in both scanner arguments and firewall rules. IPv6 is not supported.
- Public HTTP calls reject private targets, including with `allow_private=true`.
  Loopback, link-local/metadata, multicast, unspecified, and reserved remote
  addresses are always rejected.
- Nmap supports TCP connect and SYN scans, inclusive ranges, and at most 4096
  ports per call. SYN calls get only the additional `NET_RAW` capability.
- Hydra takes one username and an inline password list. Gobuster takes an
  inline path list. Lists are limited to 64 KiB and passed as data over stdin.
- SQLMap validates the URL against the declared host and port. Its fixed
  options check boolean, error, and UNION injection and retrieve the database
  banner. Time-based and stacked-query probes are excluded, and arbitrary
  SQLMap flags are outside this small API.
- Tools return structured evidence: executed argv, actual process exit code,
  stdout/stderr, duration, resolved IP, ports, sandbox settings, and output hash.
  Timeouts return `exit_code=124` and `timed_out=true`; validation failures
  return MCP tool errors. The maximum runtime is 600 seconds.
- `kali_search` searches the installed package catalog with pagination.
  `kali_command_info` finds a command's package, version and executable paths.
  `kali_run` runs any discovered executable with an argv array and optional
  stdin data. Its default network is `none`; for network tools declare a target
  and TCP `ports` and/or `udp_ports`, using `{target_ip}` in arguments to pin DNS.
  Per-call RAM is configurable from 128 to 2048 MiB. GUI, radio, GPU and
  persistent-service requirements still depend on available infrastructure.

## Execution boundary

Workers use a read-only root, bounded `/tmp` tmpfs, no-new-privileges, dropped
capabilities, and memory, CPU, PID, and Docker log limits. No Docker socket or
host paths are mounted into workers. A fixed bootstrap waits while the host
attaches a firewall chain to the worker's physical veth interface. The chain
allows only the worker's assigned source IP and declared target's TCP/UDP ports,
then drops everything else. This also blocks source-IP spoofing with `NET_RAW`.
Bridge-layer rules bind the worker's MAC and ARP source address and reject IPv6,
VLAN, and other unsupported frame types before the command starts.
Workers use a container-local DNS setting rather than Docker's host-side DNS
forwarding. The wrapper resolves declared targets; tools can query a declared
DNS server directly when its UDP/TCP ports are allowlisted.
Persistent bridge rules in `DOCKER-USER` and `INPUT` block other forwarding and
access to the Docker host. Containers
are removed before per-call rules are removed; the fallback subnet drop remains.

This requires rootful Docker with an IPv4 bridge, ebtables, the iptables `DOCKER-USER`
chain, and `net.bridge.bridge-nf-call-iptables=1`. Do not point
`MCP_KALI_SCAN_NETWORK` at a shared application network: its subnet receives
default-deny rules. `MCP_KALI_IMAGE` can override the worker image.
After a host/Docker restart, rules are rechecked before the next scan.
Abruptly killing the wrapper can leave a worker and its rules until the runtime
reaper detects the dead owner; declared target/port access remains until cleanup.
The wrapper needs host administrative access to manage Docker and firewall
rules. Commands execute inside disposable containers without the Docker socket
or host mounts. Containers share the host kernel and do not provide a VM boundary.

## Validate the service

Call `kali_health` through MCP to inspect readiness, image identity, queue load,
and recorded checks. Call `kali_self_test` to queue the functional and startup
checks described above, then poll its job ID with `kali_job_result`.

A client connection check should initialize the session, list all 14 tools, and
execute `kali_run` with `{"command":"nmap","args":["--version"]}`.
Check the returned `exit_code` rather than assuming every MCP response means success.

The runtime self-check implementation is kept in `mcp-kali/checks.py`. Historical
PoC files, disposable lab targets, and ad hoc validation scripts are not shipped.
