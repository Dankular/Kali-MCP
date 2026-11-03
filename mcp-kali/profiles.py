"""Optional server-side guidance. Installed commands still come from the live catalog."""
PROFILES = {
    "nmap": {"purpose": "TCP port and service discovery", "examples": [["--version"], ["-sT", "-n", "-Pn", "-p", "80,443", "{target_ip}"]], "memory_mb": 512, "network": "Target and ports required for remote scans", "limitations": ["SYN scanning requires needs_net_raw=true"]},
    "hydra": {"purpose": "Password testing for an authorized service", "examples": [["-h"]], "memory_mb": 512, "network": "Target and service port required", "limitations": ["Help exits with status 255; prefer hydra_bruteforce for inline password lists"]},
    "sqlmap": {"purpose": "HTTP SQL injection testing", "examples": [["--version"]], "memory_mb": 512, "network": "Target and HTTP port required", "limitations": ["Declare one target; use sqlmap_scan for the typed HTTP interface"]},
    "nikto": {"purpose": "HTTP server checks", "examples": [["-Version"]], "memory_mb": 512, "network": "Target and HTTP port required", "limitations": ["Large check sets may require a longer timeout"]},
    "gobuster": {"purpose": "HTTP path discovery", "examples": [["--version"]], "memory_mb": 512, "network": "Target and HTTP port required", "limitations": ["Use --version, not the version subcommand"]},
    "ffuf": {"purpose": "HTTP fuzzing and content discovery", "examples": [["-V"]], "memory_mb": 512, "network": "Target and HTTP port required", "limitations": []},
    "hashcat": {"purpose": "Offline password hash recovery", "examples": [["--version"]], "memory_mb": 1024, "network": "Offline", "limitations": ["GPU is not passed through; compute backend availability varies"]},
    "john": {"purpose": "Offline password hash recovery", "examples": [["--list=build-info"]], "memory_mb": 512, "network": "Offline", "limitations": []},
    "msfconsole": {"purpose": "Metasploit console", "examples": [["-q", "-x", "version; exit -y"]], "memory_mb": 2048, "timeout_s": 360, "network": "Offline startup; declare target and ports for remote use", "limitations": ["Cold startup can take several minutes", "No persistent database or listener ports"]},
    "tshark": {"purpose": "Packet capture analysis", "examples": [["--version"]], "memory_mb": 512, "network": "Offline for saved captures", "limitations": ["No host network interface access"]},
    "dumpcap": {"purpose": "Packet capture", "examples": [["--version"]], "memory_mb": 512, "network": "Declared target only", "limitations": ["Capture requires needs_net_raw=true; no host interfaces"]},
    "whatweb": {"purpose": "HTTP technology identification", "examples": [["--version"]], "memory_mb": 512, "network": "Target and HTTP port required", "limitations": []},
    "searchsploit": {"purpose": "Search the local Exploit-DB catalog", "examples": [["--json", "example"]], "memory_mb": 512, "network": "Offline", "limitations": ["--help can exit with status 2"]},
}


def guidance(command):
    return PROFILES.get(command.rsplit("/", 1)[-1], {
        "purpose": "See installed package summary and command help",
        "examples": [], "memory_mb": 512, "network": "Unknown; networking is disabled by default",
        "limitations": ["No curated execution profile; check --help before use", "GUI, hardware and persistent services may be unavailable"],
    })
