"""Reversible 443 routing to the SNI edge without changing existing listeners."""
import ipaddress
import os
import subprocess
import sys

PUBLIC_IP = str(ipaddress.IPv4Address(os.environ["KALI_MCP_EDGE_PUBLIC_IP"]))
PORT = int(os.environ.get("KALI_MCP_EDGE_PORT", "10443"))
if not 1024 <= PORT <= 65535:
    raise ValueError("Invalid edge listener port")
NAT, FILTER = "KMCPEDGE443", "KMCPEDGEIN"


def ipt(table, *args, check=True):
    return subprocess.run(["iptables", "-w", "10", "-t", table, *args], check=check,
                          stdout=subprocess.DEVNULL, stderr=None if check else subprocess.DEVNULL)


def remove():
    for chain in ("PREROUTING", "OUTPUT"):
        rule = ("-d", PUBLIC_IP, "-p", "tcp", "--dport", "443", "-j", NAT)
        while ipt("nat", "-C", chain, *rule, check=False).returncode == 0:
            ipt("nat", "-D", chain, *rule)
    rule = ("-p", "tcp", "--dport", str(PORT), "-j", FILTER)
    while ipt("filter", "-C", "INPUT", *rule, check=False).returncode == 0:
        ipt("filter", "-D", "INPUT", *rule)
    for table, chain in (("nat", NAT), ("filter", FILTER)):
        if ipt(table, "-S", chain, check=False).returncode == 0:
            ipt(table, "-F", chain)
            ipt(table, "-X", chain)


def install():
    remove()
    try:
        ipt("filter", "-N", FILTER)
        ipt("filter", "-A", FILTER, "-i", "lo", "-j", "ACCEPT")
        ipt("filter", "-A", FILTER, "-p", "tcp", "-m", "conntrack", "--ctorigdstport", "443", "-j", "ACCEPT")
        ipt("filter", "-A", FILTER, "-j", "DROP")
        # Append after existing host/worker isolation rules, never override them.
        ipt("filter", "-A", "INPUT", "-p", "tcp", "--dport", str(PORT), "-j", FILTER)
        ipt("nat", "-N", NAT)
        ipt("nat", "-A", NAT, "-p", "tcp", "-j", "REDIRECT", "--to-ports", str(PORT))
        for chain in ("OUTPUT", "PREROUTING"):
            ipt("nat", "-I", chain, "1", "-d", PUBLIC_IP, "-p", "tcp", "--dport", "443", "-j", NAT)
    except BaseException:
        remove()
        raise


if __name__ == "__main__":
    if sys.argv[1:] == ["install"]:
        install()
    elif sys.argv[1:] == ["remove"]:
        remove()
    else:
        raise SystemExit("Usage: edge-firewall.py install|remove")
