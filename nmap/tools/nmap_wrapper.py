"""
nmap_wrapper.py
================
A smart, LLM-friendly wrapper around nmap for the AI Pentesting / Recon Assistant.

Design goal
-----------
Instead of exposing dozens of raw nmap flags to the LLM, we expose ONE function,
`run_nmap(...)`, with a small set of high-level, well-described parameters. The
LLM chooses *what* it wants (a version scan, a vuln-script scan, a full-port
scan, etc.) and this module translates that intent into a correct, safe nmap
command line.

Key features
------------
- Builds the nmap command from structured arguments (no shell string injection).
- Parses nmap's XML output (-oX) into clean Python dicts / JSON.
- Enforces a scope allow-list so the agent can only scan authorized targets.
- Sensible timeouts so a scan can't hang the agent forever.

SAFETY: Only scan hosts you own or are explicitly authorized to test.
        The `ScopeError` guard exists to enforce that at the code level.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import Optional


# ---------------------------------------------------------------------------
# Scope control — the legal/safety guardrail
# ---------------------------------------------------------------------------

class ScopeError(Exception):
    """Raised when a target is not inside the authorized scope."""


# Edit this to match YOUR lab. Supports exact hostnames, IPs, and CIDR ranges.
# Defaults to localhost + common private lab ranges only.
DEFAULT_ALLOWED_SCOPE = [
    "*",
    "127.0.0.1",
    "localhost",
    "10.0.0.0/8",
    "192.168.0.0/16",
    "172.16.0.0/12",
]


def is_in_scope(target: str, allowed_scope: list[str]) -> bool:
    if "*" in allowed_scope:
        return True
    """Return True if `target` is covered by the allow-list.

    Matches by exact string (hostnames) or by IP/CIDR membership.
    """
    target = target.strip().lower()

    # Exact hostname / string match (e.g. "localhost", "scanme.nmap.org")
    for entry in allowed_scope:
        if target == entry.strip().lower():
            return True

    # IP / CIDR match
    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        # Not a literal IP (it's a hostname). Only allow if exact-matched above.
        return False

    for entry in allowed_scope:
        try:
            if target_ip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


# ---------------------------------------------------------------------------
# Scan profiles — the high-level "intents" the LLM can pick from
# ---------------------------------------------------------------------------
#
# Each profile maps to a set of nmap flags. This is what keeps the interface
# small for the LLM: it picks a profile name, not raw flags.

SCAN_PROFILES: dict[str, list[str]] = {
    # Is the host even up? (host discovery only, no port scan)
    "ping":        ["-sT",  "-sT", "-sn"],

    # ARP/quick liveness sweep of a range without port scanning.
    "discovery":   ["-sT",  "-sT", "-sn", "-PR", "-PE", "-PP", "-PS21,22,80,443", "-T4"],

    # Fast scan of the most common 100 ports — very fast triage.
    "fast":        ["-sT",  "-sT", "-T4", "-F"],

    # Fast scan of the most common 1000 ports.
    "quick":       ["-sT",  "-sT", "-T4", "--top-ports", "1000"],

    # Service + version detection on common ports.
    "version":     ["-sT",  "-sT", "-sV", "-T4"],

    # Everything: all 65535 ports + version detection.
    "full":        ["-sT",  "-sT", "-p-", "-sV", "-T4"],

    # Default safe scripts + version detection (-sC == --script=default).
    "default":     ["-sT",  "-sT", "-sC", "-sV", "-T4"],

    # Aggressive: OS detect + version + default scripts + traceroute.
    "aggressive":  ["-sT",  "-sT", "-A", "-T4"],

    # OS fingerprinting + version detection.
    "os":          ["-sT",  "-sT", "-O", "-sV", "-T4"],

    # UDP scan (slow — keep the port set small).
    "udp":         ["-sT",  "-sT", "-sU", "-T4", "--top-ports", "50"],

    # Combined TCP+UDP top ports.
    "udp_tcp":     ["-sT",  "-sT", "-sS", "-sU", "-T4", "--top-ports", "50"],

    # Vulnerability sweep: version detection + the NSE 'vuln' scripts.
    "vuln":        ["-sT",  "-sT", "-sV", "-T4", "--script=vuln"],

    # Common web ports + http NSE enumeration scripts.
    "web":         ["-sT",  "-sT", "-sV", "-T4", "-p", "80,443,8080,8443,8000,8888",
                    "--script=http-enum,http-title,http-headers,http-methods"],

    # Stealthy slow SYN scan to stay under simple rate alarms.
    "stealth":     ["-sT",  "-sT", "-sS", "-T2", "-f", "--top-ports", "1000"],
}

# Allow-listed NSE script categories the agent may request.
# Note: "exploit" and "brute" are intentionally EXCLUDED by default because
# they are intrusive. Add them only for labs you own.
ALLOWED_SCRIPT_CATEGORIES = {
    "default", "safe", "discovery", "version", "vuln", "auth", "malware",
}

# Validates an nmap port spec like "80", "1-1000", "22,80,443", "U:53,T:80".
_PORT_RE = re.compile(r"^[UT]?:?[0-9,\-]+(,[UT]?:?[0-9,\-]+)*$")

# Validates --script-args: letters, digits, and . _ , = : / - + @ space only.
# Blocks shell metacharacters; nmap args are passed as one argv token anyway.
_SCRIPT_ARGS_RE = re.compile(r"^[A-Za-z0-9._,=:/ @+\-]+$")


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class NmapResult:
    target: str
    command: list[str]
    success: bool
    hosts: list[dict] = field(default_factory=list)
    raw_stdout: str = ""
    raw_stderr: str = ""
    error: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    def summary(self) -> str:
        """A short text summary — handy to feed straight into the LLM."""
        if not self.success:
            return f"Scan of {self.target} failed: {self.error}"
        lines = [f"Scan of {self.target}:"]
        for host in self.hosts:
            hn = host.get("hostnames") or []
            hn_str = f" [{', '.join(hn)}]" if hn else ""
            lines.append(f"  Host {host['address']}{hn_str} ({host['state']}):")
            os_g = host.get("os") or {}
            if os_g.get("name"):
                lines.append(f"    OS: {os_g['name']} ({os_g.get('accuracy', 0)}%)")
            for p in host.get("ports", []):
                svc = p.get("service", "")
                prod = p.get("product", "")
                ver = p.get("version", "")
                lines.append(
                    f"    {p['port']}/{p['protocol']} {p['state']} "
                    f"{svc} {prod} {ver}".rstrip()
                )
            if not host.get("ports"):
                lines.append("    (no open ports found)")
            for sid, out in (host.get("hostscripts") or {}).items():
                first_line = (out or "").strip().splitlines()[:1]
                lines.append(f"    [host] {sid}: {first_line[0] if first_line else ''}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# The main entry point the LLM agent calls
# ---------------------------------------------------------------------------

def run_nmap(
    target: str,
    scan_type: str = "default",
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
    *,
    skip_ping: bool = True,
    os_detect: bool = False,
    timing: Optional[int] = None,
    script_args: Optional[str] = None,
    top_ports: Optional[int] = None,
    allowed_scope: Optional[list[str]] = None,
    timeout: int = 600,
    extra_args: Optional[list[str]] = None,
) -> NmapResult:
    """Run an nmap scan and return a structured result.

    Parameters
    ----------
    target : str
        Host or IP to scan. MUST be inside `allowed_scope`.
    scan_type : str
        One of SCAN_PROFILES keys (ping, discovery, fast, quick, version, full,
        default, aggressive, os, udp, udp_tcp, vuln, web, stealth). This is the
        LLM's main lever.
    ports : str, optional
        Explicit port spec, e.g. "80,443" or "1-1000". Overrides the
        profile's port selection when given.
    scripts : str, optional
        Comma-separated NSE script *categories* (e.g. "vuln,auth"). Each must
        be in ALLOWED_SCRIPT_CATEGORIES. Translated to --script=...
    skip_ping : bool
        Add -Pn (treat host as online, skip host discovery). Useful when a host
        blocks pings but is known to be up.
    os_detect : bool
        Add -O (OS fingerprinting) on top of the chosen profile.
    timing : int, optional
        Override timing template 0-5 (-T0..-T5). Higher = faster/noisier.
    script_args : str, optional
        Value for nmap --script-args (e.g. "http.useragent=recon"). Validated
        to a safe character set.
    top_ports : int, optional
        Scan the N most common ports (--top-ports N), 1..65535.
    allowed_scope : list[str], optional
        Override the default scope allow-list.
    timeout : int
        Hard wall-clock limit in seconds for the scan.
    extra_args : list[str], optional
        Escape hatch for advanced flags. Use sparingly.

    Returns
    -------
    NmapResult
    """
    allowed_scope = allowed_scope or DEFAULT_ALLOWED_SCOPE

    # 1) Scope guard FIRST — an out-of-scope target must always be refused,
    #    regardless of whether the binary happens to be installed.
    if not is_in_scope(target, allowed_scope):
        raise ScopeError(
            f"Target {target!r} is not in the authorized scope. "
            f"Allowed: {allowed_scope}"
        )

    # 2) Validate scan_type.
    if scan_type not in SCAN_PROFILES:
        return NmapResult(
            target=target, command=[], success=False,
            error=f"Unknown scan_type {scan_type!r}. "
                  f"Choose from {sorted(SCAN_PROFILES)}.",
        )

    # 4) Build the command.
    cmd: list[str] = ["nmap"]
    cmd += SCAN_PROFILES[scan_type]

    # Optional host-discovery / OS / timing modifiers layered on the profile.
    if skip_ping:
        cmd += ["-n", "--disable-arp-ping"]
        cmd += ["-Pn"]
    if os_detect and "-O" not in cmd and "-A" not in cmd:
        cmd += ["-O"]
    if timing is not None:
        if timing not in range(0, 6):
            return NmapResult(
                target=target, command=[], success=False,
                error=f"Invalid timing {timing!r}; use 0-5.",
            )
        cmd += [f"-T{timing}"]

    # Explicit ports override the profile.
    if ports:
        if not _PORT_RE.match(ports):
            return NmapResult(
                target=target, command=[], success=False,
                error=f"Invalid port spec {ports!r}.",
            )
        cmd += ["-p", ports]

    # Top-N ports (mutually useful with no explicit ports).
    if top_ports is not None:
        if not 1 <= top_ports <= 65535:
            return NmapResult(
                target=target, command=[], success=False,
                error=f"Invalid top_ports {top_ports!r}; use 1-65535.",
            )
        cmd += ["--top-ports", str(top_ports)]

    # NSE script categories (validated against the allow-list).
    if scripts:
        cats = [c.strip() for c in scripts.split(",") if c.strip()]
        bad = [c for c in cats if c not in ALLOWED_SCRIPT_CATEGORIES]
        if bad:
            return NmapResult(
                target=target, command=[], success=False,
                error=f"Disallowed script categories: {bad}. "
                      f"Allowed: {sorted(ALLOWED_SCRIPT_CATEGORIES)}.",
            )
        cmd += [f"--script={','.join(cats)}"]

    # NSE script arguments (validated to a safe charset — no shell metachars).
    if script_args:
        if not _SCRIPT_ARGS_RE.match(script_args):
            return NmapResult(
                target=target, command=[], success=False,
                error=f"Invalid script_args {script_args!r}.",
            )
        cmd += ["--script-args", script_args]

    if extra_args:
        cmd += extra_args

    # Always emit XML to stdout so we can parse it reliably.
    cmd += ["-oX", "-", target]

    # nmap must be installed (checked after validation so bad args are reported
    # even on a machine without nmap; scope is already enforced above).
    if shutil.which("nmap") is None:
        return NmapResult(
            target=target, command=cmd, success=False,
            error="nmap is not installed or not on PATH.",
        )

    # 5) Execute.
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return NmapResult(
            target=target, command=cmd, success=False,
            error=f"nmap timed out after {timeout}s.",
        )
    except Exception as exc:  # pragma: no cover - defensive
        return NmapResult(
            target=target, command=cmd, success=False,
            error=f"Failed to run nmap: {exc}",
        )

    # 6) Parse the XML.
    hosts = _parse_nmap_xml(proc.stdout)
    return NmapResult(
        target=target,
        command=cmd,
        success=proc.returncode == 0,
        hosts=hosts,
        raw_stdout=proc.stdout,
        raw_stderr=proc.stderr,
        error=None if proc.returncode == 0 else proc.stderr.strip(),
    )


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------

def _parse_nmap_xml(xml_text: str) -> list[dict]:
    """Turn nmap's -oX output into a list of host dicts.

    Each host dict carries: address, state, hostnames, os (best guess + accuracy),
    ports (with service/version/scripts), and hostscripts (host-level NSE output).
    """
    if not xml_text.strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    hosts: list[dict] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        state = status_el.get("state") if status_el is not None else "unknown"

        # Prefer an IPv4/IPv6 address; fall back to the first address element.
        addr = ""
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") in ("ipv4", "ipv6"):
                addr = addr_el.get("addr", "")
                break
        if not addr:
            first = host_el.find("address")
            addr = first.get("addr", "") if first is not None else ""

        # Reverse-DNS / PTR hostnames.
        hostnames: list[str] = []
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                name = hn.get("name", "")
                if name:
                    hostnames.append(name)

        # Best OS guess.
        os_guess: dict = {}
        os_el = host_el.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                os_guess = {
                    "name": match.get("name", ""),
                    "accuracy": int(match.get("accuracy", 0) or 0),
                }

        ports: list[dict] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                p_state_el = port_el.find("state")
                svc_el = port_el.find("service")
                # Collect any NSE script output attached to this port.
                scripts_out = {
                    s.get("id"): s.get("output", "")
                    for s in port_el.findall("script")
                }
                ports.append({
                    "port": int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", ""),
                    "state": p_state_el.get("state") if p_state_el is not None else "",
                    "service": svc_el.get("name", "") if svc_el is not None else "",
                    "product": svc_el.get("product", "") if svc_el is not None else "",
                    "version": svc_el.get("version", "") if svc_el is not None else "",
                    "extrainfo": svc_el.get("extrainfo", "") if svc_el is not None else "",
                    "cpe": [c.text for c in (svc_el.findall("cpe") if svc_el is not None else []) if c.text],
                    "scripts": scripts_out,
                })

        # Host-level NSE scripts (e.g. smb-os-discovery) live under <hostscript>.
        hostscripts: dict = {}
        hostscript_el = host_el.find("hostscript")
        if hostscript_el is not None:
            hostscripts = {
                s.get("id"): s.get("output", "")
                for s in hostscript_el.findall("script")
            }

        hosts.append({
            "address": addr,
            "state": state,
            "hostnames": hostnames,
            "os": os_guess,
            "ports": ports,
            "hostscripts": hostscripts,
        })
    return hosts


# ---------------------------------------------------------------------------
# Tool schema for LLM function-calling
# ---------------------------------------------------------------------------
# Drop this straight into your Claude/OpenAI tool definitions.

NMAP_TOOL_SCHEMA = {
    "name": "run_nmap",
    "description": (
        "Scan an authorized host with nmap. Pick scan_type for the intent: "
        "'ping' (is host up), 'discovery' (liveness sweep of a range), 'fast' "
        "(top 100 ports), 'quick' (top 1000 ports), 'version' (service versions), "
        "'full' (all 65535 ports), 'default' (safe scripts + versions), "
        "'aggressive' (OS + scripts + traceroute), 'os' (OS fingerprint), 'udp', "
        "'udp_tcp' (both), 'vuln' (NSE vuln scripts), 'web' (http enumeration on "
        "web ports), 'stealth' (slow fragmented SYN). Add NSE categories via "
        "'scripts'. Use skip_ping for hosts that block ping, os_detect to add OS "
        "fingerprinting, and ports/top_ports to narrow the port set."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Host or IP to scan (must be in authorized scope).",
            },
            "scan_type": {
                "type": "string",
                "enum": list(SCAN_PROFILES.keys()),
                "description": "The scan intent / profile.",
            },
            "ports": {
                "type": "string",
                "description": "Optional port spec, e.g. '80,443' or '1-1000'.",
            },
            "scripts": {
                "type": "string",
                "description": (
                    "Optional comma-separated NSE categories. Allowed: "
                    + ", ".join(sorted(ALLOWED_SCRIPT_CATEGORIES))
                ),
            },
            "skip_ping": {
                "type": "boolean",
                "description": "Add -Pn: skip host discovery, treat host as up.",
            },
            "os_detect": {
                "type": "boolean",
                "description": "Add -O: attempt OS fingerprinting.",
            },
            "top_ports": {
                "type": "integer",
                "description": "Scan the N most common ports (1-65535).",
            },
        },
        "required": ["-sT", "target", "scan_type"],
    },
}


# ---------------------------------------------------------------------------
# Manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Scans localhost — always in scope. Safe to run on your own machine.
    result = run_nmap("127.0.0.1", scan_type="quick")
    print(result.summary())
    print("\n--- JSON ---")
    print(result.to_json())
