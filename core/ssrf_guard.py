"""
SSRF Guard
==========

The StackSentry platform scans domains that arrive from user input (a badge
request, a report request, etc.). Without protection, someone could ask the
platform to scan an internal address and turn our own scanner into their
weapon — Server-Side Request Forgery (SSRF).

Classic SSRF targets:
  - Cloud metadata endpoints   169.254.169.254   (AWS/GCP/Azure credentials)
  - Loopback                    127.0.0.1, ::1    (services bound to localhost)
  - Private networks            10.x, 192.168.x, 172.16–31.x
  - Link-local                  169.254.x, fe80::
  - Our own internal services   Redis, Postgres, admin panels

This module is the single gate every scan target must pass through BEFORE any
network request is made. It resolves the hostname to its IP address(es) and
refuses anything that is not a public, routable host on an allowed scheme.

Design principles:
  - Fail closed. Anything we are unsure about is rejected.
  - Check the RESOLVED IP, not just the hostname. A hostname like
    "evil.com" can resolve to 127.0.0.1 — DNS rebinding. We must inspect
    where it actually points.
  - Check every address a hostname resolves to, not just the first.
  - Reject non-http(s) schemes outright.
"""

from __future__ import annotations
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse


# ── Result type ──────────────────────────────────────────────────────────────

@dataclass
class GuardResult:
    allowed: bool
    reason: str
    hostname: str | None = None
    resolved_ips: list[str] | None = None


ALLOWED_SCHEMES = {"http", "https"}

# Ports we refuse to scan even on public IPs — these are almost never a public
# web app and are common internal-service ports. The scan targets web apps.
BLOCKED_PORTS = {
    22,     # SSH
    23,     # Telnet
    25,     # SMTP
    3306,   # MySQL
    5432,   # PostgreSQL
    6379,   # Redis
    27017,  # MongoDB
    11211,  # Memcached
    9200,   # Elasticsearch
    2375,   # Docker daemon
    2376,   # Docker daemon (TLS)
}


def _ip_is_public(ip_str: str) -> tuple[bool, str]:
    """
    Return (is_public, reason). An IP is public only if it is global and not
    in any reserved, private, loopback, link-local, or multicast range.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, f"not a valid IP address: {ip_str}"

    # The cloud metadata address falls under other categories too, but we name
    # it explicitly and FIRST so logs make the specific threat obvious.
    if ip_str == "169.254.169.254":
        return False, "cloud metadata endpoint blocked"

    # ip_address exposes precise category flags — use them, do not hand-roll ranges.
    if ip.is_loopback:
        return False, f"loopback address blocked: {ip_str}"
    if ip.is_private:
        return False, f"private address blocked: {ip_str}"
    if ip.is_link_local:
        return False, f"link-local address blocked: {ip_str}"
    if ip.is_multicast:
        return False, f"multicast address blocked: {ip_str}"
    if ip.is_reserved:
        return False, f"reserved address blocked: {ip_str}"
    if ip.is_unspecified:
        return False, f"unspecified address blocked: {ip_str}"

    # is_global is the positive assertion we actually want.
    if not ip.is_global:
        return False, f"non-global address blocked: {ip_str}"

    return True, "public"


def _resolve_all(hostname: str) -> list[str]:
    """
    Resolve a hostname to every IP address it maps to (IPv4 and IPv6).
    We check all of them because a host that resolves to one public and one
    private address must still be rejected — the private one is exploitable.
    """
    ips: list[str] = []
    try:
        # AF_UNSPEC returns both IPv4 and IPv6 records.
        for family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(
            hostname, None, family=socket.AF_UNSPEC
        ):
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror:
        return []
    return ips


def check_target(url_or_domain: str) -> GuardResult:
    """
    The single gate. Given a user-supplied URL or bare domain, decide whether
    it is safe to scan.

    Returns a GuardResult. Only proceed with a scan if result.allowed is True.
    """
    raw = (url_or_domain or "").strip()
    if not raw:
        return GuardResult(False, "empty target")

    # Normalise into a URL we can parse. Bare domains get an https:// prefix
    # so urlparse populates .hostname.
    if "://" not in raw:
        parsed = urlparse("https://" + raw)
    else:
        parsed = urlparse(raw)

    # Scheme must be http or https.
    if parsed.scheme not in ALLOWED_SCHEMES:
        return GuardResult(False, f"scheme not allowed: {parsed.scheme!r}")

    hostname = parsed.hostname
    if not hostname:
        return GuardResult(False, "could not extract hostname")

    # Reject explicit userinfo (user:pass@host) — a common SSRF obfuscation.
    if "@" in (parsed.netloc or ""):
        return GuardResult(False, "userinfo in URL not allowed")

    # Port check.
    port = parsed.port
    if port is not None and port in BLOCKED_PORTS:
        return GuardResult(False, f"port blocked: {port}", hostname=hostname)

    # A literal IP given directly as the host must also pass the public check.
    # (Someone could pass http://127.0.0.1 directly.)
    try:
        ipaddress.ip_address(hostname)
        is_literal_ip = True
    except ValueError:
        is_literal_ip = False

    if is_literal_ip:
        ok, reason = _ip_is_public(hostname)
        if not ok:
            return GuardResult(False, reason, hostname=hostname,
                               resolved_ips=[hostname])
        return GuardResult(True, "public IP literal", hostname=hostname,
                           resolved_ips=[hostname])

    # Resolve the hostname and check EVERY address it points to.
    ips = _resolve_all(hostname)
    if not ips:
        return GuardResult(False, f"could not resolve: {hostname}",
                           hostname=hostname)

    for ip in ips:
        ok, reason = _ip_is_public(ip)
        if not ok:
            # If ANY resolved address is non-public, reject the whole target.
            return GuardResult(False, f"{reason} (via {hostname})",
                               hostname=hostname, resolved_ips=ips)

    return GuardResult(True, "public", hostname=hostname, resolved_ips=ips)
