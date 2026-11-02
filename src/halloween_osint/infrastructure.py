"""Bounded passive observations for an explicitly supplied public hostname."""
from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import ssl
from datetime import UTC, datetime
from typing import Any


def observe_domain(hostname: str, timeout: float = 5.0) -> dict[str, Any]:
    raw_host = hostname.strip().rstrip(".")
    try:
        ipaddress.ip_address(raw_host)
    except ValueError:
        pass
    else:
        raise ValueError("IP-literal targets are not allowed; provide a public DNS hostname")

    host = raw_host.encode("idna").decode("ascii").lower()
    if (
        not host
        or len(host) > 253
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        )
    ):
        raise ValueError("Provide a valid DNS hostname")
    if timeout <= 0 or timeout > 20:
        raise ValueError("Timeout must be greater than 0 and no more than 20 seconds")

    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"Could not resolve public hostname: {type(exc).__name__}") from exc

    resolved: set[tuple[int, str]] = set()
    for family, socktype, proto, _canonname, sockaddr in answers:
        address = sockaddr[0]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError("Resolver returned an invalid IP address") from exc
        if not parsed.is_global:
            raise ValueError("Hostname resolves to a non-public address; connection refused")
        resolved.add((family, address))

    if not resolved:
        raise ValueError("Hostname did not resolve to a public address")

    observed_at = datetime.now(UTC).isoformat()
    result: dict[str, Any] = {
        "hostname": host,
        "observed_at": observed_at,
        "method": ["system DNS resolver", "TLS handshake on TCP port 443"],
        "dns": {"addresses": sorted(address for _family, address in resolved)},
        "tls": None,
        "limitations": [
            "Results reflect this machine's resolver and network at observation time.",
            "DNS answers do not establish ownership or control.",
            "A TLS certificate does not establish that a site is trustworthy.",
            "No port scan, content crawl, exploit attempt, or authentication was performed.",
            "Every resolved address must be globally routable; the TLS connection uses the validated address directly.",
        ],
    }

    context = ssl.create_default_context()
    errors: list[str] = []
    for family, address in resolved:
        if family == socket.AF_INET6:
            connect_address = (address, 443, 0, 0)
        else:
            connect_address = (address, 443)
        try:
            with socket.socket(family, socket.SOCK_STREAM) as raw:
                raw.settimeout(timeout)
                raw.connect(connect_address)
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    der = tls.getpeercert(binary_form=True)
                    cipher = tls.cipher()
                    result["tls"] = {
                        "connected_address": address,
                        "verified_by_local_trust_store": True,
                        "protocol": tls.version(),
                        "cipher": cipher[0] if cipher else None,
                        "subject": cert.get("subject", []),
                        "issuer": cert.get("issuer", []),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "subject_alt_names": cert.get("subjectAltName", []),
                        "sha256_fingerprint": hashlib.sha256(der).hexdigest() if der else None,
                    }
                    return result
        except (OSError, ssl.SSLError, ValueError) as exc:
            errors.append(f"{address}: {type(exc).__name__}: {exc}")
    result["tls"] = {"errors": errors}
    return result
