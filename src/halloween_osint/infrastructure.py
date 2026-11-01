"""Bounded passive observations for an explicitly supplied public hostname."""
from __future__ import annotations

import hashlib
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any


def observe_domain(hostname: str, timeout: float = 5.0) -> dict[str, Any]:
    host = hostname.strip().rstrip(".").encode("idna").decode("ascii").lower()
    if (not host or len(host) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in host.split(".")
    )):
        raise ValueError("Provide a valid DNS hostname")
    if timeout <= 0 or timeout > 20:
        raise ValueError("Timeout must be greater than 0 and no more than 20 seconds")

    observed_at = datetime.now(timezone.utc).isoformat()
    result: dict[str, Any] = {
        "hostname": host,
        "observed_at": observed_at,
        "method": ["system DNS resolver", "TLS handshake on TCP port 443"],
        "dns": {"addresses": [], "errors": []},
        "tls": None,
        "limitations": [
            "Results reflect this machine's resolver and network at observation time.",
            "DNS answers do not establish ownership or control.",
            "A TLS certificate does not establish that a site is trustworthy.",
            "No port scan, content crawl, exploit attempt, or authentication was performed.",
        ],
    }

    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        result["dns"]["addresses"] = sorted({entry[4][0] for entry in answers})
    except OSError as exc:
        result["dns"]["errors"].append(f"{type(exc).__name__}: {exc}")

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                der = tls.getpeercert(binary_form=True)
                result["tls"] = {
                    "verified_by_local_trust_store": True,
                    "protocol": tls.version(),
                    "cipher": tls.cipher()[0] if tls.cipher() else None,
                    "subject": cert.get("subject", []),
                    "issuer": cert.get("issuer", []),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "subject_alt_names": cert.get("subjectAltName", []),
                    "sha256_fingerprint": hashlib.sha256(der).hexdigest() if der else None,
                }
    except (OSError, ssl.SSLError, ValueError) as exc:
        result["tls"] = {"error": f"{type(exc).__name__}: {exc}"}
    return result
