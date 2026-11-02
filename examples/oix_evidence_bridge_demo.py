"""Demonstrate signing a local Halloween OSINT artifact as an OIX evidence record.

The sample observation is synthetic. No network request or artifact upload occurs.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from oix.identity import generate_identity
from oix.inbox import SQLiteInbox
from oix.policy import CapabilityPolicy

from halloween_osint.oix_bridge import create_evidence_message


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="halloween-oix-") as directory:
        root = Path(directory)
        sender_dir, receiver_dir = root / "sender", root / "receiver"
        sender = generate_identity(sender_dir, "Halloween OSINT Demo", ["public.research"])
        receiver = generate_identity(receiver_dir, "OIX Demo Receiver", ["public.research"])
        artifact = root / "synthetic-domain-observation.json"
        artifact.write_text(
            json.dumps(
                {
                    "hostname": "example.org",
                    "observed_at": "2026-11-02T00:00:00Z",
                    "dns": {"addresses": ["203.0.113.10"]},
                    "tls": {"verified_by_local_trust_store": True},
                    "synthetic": True,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        envelope = create_evidence_message(
            identity_dir=sender_dir,
            recipient=receiver["card"]["agent_id"],
            artifact_path=artifact,
            evidence_type="domain_observation",
            method_name="synthetic-passive-dns-tls-example",
            method_version="1.0",
            summary={"hostname": "example.org", "synthetic": True},
            limitations=[
                "This demonstration uses synthetic data and makes no real-world observation."
            ],
            classification="public",
            status="unverified",
        )
        inbox = SQLiteInbox(
            root / "receiver.sqlite3",
            receiver["card"]["agent_id"],
            CapabilityPolicy({"public.research"}),
        )
        inbox.trust_peer(sender)
        receipt = inbox.receive(envelope)
        print(
            json.dumps(
                {
                    "message_type": receipt.message_type,
                    "work_status": receipt.work_status,
                    "artifact_sha256": envelope["body"]["payload"]["artifact"]["sha256"],
                    "artifact_uploaded": False,
                    "operator_review_required": True,
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
