from __future__ import annotations

import hashlib

import pytest

pytest.importorskip("oix")

from oix.identity import generate_identity, load_private_key
from oix.inbox import InboxError, SQLiteInbox
from oix.policy import CapabilityPolicy

from halloween_osint.oix_bridge import create_evidence_message


def test_artifact_is_hashed_and_signed_as_metadata_only_evidence(tmp_path):
    sender_dir, receiver_dir = tmp_path / "sender", tmp_path / "receiver"
    sender_card = generate_identity(sender_dir, "Halloween OSINT", ["public.research"])
    receiver_card = generate_identity(receiver_dir, "OIX Receiver", ["public.research"])
    artifact = tmp_path / "domain-observation.json"
    content = b'{"hostname":"example.org","tls":{"verified_by_local_trust_store":true}}'
    artifact.write_bytes(content)

    message = create_evidence_message(
        identity_dir=sender_dir,
        recipient=receiver_card["card"]["agent_id"],
        artifact_path=artifact,
        evidence_type="domain_observation",
        method_name="passive-dns-tls-observation",
        method_version="1.0",
        summary={"hostname": "example.org", "tls_observed": True},
        limitations=["Observation is point-in-time and does not establish ownership."],
        source_uri="https://example.org/",
        classification="public",
    )

    payload = message["body"]["payload"]
    assert payload["artifact"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert payload["artifact"]["size_bytes"] == len(content)
    assert payload["evidence_type"] == "domain_observation"
    assert content.decode() not in str(payload)

    inbox = SQLiteInbox(
        tmp_path / "receiver.sqlite3",
        receiver_card["card"]["agent_id"],
        CapabilityPolicy({"public.research"}),
    )
    inbox.trust_peer(sender_card)
    receipt = inbox.receive(message)
    assert receipt.message_type == "evidence.submit"
    assert receipt.work_status == "pending_review"
    assert inbox.pending_work()[0]["payload"] == payload


def test_bridge_rejects_unsupported_evidence_type(tmp_path):
    identity_dir = tmp_path / "identity"
    generate_identity(identity_dir, "Halloween OSINT", ["public.research"])
    artifact = tmp_path / "report.json"
    artifact.write_text("{}", encoding="utf-8")
    with pytest.raises(InboxError):
        create_evidence_message(
            identity_dir=identity_dir,
            recipient="ed25519:" + "a" * 64,
            artifact_path=artifact,
            evidence_type="person_attribution",
            method_name="unsupported",
            method_version="1.0",
            summary={"finding_count": 0},
            limitations=["No attribution."],
        )


def test_bridge_rejects_non_deterministic_summary(tmp_path):
    identity_dir = tmp_path / "identity"
    generate_identity(identity_dir, "Halloween OSINT", ["public.research"])
    artifact = tmp_path / "report.json"
    artifact.write_text("{}", encoding="utf-8")
    with pytest.raises(Exception):
        create_evidence_message(
            identity_dir=identity_dir,
            recipient="ed25519:" + "a" * 64,
            artifact_path=artifact,
            evidence_type="domain_observation",
            method_name="passive-observation",
            method_version="1.0",
            summary={"confidence": 0.99},
            limitations=["Confidence is not computed."],
        )


def test_bridge_refuses_symlink_artifact(tmp_path):
    identity_dir = tmp_path / "identity"
    generate_identity(identity_dir, "Halloween OSINT", ["public.research"])
    artifact = tmp_path / "real.json"
    artifact.write_text("{}", encoding="utf-8")
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(artifact)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available on this platform")
    with pytest.raises(ValueError, match="regular file"):
        create_evidence_message(
            identity_dir=identity_dir,
            recipient="ed25519:" + "a" * 64,
            artifact_path=link,
            evidence_type="domain_observation",
            method_name="passive-observation",
            method_version="1.0",
            summary={"hostname": "example.org"},
            limitations=["No attribution."],
        )
