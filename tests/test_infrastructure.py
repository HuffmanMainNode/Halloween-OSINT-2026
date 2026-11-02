import socket

import pytest

from halloween_osint.infrastructure import observe_domain


def test_invalid_hostname_rejected():
    with pytest.raises(ValueError):
        observe_domain("bad..example")


def test_invalid_timeout_rejected():
    with pytest.raises(ValueError):
        observe_domain("example.org", timeout=100)


@pytest.mark.parametrize(
    "target",
    ["127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "::ffff:127.0.0.1"],
)
def test_ip_literal_targets_are_rejected(target):
    with pytest.raises(ValueError, match="IP-literal"):
        observe_domain(target)


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "::ffff:127.0.0.1"],
)
def test_hostname_resolving_to_non_public_address_is_rejected(monkeypatch, address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(family, socket.SOCK_STREAM, 6, "", sockaddr)],
    )
    with pytest.raises(ValueError, match="non-public"):
        observe_domain("public.example")


def test_public_resolution_connects_to_validated_ip_without_second_lookup(monkeypatch):
    calls = []
    address = "93.184.216.34"
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))
        ],
    )

    class FakeTLS:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def getpeercert(self, binary_form=False):
            return b"certificate" if binary_form else {}

        def cipher(self):
            return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)

        def version(self):
            return "TLSv1.3"

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, timeout):
            pass

        def connect(self, sockaddr):
            calls.append(sockaddr)

    class FakeContext:
        def wrap_socket(self, raw, server_hostname):
            assert server_hostname == "public.example"
            return FakeTLS()

    monkeypatch.setattr(socket, "socket", lambda *args: FakeSocket())
    monkeypatch.setattr("halloween_osint.infrastructure.ssl.create_default_context", FakeContext)
    result = observe_domain("public.example")
    assert calls == [(address, 443)]
    assert result["tls"]["connected_address"] == address
