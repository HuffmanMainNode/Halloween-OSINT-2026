import pytest

from halloween_osint.infrastructure import observe_domain


def test_invalid_hostname_rejected():
    with pytest.raises(ValueError):
        observe_domain("bad..example")


def test_invalid_timeout_rejected():
    with pytest.raises(ValueError):
        observe_domain("example.org", timeout=100)
