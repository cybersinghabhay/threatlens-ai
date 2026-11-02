
"""Tests for offline IP address classification."""

import pytest

from threatlens_ai.ip_intelligence import classify_ip_address


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("192.168.1.10", "private"),
        ("10.0.0.1", "private"),
        ("172.16.0.1", "private"),
        ("fc00::1", "private"),
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("0.0.0.0", "unspecified"),
        ("::", "unspecified"),
        ("169.254.1.10", "link_local"),
        ("224.0.0.1", "multicast"),
        ("ff02::1", "multicast"),
        ("192.0.2.10", "documentation"),
        ("198.51.100.10", "documentation"),
        ("203.0.113.10", "documentation"),
        ("8.8.8.8", "public"),
        ("2001:4860:4860::8888", "public"),
    ],
)
def test_ip_classification(address, expected):
    result = classify_ip_address(address)

    assert result["valid"] is True
    assert result["classification"] == expected


@pytest.mark.parametrize(
    "address",
    [
        "999.999.999.999",
        "not-an-ip",
        "192.168.1",
        "192.168.1.10.5",
        "",
        "   ",
    ],
)
def test_invalid_ip_addresses(address):
    result = classify_ip_address(address)

    assert result["valid"] is False
    assert result["classification"] == "invalid"
    assert result["version"] is None


def test_ipv4_version():
    result = classify_ip_address("8.8.8.8")

    assert result["version"] == 4


def test_ipv6_version():
    result = classify_ip_address("2001:4860:4860::8888")

    assert result["version"] == 6


def test_ip_address_whitespace_is_removed():
    result = classify_ip_address("  192.168.1.10  ")

    assert result["valid"] is True
    assert result["ip_address"] == "192.168.1.10"


@pytest.mark.parametrize("address", [None, 12345, [], {}])
def test_non_string_input(address):
    result = classify_ip_address(address)

    assert result["valid"] is False
    assert result["classification"] == "invalid"


def test_public_ip_is_not_private():
    result = classify_ip_address("8.8.8.8")

    assert result["is_global"] is True
    assert result["is_private"] is False


def test_private_ip_is_not_global():
    result = classify_ip_address("192.168.1.10")

    assert result["is_global"] is False
    assert result["is_private"] is True
