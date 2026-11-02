
"""Offline IP address validation and classification.

This module uses Python's standard-library ipaddress module.
It does not send IP addresses to external services.
"""

import ipaddress


# RFC 1918 private IPv4 networks and IPv6 Unique Local Addresses.
PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)

# RFC 5737 IPv4 documentation ranges.
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def classify_ip_address(address: str) -> dict:
    """Validate and classify an IPv4 or IPv6 address."""

    if not isinstance(address, str) or not address.strip():
        return {
            "ip_address": address,
            "valid": False,
            "classification": "invalid",
            "version": None,
            "is_global": False,
            "message": "A valid IP address string is required.",
        }

    address = address.strip()

    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return {
            "ip_address": address,
            "valid": False,
            "classification": "invalid",
            "version": None,
            "is_global": False,
            "message": "Invalid IPv4 or IPv6 address.",
        }

    # Check specific categories before broader categories.
    if any(ip in network for network in DOCUMENTATION_NETWORKS):
        classification = "documentation"

    elif ip.is_loopback:
        classification = "loopback"

    elif ip.is_unspecified:
        classification = "unspecified"

    elif ip.is_multicast:
        classification = "multicast"

    elif ip.is_link_local:
        classification = "link_local"

    elif any(ip in network for network in PRIVATE_NETWORKS):
        classification = "private"

    elif ip.is_reserved:
        classification = "reserved"

    elif ip.is_global:
        classification = "public"

    else:
        classification = "special"

    return {
        "ip_address": str(ip),
        "valid": True,
        "classification": classification,
        "version": ip.version,
        "is_global": ip.is_global,
        "is_private": classification == "private",
        "is_loopback": ip.is_loopback,
        "is_link_local": ip.is_link_local,
        "is_multicast": ip.is_multicast,
        "is_reserved": ip.is_reserved,
        "is_unspecified": ip.is_unspecified,
        "message": f"IP address classified as {classification}.",
    }
