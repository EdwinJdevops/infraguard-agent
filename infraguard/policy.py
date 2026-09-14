from __future__ import annotations

import ipaddress

PRIVATE_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
UNIQUE_LOCAL_IPV6 = ipaddress.ip_network("fc00::/7")


class PolicyError(ValueError):
    """Raised when a proposed remediation violates local policy."""


def validate_replacement_source(source: str) -> str:
    try:
        network = ipaddress.ip_network(source, strict=False)
    except ValueError as exc:
        raise PolicyError(f"replacement source is not a valid CIDR: {source}") from exc

    if network.version == 4 and not any(
        network.subnet_of(private) for private in PRIVATE_IPV4_NETWORKS
    ):
        raise PolicyError("replacement source must be within an RFC1918 IPv4 network")
    if network.version == 6 and not network.subnet_of(UNIQUE_LOCAL_IPV6):
        raise PolicyError("replacement source must be within the IPv6 unique-local range fc00::/7")

    return str(network)
