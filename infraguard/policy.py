from __future__ import annotations

import ipaddress


class PolicyError(ValueError):
    """Raised when a proposed remediation violates local policy."""


def validate_replacement_source(source: str) -> str:
    try:
        network = ipaddress.ip_network(source, strict=False)
    except ValueError as exc:
        raise PolicyError(f"replacement source is not a valid CIDR: {source}") from exc

    if network.version == 4 and str(network) == "0.0.0.0/0":
        raise PolicyError("replacement source cannot be public IPv4")
    if network.version == 6 and str(network) == "::/0":
        raise PolicyError("replacement source cannot be public IPv6")
    if network.prefixlen == 0:
        raise PolicyError("replacement source cannot be a global CIDR")

    return str(network)

