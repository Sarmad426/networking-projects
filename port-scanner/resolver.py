"""Hostname resolution utilities.

DNS resolution converts a human-readable hostname (e.g. "example.com")
into an IP address (e.g. "93.184.216.34") that the OS network stack can
actually route packets to. This module wraps that lookup and converts
low-level socket errors into a clear, custom exception the rest of the
app can handle predictably.
"""

import socket


class HostResolutionError(Exception):
    """Raised when a hostname or IP address cannot be resolved."""


def resolve_host(target: str) -> str:
    """Resolve a hostname or IP address string to an IPv4 address.

    Args:
        target: A hostname (e.g. "scanme.nmap.org") or an IP address
            (e.g. "45.33.32.156"). If an IP is given, it is validated
            and returned as-is.

    Returns:
        The resolved IPv4 address as a string.

    Raises:
        HostResolutionError: If the target cannot be resolved to an IP.
    """
    try:
        # gethostbyname() triggers the OS resolver: it checks the local
        # hosts file first, then queries configured DNS servers if needed.
        # It returns the first IPv4 address found for the name.
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        # gaierror = "getaddrinfo error" -- raised for unknown hosts,
        # unreachable DNS servers, or malformed names.
        raise HostResolutionError(f"Could not resolve host '{target}': {exc}") from exc