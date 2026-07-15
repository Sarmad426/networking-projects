"""Data models for the port scanner.

This module defines simple, immutable data structures used to represent
scan results. Using dataclasses keeps the code readable and type-safe
without needing any external libraries.
"""

from dataclasses import dataclass, field
from enum import Enum


class PortStatus(str, Enum):
    """Possible states for a scanned port."""

    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"  # No response at all -- likely a firewall dropping packets.


@dataclass(frozen=True)
class PortResult:
    """Result of scanning a single TCP port.

    Attributes:
        port: The port number that was scanned (1-65535).
        status: Whether the port was open, closed, or filtered.
        service: The commonly known service name for this port.
    """

    port: int
    status: PortStatus
    service: str


@dataclass
class ScanSummary:
    """Aggregated results for an entire scan run.

    Attributes:
        target_host: The original hostname/IP given by the user.
        resolved_ip: The IP address the hostname resolved to.
        results: List of PortResult objects, one per port scanned.
        duration_seconds: Total wall-clock time the scan took.
    """

    target_host: str
    resolved_ip: str
    results: list[PortResult] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def open_ports(self) -> list[PortResult]:
        """Return only the open ports, sorted by port number."""
        return sorted(
            (r for r in self.results if r.status == PortStatus.OPEN),
            key=lambda r: r.port,
        )