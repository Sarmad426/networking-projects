"""Core TCP port scanning logic.

Concept refresher
------------------
A TCP connection is established through a three-way handshake:
SYN -> SYN/ACK -> ACK. Python's socket.connect() performs a *full*
handshake -- this is called a "connect scan". It's slower and more
detectable than tools like nmap's SYN scan (which sends only the first
SYN and never finishes the handshake), but it requires no special OS
privileges (no raw sockets) and needs nothing beyond the standard
library. That trade-off is exactly right for a V1 learning project.

How we classify a port:
    - connect() succeeds            -> OPEN      (something accepted the handshake)
    - OS immediately replies TCP RST -> CLOSED    (host is reachable, nothing is listening)
    - No reply within the timeout   -> FILTERED  (packet likely dropped by a firewall)
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from  models import PortResult, PortStatus, ScanSummary
from  resolver import resolve_host
from  services import get_service_name

DEFAULT_TIMEOUT_SECONDS = 1.0
DEFAULT_MAX_WORKERS = 200


def scan_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> PortResult:
    """Attempt a TCP connection to a single port and classify the result.

    Args:
        ip: The resolved IPv4 address to connect to.
        port: The TCP port number to test.
        timeout: Seconds to wait for a response before giving up.

    Returns:
        A PortResult describing whether the port is open, closed, or
        filtered, along with its conventional service name.
    """
    # AF_INET     -> use IPv4 addressing.
    # SOCK_STREAM -> use TCP (as opposed to SOCK_DGRAM for UDP).
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            # connect_ex() behaves like connect() but returns an errno
            # integer instead of raising on failure (0 == success). This
            # lets us handle the extremely common "connection refused"
            # case without paying for exception handling every time.
            result_code = sock.connect_ex((ip, port))
            status = PortStatus.OPEN if result_code == 0 else PortStatus.CLOSED
        except socket.timeout:
            status = PortStatus.FILTERED
        except OSError:
            # Covers rarer errors, e.g. "network unreachable" mid-scan.
            status = PortStatus.FILTERED

    return PortResult(port=port, status=status, service=get_service_name(port))


class PortScanner:
    """Scans a range of TCP ports on a target host using a thread pool.

    Why threads instead of asyncio or multiprocessing?
        Port scanning is I/O-bound -- almost all the wall-clock time is
        spent blocked inside connect(), waiting on the network, not
        doing CPU work. Python releases the GIL during blocking socket
        calls, so a modest thread pool gives real concurrency here
        without the added complexity of async/await syntax. This makes
        threads the simplest tool that's still genuinely fast -- ideal
        for a learning project. multiprocessing would add OS process
        overhead for zero benefit, since there's no CPU-bound work to
        parallelize.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_workers: int = DEFAULT_MAX_WORKERS,
    ) -> None:
        """Initialize the scanner.

        Args:
            timeout: Per-port connection timeout, in seconds.
            max_workers: Maximum number of concurrent threads.
        """
        self.timeout = timeout
        self.max_workers = max_workers

    def scan(self, target: str, start_port: int, end_port: int) -> ScanSummary:
        """Resolve a target and scan every port in [start_port, end_port].

        Args:
            target: Hostname or IP address to scan.
            start_port: First port in the range (inclusive).
            end_port: Last port in the range (inclusive).

        Returns:
            A ScanSummary containing every port's result and timing info.

        Raises:
            HostResolutionError: If the target hostname cannot be resolved.
            ValueError: If the port range is invalid.
        """
        if not (1 <= start_port <= end_port <= 65535):
            raise ValueError(
                f"Invalid port range: {start_port}-{end_port}. "
                "Ports must satisfy 1 <= start <= end <= 65535."
            )

        ip = resolve_host(target)
        ports = range(start_port, end_port + 1)

        summary = ScanSummary(target_host=target, resolved_ip=ip)
        start_time = time.perf_counter()

        # ThreadPoolExecutor manages a fixed-size pool of worker threads
        # plus a queue of pending tasks. We submit one "scan this port"
        # job per port; the pool runs up to `max_workers` of them at
        # once and pulls the next queued job as soon as a thread frees
        # up -- so a 1000-port scan doesn't spawn 1000 OS threads.
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(scan_port, ip, port, self.timeout): port
                for port in ports
            }

            # as_completed() yields futures as soon as each finishes,
            # in completion order -- not submission order -- so fast
            # (closed/refused) ports report back before slow (filtered,
            # timed-out) ones. We don't need the port from future_to_port
            # here since it's already inside each PortResult.
            for future in as_completed(future_to_port):
                summary.results.append(future.result())

        summary.duration_seconds = time.perf_counter() - start_time
        return summary