"""Command-line entry point for the TCP port scanner.

Usage:
    python main.py <host> [--start-port N] [--end-port N] [--timeout S] [--workers N] [--show-all]

Examples:
    python main.py 127.0.0.1
    python main.py scanme.nmap.org --start-port 1 --end-port 1000
"""

import argparse
import sys

from models import PortStatus, ScanSummary
from resolver import HostResolutionError
from scanner import DEFAULT_MAX_WORKERS, DEFAULT_TIMEOUT_SECONDS, PortScanner


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser.

    Returns:
        A configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="port-scanner",
        description="A simple concurrent TCP port scanner for learning networking fundamentals.",
    )
    parser.add_argument(
        "target",
        help="Hostname or IP address to scan (e.g. scanme.nmap.org or 127.0.0.1)",
    )
    parser.add_argument(
        "--start-port",
        type=int,
        default=1,
        help="First port to scan (default: 1)",
    )
    parser.add_argument(
        "--end-port",
        type=int,
        default=1024,
        help="Last port to scan (default: 1024)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Per-port connection timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS})",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help=f"Max concurrent threads (default: {DEFAULT_MAX_WORKERS})",
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Show closed/filtered ports too, not just open ones",
    )
    return parser


def print_results(summary: ScanSummary, show_all: bool) -> None:
    """Print scan results as a clean, aligned table.

    Args:
        summary: The completed scan summary to display.
        show_all: If True, show every scanned port; otherwise only open ones.
    """
    print(f"\nTarget:        {summary.target_host} ({summary.resolved_ip})")
    print(f"Ports scanned: {len(summary.results)}")
    print(f"Duration:      {summary.duration_seconds:.2f}s\n")

    rows = summary.results if show_all else summary.open_ports
    rows = sorted(rows, key=lambda r: r.port)

    if not rows:
        print("No open ports found." if not show_all else "No results.")
        return

    header = f"{'PORT':<8}{'STATUS':<10}{'SERVICE':<15}"
    print(header)
    print("-" * len(header))
    for result in rows:
        print(f"{result.port:<8}{result.status.value:<10}{result.service:<15}")

    open_count = sum(1 for r in summary.results if r.status == PortStatus.OPEN)
    print(f"\n{open_count} open port(s) found.")


def main() -> int:
    """Parse arguments, run the scan, and print results.

    Returns:
        Process exit code (0 for success, non-zero for failure).
    """
    parser = build_arg_parser()
    args = parser.parse_args()

    scanner = PortScanner(timeout=args.timeout, max_workers=args.workers)

    try:
        summary = scanner.scan(args.target, args.start_port, args.end_port)
    except HostResolutionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nScan interrupted by user.", file=sys.stderr)
        return 130

    print_results(summary, args.show_all)
    return 0


if __name__ == "__main__":
    sys.exit(main())