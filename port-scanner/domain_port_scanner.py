import socket
from concurrent.futures import ThreadPoolExecutor


def scan_port(host: str, port: int) -> int | None:
    """
    Return port number if open, otherwise None.
    """

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(1)

    result = sock.connect_ex((host, port))

    sock.close()

    if result == 0:
        return port

    return None


def resolve_host(hostname: str) -> str:
    """
    Resolve hostname to IP address.
    """

    return socket.gethostbyname(hostname)


def main() -> None:
    target = input("Enter hostname or IP: ")

    try:
        ip_address = resolve_host(target)

        print(f"\nTarget: {target}")
        print(f"IP Address: {ip_address}")
        print("\nScanning ports 1-1001...\n")

        open_ports = []

        with ThreadPoolExecutor(max_workers=1001) as executor:

            results = executor.map(
                lambda port: scan_port(ip_address, port),
                range(1, 1001)
            )

            for result in results:
                if result is not None:
                    open_ports.append(result)

        if open_ports:
            print("Open Ports:")

            for port in sorted(open_ports):
                print(f"Port {port}")

        else:
            print("No open ports found.")

    except socket.gaierror:
        print("Could not resolve hostname.")

    except KeyboardInterrupt:
        print("\nScan cancelled.")

    except Exception as error:
        print(f"Error: {error}")


if __name__ == "__main__":
    main()