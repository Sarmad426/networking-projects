import socket


def scan_port(host: str, port: int) -> bool:
    """
    Check whether a TCP port is open.
    """
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(1)

    result = sock.connect_ex((host, port))

    sock.close()

    return result == 0


def resolve_host(hostname: str) -> str:
    """
    Convert a hostname to an IP address.
    """
    return socket.gethostbyname(hostname)


def main() -> None:
    target = input("Enter hostname or IP: ")

    try:
        ip_address = resolve_host(target)

        print(f"\nTarget: {target}")
        print(f"IP Address: {ip_address}")
        print("\nScanning ports 1-100...\n")

        open_ports = []

        for port in range(1, 101):
            if scan_port(ip_address, port):
                open_ports.append(port)

        if open_ports:
            print("Open Ports:")
            for port in open_ports:
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