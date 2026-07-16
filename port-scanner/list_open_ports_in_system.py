import socket
from concurrent.futures import ThreadPoolExecutor
import sys
from datetime import datetime

# Target configuration
TARGET_HOST = "127.0.0.1"  # Localhost (your system)
PORT_START = 1
PORT_END = 1024            # Standard well-known ports
MAX_WORKERS = 100          # Number of threads to run in parallel


def scan_port(host, port):
    """
    Attempts to connect to a specific port on the target host.
    Returns the port number if it is open, otherwise None.
    """
    # socket.AF_INET specifies IPv4, socket.SOCK_STREAM specifies TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Set a short timeout so we don't hang on filtered ports
        s.settimeout(1.0)
        
        # connect_ex returns 0 if the connection succeeded (port is open)
        result = s.connect_ex((host, port))
        if result == 0:
            return port
    return None


def main():
    print("-" * 50)
    print(f"Scanning target: {TARGET_HOST}")
    print(f"Time started: {datetime.now()}")
    print("-" * 50)

    open_ports = []
    ports_to_scan = range(PORT_START, PORT_END + 1)

    # Using ThreadPoolExecutor to run scans concurrently
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Map the scan_port function across our port range
            futures = [
                executor.submit(scan_port, TARGET_HOST, port) 
                for port in ports_to_scan
            ]
            
            for future in futures:
                port = future.result()
                if port is not None:
                    print(f"[+] Port {port:5} is OPEN")
                    open_ports.append(port)
                    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting...")
        sys.exit()
    except socket.gaierror:
        print("\n[!] Hostname could not be resolved.")
        sys.exit()
    except socket.error:
        print("\n[!] Could not connect to server.")
        sys.exit()

    print("-" * 50)
    print(f"Scan complete. Found {len(open_ports)} open ports.")
    print("-" * 50)


if __name__ == "__main__":
    main()