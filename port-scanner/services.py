"""Well-known TCP service name lookups.

A small, static mapping of common ports to the services conventionally
associated with them (per IANA's registered ports list). This is not
exhaustive or authoritative -- any service can technically run on any
port -- but it gives useful context when reading scan output.
"""

COMMON_PORTS: dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBIND",
    123: "NTP",
    135: "MS-RPC",
    137: "NETBIOS-NS",
    139: "NETBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "SYSLOG",
    587: "SMTP-SUB",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE-DB",
    2049: "NFS",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    27017: "MONGODB",
}


def get_service_name(port: int) -> str:
    """Look up the conventional service name for a port.

    Args:
        port: The TCP port number.

    Returns:
        The service name if known, otherwise "UNKNOWN".
    """
    return COMMON_PORTS.get(port, "UNKNOWN")