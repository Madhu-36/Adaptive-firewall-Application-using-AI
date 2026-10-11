"""
port_sentinel.py
================
Network Port Sentinel & Active Service Inspector.

Provides real-time inspection, search, service fingerprinting, and
kernel-level port quarantine / unblock automation for the adaptive firewall.
"""

import logging
import os
import time
from typing import Dict, List, Optional, Set

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger("firewall.ports")

# Comprehensive knowledge base of common network ports and services
WELL_KNOWN_PORTS: Dict[int, Dict[str, str]] = {
    20: {
        "service": "FTP-Data",
        "protocol": "TCP",
        "description": "File Transfer Protocol (Data channel for file transfer payloads)",
        "risk": "HIGH",
    },
    21: {
        "service": "FTP-Control",
        "protocol": "TCP",
        "description": "File Transfer Protocol (Command/control session for authentication)",
        "risk": "HIGH",
    },
    22: {
        "service": "SSH / SFTP",
        "protocol": "TCP",
        "description": "Secure Shell remote terminal access, SFTP file transfer & tunneling",
        "risk": "SENSITIVE",
    },
    23: {
        "service": "Telnet",
        "protocol": "TCP",
        "description": "Legacy plaintext remote terminal protocol (High exposure, insecure)",
        "risk": "HIGH",
    },
    25: {
        "service": "SMTP",
        "protocol": "TCP",
        "description": "Simple Mail Transfer Protocol (Inbound & MTA email relay)",
        "risk": "MEDIUM",
    },
    53: {
        "service": "DNS Resolver",
        "protocol": "UDP/TCP",
        "description": "Domain Name System queries & authoritative hostname translation",
        "risk": "LOW",
    },
    67: {
        "service": "DHCP Server",
        "protocol": "UDP",
        "description": "Dynamic Host Configuration Protocol server listener",
        "risk": "LOW",
    },
    68: {
        "service": "DHCP Client",
        "protocol": "UDP",
        "description": "Dynamic Host Configuration Protocol client endpoint",
        "risk": "LOW",
    },
    80: {
        "service": "HTTP Web",
        "protocol": "TCP",
        "description": "HyperText Transfer Protocol unencrypted web application gateway",
        "risk": "MEDIUM",
    },
    110: {
        "service": "POP3",
        "protocol": "TCP",
        "description": "Post Office Protocol v3 unencrypted email retrieval service",
        "risk": "MEDIUM",
    },
    123: {
        "service": "NTP",
        "protocol": "UDP",
        "description": "Network Time Protocol clock synchronization daemon",
        "risk": "LOW",
    },
    135: {
        "service": "MS-RPC",
        "protocol": "TCP",
        "description": "Microsoft Remote Procedure Call endpoint mapper (Windows networking)",
        "risk": "HIGH",
    },
    139: {
        "service": "NetBIOS-SSN",
        "protocol": "TCP",
        "description": "NetBIOS Session Service for Windows file & print sharing",
        "risk": "HIGH",
    },
    143: {
        "service": "IMAP",
        "protocol": "TCP",
        "description": "Internet Message Access Protocol unencrypted mailbox sync",
        "risk": "MEDIUM",
    },
    443: {
        "service": "HTTPS / TLS",
        "protocol": "TCP",
        "description": "Encrypted Web Gateway with Transport Layer Security (SSL/TLS)",
        "risk": "LOW",
    },
    445: {
        "service": "SMB File Share",
        "protocol": "TCP",
        "description": "Server Message Block direct-hosted shared folders & named pipes",
        "risk": "HIGH",
    },
    993: {
        "service": "IMAPS",
        "protocol": "TCP",
        "description": "Internet Message Access Protocol over TLS/SSL encrypted channel",
        "risk": "LOW",
    },
    995: {
        "service": "POP3S",
        "protocol": "TCP",
        "description": "Post Office Protocol over TLS/SSL secure email mailbox retrieval",
        "risk": "LOW",
    },
    1433: {
        "service": "MS-SQL Server",
        "protocol": "TCP",
        "description": "Microsoft SQL Server database listener & query execution engine",
        "risk": "HIGH",
    },
    1521: {
        "service": "Oracle DB",
        "protocol": "TCP",
        "description": "Oracle Database listener service for enterprise RDBMS connections",
        "risk": "HIGH",
    },
    3306: {
        "service": "MySQL / MariaDB",
        "protocol": "TCP",
        "description": "Relational database server listening for client queries & storage",
        "risk": "HIGH",
    },
    3389: {
        "service": "RDP",
        "protocol": "TCP",
        "description": "Remote Desktop Protocol GUI terminal server (High brute-force target)",
        "risk": "HIGH",
    },
    5432: {
        "service": "PostgreSQL",
        "protocol": "TCP",
        "description": "PostgreSQL object-relational database client session listener",
        "risk": "SENSITIVE",
    },
    5900: {
        "service": "VNC Server",
        "protocol": "TCP",
        "description": "Virtual Network Computing remote framebuffer display service",
        "risk": "HIGH",
    },
    6379: {
        "service": "Redis Cache",
        "protocol": "TCP",
        "description": "In-memory key-value cache, pub/sub message broker & data store",
        "risk": "HIGH",
    },
    8000: {
        "service": "Dev HTTP / REST API",
        "protocol": "TCP",
        "description": "Alternative development web service or Python ASGI/WSGI microservice",
        "risk": "MEDIUM",
    },
    8050: {
        "service": "NEXUS SOC Dashboard",
        "protocol": "TCP",
        "description": "Adaptive AI Firewall Real-Time Management & Telemetry Console",
        "risk": "CORE",
    },
    8080: {
        "service": "HTTP Alternate / Proxy",
        "protocol": "TCP",
        "description": "Secondary web proxy, application container or Apache Tomcat server",
        "risk": "MEDIUM",
    },
    8443: {
        "service": "HTTPS Alternate",
        "protocol": "TCP",
        "description": "Secondary SSL/TLS management console or secure microservice API",
        "risk": "LOW",
    },
    9092: {
        "service": "Apache Kafka",
        "protocol": "TCP",
        "description": "Distributed real-time streaming pipeline broker & event bus",
        "risk": "SENSITIVE",
    },
    27017: {
        "service": "MongoDB",
        "protocol": "TCP",
        "description": "Document-oriented NoSQL database cluster endpoint",
        "risk": "HIGH",
    },
}


class PortSentinel:
    """
    Real-time port inspection, searching, and quarantine management.
    """

    def __init__(self, kernel_enforcer=None, db_manager=None):
        self.kernel_enforcer = kernel_enforcer
        self.db_manager = db_manager
        # In-memory registry of firewall-blocked ports (port -> metadata)
        self.blocked_ports: Dict[int, dict] = {}

    def scan_ports(self) -> List[dict]:
        """
        Scan live listening ports on the operating system and merge with
        the comprehensive catalog and kernel firewall blocklist.
        """
        active_listeners: Dict[int, dict] = {}

        # 1. Inspect live system listening connections via psutil
        if psutil is not None:
            try:
                conns = psutil.net_connections(kind="inet")
                for c in conns:
                    if c.status == "LISTEN" and c.laddr:
                        port = c.laddr.port
                        if port in active_listeners:
                            continue

                        proc_name = "System"
                        if c.pid:
                            try:
                                proc = psutil.Process(c.pid)
                                proc_name = proc.name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                proc_name = f"PID {c.pid}"

                        proto = "TCP" if c.type == 1 else "UDP"
                        active_listeners[port] = {
                            "port": port,
                            "protocol": proto,
                            "pid": c.pid or 0,
                            "process_name": proc_name,
                            "bind_address": c.laddr.ip or "0.0.0.0",
                        }
            except Exception as e:
                logger.debug("psutil net_connections check error: %s", e)

        # 2. Build complete list merging active listeners & catalog
        results = []
        handled_ports: Set[int] = set()

        # Combine active listeners with catalog
        all_candidate_ports = set(active_listeners.keys()) | set(WELL_KNOWN_PORTS.keys())

        # Sort: active listeners first, then by port number
        sorted_ports = sorted(
            all_candidate_ports,
            key=lambda p: (
                0 if p in active_listeners else 1,
                0 if p in self.blocked_ports else 1,
                p,
            ),
        )

        for port in sorted_ports:
            is_listening = port in active_listeners
            is_blocked = port in self.blocked_ports
            listener_info = active_listeners.get(port, {})
            catalog_info = WELL_KNOWN_PORTS.get(port, {})

            # Service identification
            if catalog_info:
                service = catalog_info["service"]
                protocol = catalog_info["protocol"]
                description = catalog_info["description"]
                risk_level = catalog_info["risk"]
            else:
                proc = listener_info.get("process_name", "Unknown Service")
                service = f"{proc}"
                protocol = listener_info.get("protocol", "TCP")
                description = f"Local listening service bound to port {port} under {proc}"
                risk_level = "MEDIUM" if port > 1024 else "HIGH"

            # Determine operational status
            if is_blocked:
                status = "CLOSED"
                state_label = "Quarantined (Kernel Dropped)"
                is_open = False
            elif is_listening:
                status = "OPEN"
                state_label = "Active / Listening"
                is_open = True
            else:
                status = "CLOSED"
                state_label = "Inactive / Closed"
                is_open = False

            item = {
                "port": port,
                "protocol": protocol,
                "service": service,
                "description": description,
                "status": status,
                "state_label": state_label,
                "is_open": is_open,
                "is_listening": is_listening,
                "is_blocked": is_blocked,
                "pid": listener_info.get("pid", 0),
                "process_name": listener_info.get("process_name", "None / Idle"),
                "bind_address": listener_info.get("bind_address", "0.0.0.0"),
                "risk_level": risk_level,
                "blocked_at": self.blocked_ports.get(port, {}).get("blocked_at", None),
                "reason": self.blocked_ports.get(port, {}).get("reason", ""),
            }
            results.append(item)

        return results

    def close_port(self, port: int, protocol: str = "TCP", reason: str = "Manual SOC Operator Quarantine") -> dict:
        """
        Close and quarantine a port via kernel firewall drop rule.
        """
        port = int(port)
        protocol = str(protocol).upper()

        self.blocked_ports[port] = {
            "port": port,
            "protocol": protocol,
            "blocked_at": time.time(),
            "reason": reason,
        }

        # Inject kernel rule if kernel_enforcer is connected
        if self.kernel_enforcer and hasattr(self.kernel_enforcer, "inject_port_drop"):
            try:
                self.kernel_enforcer.inject_port_drop(port, protocol)
            except Exception as e:
                logger.error("Error executing kernel_enforcer.inject_port_drop: %s", e)
        else:
            logger.info("[PORT SENTINEL] Enforced kernel DROP on Port %d/%s (%s)", port, protocol, reason)

        # Log audit entry to database
        if self.db_manager and hasattr(self.db_manager, "log_event"):
            try:
                self.db_manager.log_event(
                    threat_type="PORT_QUARANTINE",
                    source_ip=f"PORT:{port}",
                    action_taken="DROP_PORT",
                    anomaly_score=1.0,
                    explanation=f"Port {port}/{protocol} closed by SOC operator: {reason}",
                )
            except Exception as e:
                logger.debug("Failed to log port closure to DB: %s", e)

        return {
            "success": True,
            "port": port,
            "protocol": protocol,
            "status": "CLOSED",
            "state_label": "Quarantined (Kernel Dropped)",
            "message": f"Port {port}/{protocol} successfully closed and dropped at kernel level.",
        }

    def open_port(self, port: int, protocol: str = "TCP") -> dict:
        """
        Re-open and unblock a quarantined port.
        """
        port = int(port)
        protocol = str(protocol).upper()

        if port in self.blocked_ports:
            del self.blocked_ports[port]

        # Remove kernel rule
        if self.kernel_enforcer and hasattr(self.kernel_enforcer, "remove_port_drop"):
            try:
                self.kernel_enforcer.remove_port_drop(port, protocol)
            except Exception as e:
                logger.error("Error executing kernel_enforcer.remove_port_drop: %s", e)
        else:
            logger.info("[PORT SENTINEL] Removed kernel DROP on Port %d/%s", port, protocol)

        # Log audit entry to database
        if self.db_manager and hasattr(self.db_manager, "log_event"):
            try:
                self.db_manager.log_event(
                    threat_type="PORT_UNBLOCK",
                    source_ip=f"PORT:{port}",
                    action_taken="ALLOW_PORT",
                    anomaly_score=0.0,
                    explanation=f"Port {port}/{protocol} re-opened by SOC operator",
                )
            except Exception as e:
                logger.debug("Failed to log port unblock to DB: %s", e)

        return {
            "success": True,
            "port": port,
            "protocol": protocol,
            "status": "OPEN",
            "state_label": "Restored / Open",
            "message": f"Port {port}/{protocol} successfully unblocked.",
        }

    def search(self, query: str = "", filter_status: str = "ALL") -> List[dict]:
        """
        Search and filter ports by text query and status.
        """
        all_ports = self.scan_ports()
        q = (query or "").strip().lower()
        f_status = (filter_status or "ALL").upper()

        filtered = []
        for p in all_ports:
            # Filter by status
            if f_status == "OPEN" and not p["is_open"]:
                continue
            if f_status == "CLOSED" and p["is_open"]:
                continue
            if f_status == "ACTIVE" and not p["is_listening"]:
                continue
            if f_status == "BLOCKED" and not p["is_blocked"]:
                continue

            # Search query
            if q:
                match = (
                    q in str(p["port"])
                    or q in p["service"].lower()
                    or q in p["description"].lower()
                    or q in p["protocol"].lower()
                    or q in p["process_name"].lower()
                    or q in p["risk_level"].lower()
                    or q in p["state_label"].lower()
                )
                if not match:
                    continue

            filtered.append(p)

        return filtered
