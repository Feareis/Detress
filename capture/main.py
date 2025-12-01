import logging
import os
import sys
import time
from typing import Dict, List, Optional

import httpx
from httpx import RequestError
from scapy.all import sniff, IP, TCP, UDP, get_if_list

# On Windows: used to get readable interface names (Ethernet, Wi-Fi, etc.)
try:
    from scapy.arch.windows import get_windows_if_list
except ImportError:
    get_windows_if_list = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_URL: str = os.getenv("NDR_API_URL", "http://127.0.0.1:8000/traffic")
DEFAULT_INTERFACE: Optional[str] = os.getenv("NDR_INTERFACE")
DEFAULT_INTERFACE_INDEX: Optional[str] = os.getenv("NDR_INTERFACE_INDEX")

HTTP_TIMEOUT_SECONDS: float = 2.0
MAX_SEND_ERRORS_BEFORE_WARN: int = 10

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | capture | %(message)s",
)
logger = logging.getLogger("detress-capture")


# ---------------------------------------------------------------------------
# Interface discovery and selection
# ---------------------------------------------------------------------------


def list_interfaces() -> List[str]:
    """
    Return a list of interface names usable by sniff(), and print them.

    On Windows:
        Uses get_windows_if_list() to show human-readable names.
    On other OS:
        Uses get_if_list() from Scapy.
    """
    if sys.platform.startswith("win") and get_windows_if_list:
        raw = get_windows_if_list()
        interfaces: List[str] = []

        print("\nAvailable network interfaces:")
        for idx, iface in enumerate(raw):
            name = iface.get("name", "Unknown")
            desc = iface.get("description", "")
            print(f"  [{idx}] {name} - {desc}")
            interfaces.append(name)

        print()
        return interfaces

    interfaces = get_if_list()
    print("\nAvailable network interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"  [{idx}] {iface}")
    print()

    return interfaces


def choose_interface(interfaces: List[str]) -> str:
    """
    Ask the operator to select an interface from the provided list.
    """
    if not interfaces:
        logger.error("No network interfaces detected. Exiting.")
        print("[ERROR] No network interfaces detected. Exiting.")
        sys.exit(1)

    while True:
        choice = input("Select an interface index (e.g. 0): ").strip()

        if not choice.isdigit():
            print("[!] Invalid input. Please enter a numeric index.")
            continue

        idx = int(choice)
        if 0 <= idx < len(interfaces):
            return interfaces[idx]

        print("[!] Index out of range. Try again.")


def resolve_interface() -> str:
    """
    Resolve which interface to use:
        1) If NDR_INTERFACE_INDEX is set and valid -> use that index
        2) Else if NDR_INTERFACE is set and matches a name -> use that name
        3) Else:
            - if running interactively (tty) -> ask user
            - if non-interactive (Docker, service) -> auto-pick first non-lo iface
    """
    interfaces = list_interfaces()

    # 1) Env: index
    if DEFAULT_INTERFACE_INDEX and DEFAULT_INTERFACE_INDEX.isdigit():
        idx = int(DEFAULT_INTERFACE_INDEX)
        if 0 <= idx < len(interfaces):
            iface = interfaces[idx]
            logger.info("Using interface index from env: %s -> %s", idx, iface)
            print(f"Using interface index from env: [{idx}] {iface}")
            return iface
        else:
            logger.warning(
                "NDR_INTERFACE_INDEX=%s out of range (0..%d).",
                DEFAULT_INTERFACE_INDEX,
                len(interfaces) - 1,
            )

    # 2) Env: name
    if DEFAULT_INTERFACE:
        logger.info("Attempting to use interface from env: %s", DEFAULT_INTERFACE)
        if DEFAULT_INTERFACE in interfaces:
            print(f"Using interface from environment: {DEFAULT_INTERFACE}")
            return DEFAULT_INTERFACE
        else:
            logger.warning(
                "Interface '%s' from env not found in detected interfaces.",
                DEFAULT_INTERFACE,
            )
            print(
                f"[!] Interface '{DEFAULT_INTERFACE}' not found. "
                "Falling back to auto-selection / manual selection."
            )

    # 3) Non-interactive environment (e.g. Docker, service): no input()
    if not sys.stdin.isatty():
        # Prefer first non-loopback interface, else fall back to first one
        non_lo = [i for i in interfaces if i != "lo"]
        if non_lo:
            iface = non_lo[0]
        else:
            iface = interfaces[0]
        logger.info("Non-interactive mode: auto-selected interface '%s'", iface)
        print(f"Auto-selected interface: {iface}")
        return iface

    # 4) Interactive: ask the operator
    iface = choose_interface(interfaces)
    return iface


# ---------------------------------------------------------------------------
# Packet handling and metadata extraction
# ---------------------------------------------------------------------------


def packet_to_metadata(pkt) -> Optional[Dict]:
    """
    Convert a Scapy packet into a minimal metadata dictionary.
    """
    if IP not in pkt:
        return None

    ip_layer = pkt[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    protocol = "OTHER"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    if TCP in pkt:
        protocol = "TCP"
        src_port = int(pkt[TCP].sport)
        dst_port = int(pkt[TCP].dport)
    elif UDP in pkt:
        protocol = "UDP"
        src_port = int(pkt[UDP].sport)
        dst_port = int(pkt[UDP].dport)

    size = len(pkt)

    metadata = {
        "timestamp": time.time(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "size": size,
    }

    return metadata


_send_error_count: int = 0


def send_metadata(metadata: Dict) -> None:
    """
    Send metadata to the NDR backend API.
    """
    global _send_error_count

    try:
        resp = httpx.post(API_URL, json=metadata, timeout=HTTP_TIMEOUT_SECONDS)
        resp.raise_for_status()
    except RequestError as exc:
        _send_error_count += 1
        logger.warning("Failed to send metadata to API: %s", exc)

        if _send_error_count == 1:
            print(
                "[!] Failed to send metadata to API. "
                "Check connectivity and backend status."
            )
        elif _send_error_count % MAX_SEND_ERRORS_BEFORE_WARN == 0:
            print(
                f"[!] Repeated send failures ({_send_error_count} errors). "
                "API might be down or unreachable."
            )
    except Exception as exc:
        _send_error_count += 1
        logger.exception("Unexpected error while sending metadata: %s", exc)


def handle_packet(pkt) -> None:
    """
    Callback invoked by Scapy for each captured packet.
    """
    metadata = packet_to_metadata(pkt)
    if metadata is None:
        return
    send_metadata(metadata)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """
    Main entry point for the capture agent.
    """
    print("\n=== NDR Capture Module ===")
    print(f"API URL   : {API_URL}")
    print(f"Platform  : {sys.platform}")
    print("------------------------------")

    iface = resolve_interface()

    print(f"\n[+] Starting capture on interface: {iface}")
    print("[+] Press CTRL+C to stop.\n")
    logger.info("Starting capture on interface: %s", iface)

    try:
        sniff(iface=iface, prn=handle_packet, store=False)
    except PermissionError:
        logger.error("Permission denied while opening interface '%s'.", iface)
        print("\n[ERROR] Permission denied while opening the interface.")
        print("        On Windows: run the script as Administrator.")
        print("        On Linux  : run with sudo or appropriate capabilities.")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Capture interrupted by user (KeyboardInterrupt).")
        print("\n[*] Capture interrupted by user. Exiting.")
        sys.exit(0)
    except Exception as exc:
        logger.exception("Unexpected error during capture: %s", exc)
        print(f"\n[ERROR] Unexpected error during capture: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
