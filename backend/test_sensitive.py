import time
import requests
from requests.exceptions import RequestException

API_BASE = "http://127.0.0.1:8000"
TRAFFIC_ENDPOINT = f"{API_BASE}/traffic"
ALERTS_ENDPOINT = f"{API_BASE}/alerts"
HEALTH_ENDPOINT = f"{API_BASE}/health"


def check_api_health() -> bool:
    """
    Check backend health endpoint to ensure API is reachable.

    Returns:
        True if API responds with {"status": "ok"}
        False otherwise
    """
    print("[*] Checking API health...")

    try:
        r = requests.get(HEALTH_ENDPOINT, timeout=2)
        r.raise_for_status()
        data = r.json()

        if data.get("status") == "ok":
            print("[+] API health: OK")
            return True

        print("[!] API responded but status != ok:", data)
        return False

    except RequestException as exc:
        print(f"[!] Health check failed: {exc}")
        return False


def send_sensitive_traffic_events(count: int = 3) -> None:
    """
    Send several synthetic traffic events targeting a sensitive port.

    Args:
        count: number of events to send (default: 3)

    These events target dst_port=3389 (RDP), which is part of SENSITIVE_PORTS
    in the backend, and should generate 'sensitive_port' alerts.
    """
    for i in range(count):
        event = {
            "timestamp": time.time(),
            "src_ip": "10.0.0.10",
            "dst_ip": "192.168.0.20",
            "src_port": 50000 + i,   # Slight variation per event
            "dst_port": 3389,        # RDP (sensitive port)
            "protocol": "TCP",
            "size": 80,
        }

        print(f"[*] Sending sensitive test event #{i + 1}: {event}")

        try:
            r = requests.post(TRAFFIC_ENDPOINT, json=event, timeout=3)
            r.raise_for_status()
            print("[+] Traffic POST status:", r.status_code, "| response:", r.json())
        except RequestException as exc:
            print(f"[!] Failed to send traffic event #{i + 1}: {exc}")


def fetch_recent_alerts(limit: int = 20) -> None:
    """
    Retrieve and display the most recent alerts from the backend.

    Args:
        limit: number of alerts to retrieve (default: 20)
    """
    print(f"[*] Fetching last {limit} alerts...")

    try:
        r = requests.get(f"{ALERTS_ENDPOINT}?limit={limit}", timeout=3)
        r.raise_for_status()
        alerts = r.json()
    except RequestException as exc:
        print(f"[!] Failed to retrieve alerts: {exc}")
        return

    if not alerts:
        print("[!] No alerts returned.")
        return

    print(f"[+] Retrieved {len(alerts)} alerts:")
    for a in alerts:
        level = a.get("level", "?")
        category = a.get("category", "?")
        msg = a.get("message", "")
        aid = a.get("id", "?")
        print(f"  - [ID {aid}] [{level}] {category} → {msg}")


def main():
    print("=== Detress Lite - Sensitive Port Rule Test ===\n")

    if not check_api_health():
        print("[X] API not healthy. Aborting test.")
        return

    # Send multiple connections to a sensitive port (RDP / 3389)
    send_sensitive_traffic_events(count=3)

    # Give the backend a bit of time to process and generate alerts
    time.sleep(0.5)

    # Retrieve and display alerts (we expect 'sensitive_port' entries)
    fetch_recent_alerts(limit=10)

    print("\n=== Test finished ===")


if __name__ == "__main__":
    main()
