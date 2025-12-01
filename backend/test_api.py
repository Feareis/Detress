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
        True if API responds with status: ok
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
        else:
            print("[!] API responded but status != ok:", data)
            return False

    except RequestException as exc:
        print(f"[!] Health check failed: {exc}")
        return False


def send_test_traffic() -> None:
    """
    Send a synthetic traffic event to exercise the backend rule engine.
    This event should generate a "sensitive_port" alert (dst_port=22).
    """

    event = {
        "timestamp": time.time(),
        "src_ip": "10.0.0.5",
        "dst_ip": "192.168.0.10",
        "src_port": 12345,
        "dst_port": 22,          # Sensitive port → should trigger alert
        "protocol": "TCP",
        "size": 60,
    }

    print("[*] Sending test traffic event:", event)

    try:
        r = requests.post(TRAFFIC_ENDPOINT, json=event, timeout=3)
        r.raise_for_status()
        print("[+] Traffic POST status:", r.status_code)
        print("[+] Backend response:", r.json())

    except RequestException as exc:
        print(f"[!] Failed to send traffic event: {exc}")


def fetch_alerts(limit: int = 20) -> None:
    """
    Fetch most recent alerts from backend.

    Args:
        limit: number of alerts to retrieve (default = 20)
    """

    print(f"[*] Fetching last {limit} alerts...")

    try:
        r = requests.get(f"{ALERTS_ENDPOINT}?limit={limit}", timeout=3)
        r.raise_for_status()
        alerts = r.json()

        if not alerts:
            print("[!] No alerts returned.")
            return

        print(f"[+] Retrieved {len(alerts)} alerts:")
        for a in alerts:
            print(f"  - [ID {a['id']}] [{a['level']}] {a['category']} → {a['message']}")

    except RequestException as exc:
        print(f"[!] Failed to retrieve alerts: {exc}")


def main():
    print("=== Detress Lite API Test Client ===\n")

    if not check_api_health():
        print("[X] API not healthy. Aborting test.")
        return

    send_test_traffic()
    time.sleep(0.5)  # Give the backend rule engine time to generate alerts
    fetch_alerts(limit=10)

    print("\n=== Test finished ===")


if __name__ == "__main__":
    main()
