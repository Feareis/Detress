from __future__ import annotations

import logging
import os
from collections import deque, defaultdict
from datetime import datetime, timedelta
from threading import Lock
from typing import Deque, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, validator

# ---------------------------------------------------------------------------
# Basic logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("detress-lite")


# ---------------------------------------------------------------------------
# FastAPI application and static assets configuration
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Detress",
    description="Simple Network Detection & Response API",
    version="0.2.0",
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Mount static directory for web assets
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
    """
    Simple HTML dashboard served directly by FastAPI.

    Note:
        - This is intentionally minimal and file-based.
        - In a production setup, this would be hosted behind a reverse proxy
          or served as a separate frontend.
    """
    index_path = os.path.join(STATIC_DIR, "index.html")

    if not os.path.exists(index_path):
        logger.error("index.html not found in static directory: %s", STATIC_DIR)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Dashboard asset missing (index.html). Contact administrator.",
        )

    try:
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError as exc:
        logger.exception("Failed to read index.html: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to load dashboard content.",
        ) from exc


# ---------------------------------------------------------------------------
# Pydantic models (input / output)
# ---------------------------------------------------------------------------


class TrafficIn(BaseModel):
    """
    Minimal traffic metadata model as received from the capture agent.

    This is intentionally limited (no payload, no PII, no DPI) to keep
    focus on metadata-driven detection.
    """

    timestamp: float = Field(
        ...,
        description="Unix timestamp (float seconds since epoch) as seen by the capture agent.",
    )
    src_ip: str = Field(..., description="Source IP address.")
    dst_ip: str = Field(..., description="Destination IP address.")
    src_port: Optional[int] = Field(
        None, ge=0, le=65535, description="Source TCP/UDP port, if applicable."
    )
    dst_port: Optional[int] = Field(
        None, ge=0, le=65535, description="Destination TCP/UDP port, if applicable."
    )
    protocol: str = Field(
        ...,
        description="L4 protocol as string (e.g., 'TCP', 'UDP', 'ICMP', 'OTHER').",
    )
    size: Optional[int] = Field(
        None,
        ge=0,
        description="Packet size in bytes (as observed by the capture module).",
    )

    @validator("protocol")
    def normalize_protocol(cls, v: str) -> str:
        """Normalize protocol name to uppercase for consistent rule matching."""
        return v.upper().strip()


class Alert(BaseModel):
    """
    Alert model used both for in-memory storage and API response.

    Note:
        - In a production SOC stack, alerts would likely be persisted into
          a SIEM, message bus, or ticketing system rather than in-memory only.
    """

    id: int
    timestamp: datetime
    level: str
    category: str
    message: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None


# ---------------------------------------------------------------------------
# In-memory storage (PoC / lab only)
# ---------------------------------------------------------------------------

MAX_TRAFFIC_EVENTS: int = 1000
traffic_events: Deque[TrafficIn] = deque(maxlen=MAX_TRAFFIC_EVENTS)

alerts: List[Alert] = []

# Alert id counter + lock (avoid race conditions if multi-worker later)
_alert_id_counter: int = 1
_alert_id_lock = Lock()

# For basic port scan detection: track recent connection timestamps per source IP
connection_history: Dict[str, Deque[datetime]] = defaultdict(
    lambda: deque(maxlen=200)
)

# ---------------------------------------------------------------------------
# Rule parameters (tunable detection logic)
# ---------------------------------------------------------------------------

# Time window used for basic "burst" port scan detection
PORT_SCAN_WINDOW: timedelta = timedelta(seconds=10)

# Number of events per source IP within PORT_SCAN_WINDOW to trigger an alert
PORT_SCAN_THRESHOLD: int = 20

# Ports considered sensitive / high-value targets in typical environments
SENSITIVE_PORTS = {22, 23, 3389, 445, 5900}  # SSH, Telnet, RDP, SMB, VNC


# ---------------------------------------------------------------------------
# Alert utilities and rule engine
# ---------------------------------------------------------------------------


def get_next_alert_id() -> int:
    """
    Thread-safe incrementing alert identifier.

    While FastAPI is single-process by default in this setup, we use a lock
    here to be explicit about concurrency and avoid race conditions if the
    runtime model changes (e.g. multiple workers).
    """
    global _alert_id_counter
    with _alert_id_lock:
        current = _alert_id_counter
        _alert_id_counter += 1
    return current


def create_alert(
    level: str,
    category: str,
    message: str,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
) -> Alert:
    """
    Create an alert object and push it into the in-memory alert list.

    This function centralizes alert instantiation and logging to ensure
    consistent behavior and auditability.
    """
    alert = Alert(
        id=get_next_alert_id(),
        timestamp=datetime.utcnow(),
        level=level,
        category=category,
        message=message,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )

    alerts.append(alert)

    # Log at INFO level so that an analyst can tail logs and see alert creation
    logger.info(
        "Alert created | id=%s level=%s category=%s src_ip=%s dst_ip=%s dst_port=%s message=%s",
        alert.id,
        alert.level,
        alert.category,
        alert.src_ip,
        alert.dst_ip,
        alert.dst_port,
        alert.message,
    )

    return alert


def _rule_port_scan(event: TrafficIn, now: datetime) -> Optional[Alert]:
    """
    Basic burst-based port scan detection.

    Logic:
        - Track a sliding window of events per src_ip.
        - If the number of events from a single src_ip in PORT_SCAN_WINDOW
          exceeds PORT_SCAN_THRESHOLD, raise an alert.

    Limitations:
        - Does not differentiate per-destination host.
        - Does not track unique destination ports (only volume).
        - Intended as a simple PoC rule.
    """
    if not event.src_ip:
        return None

    history = connection_history[event.src_ip]
    history.append(now)

    # Remove stale entries outside the detection window
    while history and (now - history[0]) > PORT_SCAN_WINDOW:
        history.popleft()

    if len(history) >= PORT_SCAN_THRESHOLD:
        msg = (
            f"Possible port scan detected from {event.src_ip} "
            f"({len(history)} connections in {PORT_SCAN_WINDOW.seconds}s)"
        )
        alert = create_alert(
            level="high",
            category="port_scan",
            message=msg,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
        )

        # Reset history to avoid spamming alerts for the same burst
        history.clear()
        return alert

    return None


def _rule_sensitive_ports(event: TrafficIn) -> Optional[Alert]:
    """
    Detect connections to ports known to be sensitive in a typical environment.

    This rule is intentionally simple and should be considered as a generic
    heuristic rather than a stand-alone incident indicator.
    """
    if event.dst_port in SENSITIVE_PORTS:
        msg = (
            f"Connection to sensitive port {event.dst_port} "
            f"from {event.src_ip} to {event.dst_ip}"
        )
        return create_alert(
            level="medium",
            category="sensitive_port",
            message=msg,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
        )
    return None


def apply_rules(event: TrafficIn) -> List[Alert]:
    """
    Apply a minimal set of detection rules to a single traffic event.

    Rules included:
        - _rule_port_scan: burst-based scan detection
        - _rule_sensitive_ports: simple heuristic on sensitive ports

    Returns:
        List of Alert instances generated for this event (can be empty).
    """
    generated: List[Alert] = []
    now = datetime.utcnow()

    try:
        # Rule 1: basic burst port scan
        port_scan_alert = _rule_port_scan(event, now)
        if port_scan_alert:
            generated.append(port_scan_alert)

        # Rule 2: connection to sensitive ports
        sensitive_port_alert = _rule_sensitive_ports(event)
        if sensitive_port_alert:
            generated.append(sensitive_port_alert)

    except Exception as exc:
        # Any unexpected failure in the rule engine is logged but does not
        # break the ingestion pipeline.
        logger.exception("Error while applying rules: %s", exc)

    return generated


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------


@app.post("/traffic")
async def ingest_traffic(event: TrafficIn):
    """
    Ingest a single traffic event produced by the capture module.

    Behavior:
        - Store event in an in-memory ring buffer.
        - Apply detection rules.
        - Return basic status and number of alerts generated.
    """
    try:
        traffic_events.append(event)
        generated_alerts = apply_rules(event)
    except Exception as exc:
        logger.exception("Failed to ingest traffic event: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error while processing traffic event.",
        ) from exc

    return {
        "status": "ok",
        "alerts_generated": len(generated_alerts),
    }


@app.get("/traffic", response_model=List[TrafficIn])
async def get_recent_traffic(
    limit: int = Query(
        100,
        ge=1,
        le=MAX_TRAFFIC_EVENTS,
        description="Maximum number of most recent events to return.",
    )
):
    """
    Return the most recent traffic events from the in-memory buffer.
    """
    try:
        events = list(traffic_events)[-limit:]
        return events
    except Exception as exc:
        logger.exception("Failed to read recent traffic: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve recent traffic.",
        ) from exc


@app.get("/alerts", response_model=List[Alert])
async def get_alerts(
    limit: int = Query(
        100,
        ge=1,
        description="Maximum number of most recent alerts to return.",
    )
):
    """
    Return the most recent alerts generated by the rule engine.
    """
    try:
        return alerts[-limit:]
    except Exception as exc:
        logger.exception("Failed to read alerts: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve alerts.",
        ) from exc


@app.get("/health")
async def health():
    """
    Basic health check endpoint.
    """
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
