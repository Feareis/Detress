FROM python:3.12-slim

# Install basic system dependencies for Scapy & networking
RUN apt-get update && apt-get install -y \
    iproute2 \
    tcpdump \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY backend ./backend
COPY capture ./capture
COPY entrypoint.sh ./entrypoint.sh

# Python dependencies
RUN pip install --no-cache-dir \
    fastapi \
    "uvicorn[standard]" \
    httpx \
    requests \
    scapy

# Environment defaults
ENV NDR_API_URL="http://127.0.0.1:8000/traffic"
# Default interface index = 3
ENV NDR_INTERFACE_INDEX="3"

# Make sure entrypoint is executable
RUN chmod +x /app/entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
