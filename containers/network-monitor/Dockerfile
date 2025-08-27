# containers/network-monitor/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including network tools
RUN apt-get update && apt-get install -y \
    tcpdump \
    wireshark-common \
    tshark \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY containers/network-monitor/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy network analysis tools
COPY containers/network-monitor/packet_analyzer.py .

CMD ["python", "packet_analyzer.py"]
