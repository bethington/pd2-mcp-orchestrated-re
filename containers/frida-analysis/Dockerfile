# containers/frida-analysis/Dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    gdb \
    strace \
    ltrace \
    procps \
    psmisc \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY containers/frida-analysis/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Frida scripts and server
COPY containers/frida-analysis/frida_server.py .
COPY containers/frida-analysis/dynamic_analyzer.py .
COPY containers/frida-analysis/scripts/ ./scripts/
COPY shared/ ./shared/

# Set Python path
ENV PYTHONPATH=/app:/app/shared

# Expose API port
EXPOSE 8003

CMD ["python", "frida_server.py"]