# containers/memory-forensics/Dockerfile
FROM python:3.11-slim

# Install system dependencies for memory analysis
RUN apt-get update && apt-get install -y \
    build-essential \
    gdb \
    valgrind \
    strace \
    ltrace \
    binutils \
    elfutils \
    procps \
    psmisc \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY containers/memory-forensics/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY containers/memory-forensics/memory_forensics_server.py .
COPY containers/memory-forensics/advanced_memory_analyzer.py .
COPY containers/memory-forensics/heap_analyzer.py .
COPY containers/memory-forensics/memory_dump_analyzer.py .
COPY containers/memory-forensics/tools/ ./tools/
COPY shared/ ./shared/

# Set Python path
ENV PYTHONPATH=/app:/app/shared

# Create directories for analysis data
RUN mkdir -p /app/dumps /app/reports /app/temp

# Expose API port
EXPOSE 8004

CMD ["python", "memory_forensics_server.py"]