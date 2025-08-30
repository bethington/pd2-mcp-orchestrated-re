# containers/ghidra-analysis/Dockerfile
FROM openjdk:17-jdk-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    python3 \
    python3-pip \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create analysis user
RUN useradd -m -s /bin/bash analysis
USER analysis
WORKDIR /app

# Download and install Ghidra
ARG GHIDRA_VERSION=11.0.1
ARG GHIDRA_BUILD=20240130
RUN wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip \
    && unzip ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip \
    && mv ghidra_${GHIDRA_VERSION}_PUBLIC ghidra \
    && rm ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip

# Set environment variables
ENV GHIDRA_INSTALL_DIR=/app/ghidra
ENV PATH="${GHIDRA_INSTALL_DIR}/support:${PATH}"

# Install Python dependencies for MCP server
COPY containers/ghidra-analysis/requirements.txt /tmp/requirements.txt
RUN pip3 install --user -r /tmp/requirements.txt

# Create directories
RUN mkdir -p /app/{exports,pd2,project}

# Copy Ghidra scripts and MCP server
COPY containers/ghidra-analysis/scripts/ /app/scripts/
COPY containers/ghidra-analysis/ghidra_server.py /app/
COPY containers/ghidra-analysis/headless_analyzer.py /app/
COPY shared/ /app/shared/

# Set Python path
ENV PYTHONPATH=/app:/app/shared

# Expose MCP server port
EXPOSE 8002

CMD ["python3", "/app/ghidra_server.py"]