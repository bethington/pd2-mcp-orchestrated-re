# containers/mcp-coordinator/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY containers/mcp-coordinator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY shared/ ./shared/
COPY config/ ./config/

# Copy coordinator scripts
COPY containers/mcp-coordinator/src/ ./src/
COPY containers/mcp-coordinator/scripts/entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 8000 9000

CMD ["./entrypoint.sh"]
