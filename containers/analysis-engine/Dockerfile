# containers/analysis-engine/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including Docker client
RUN apt-get update && apt-get install -y \
    curl \
    git \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY containers/analysis-engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY shared/ ./shared/
COPY config/ ./config/

# Copy analysis tools and source code
COPY containers/analysis-engine/tools/ ./tools/
COPY containers/analysis-engine/analysis_server.py .
COPY containers/analysis-engine/ghidra_server.py .
COPY containers/analysis-engine/windbg_server.py .

EXPOSE 8001 8002

CMD ["python", "-m", "uvicorn", "analysis_server:app", "--host", "0.0.0.0", "--port", "8001"]
