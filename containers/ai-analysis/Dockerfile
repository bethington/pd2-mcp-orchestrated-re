# containers/ai-analysis/Dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY containers/ai-analysis/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY containers/ai-analysis/ai_analysis_server.py .
COPY containers/ai-analysis/intelligent_analyzer.py .
COPY containers/ai-analysis/pattern_recognition.py .
COPY containers/ai-analysis/threat_classifier.py .
COPY containers/ai-analysis/automated_triage.py .
COPY containers/ai-analysis/ml_models/ ./ml_models/
COPY shared/ ./shared/

# Create directories
RUN mkdir -p /app/models /app/reports /app/training_data

# Set Python path
ENV PYTHONPATH=/app:/app/shared

# Expose API port
EXPOSE 8005

CMD ["python", "ai_analysis_server.py"]