# containers/web-dashboard/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY containers/web-dashboard/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy dashboard application
COPY containers/web-dashboard/app.py .
COPY containers/web-dashboard/static/ ./static/
COPY containers/web-dashboard/templates/ ./templates/

EXPOSE 80

CMD ["python", "app.py"]
