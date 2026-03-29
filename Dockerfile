FROM python:3.13-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 sentricore && \
    chown -R sentricore:sentricore /app

USER sentricore

# Expose DNS (UDP) and web dashboard ports
EXPOSE 5300/udp 5000/tcp

# Start both services
CMD ["sh", "-c", "python app/dns/proxy.py & python -m flask --app app.web.app run --host 0.0.0.0 --port 5000"]
