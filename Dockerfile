FROM python:3.13-slim

WORKDIR /app

# Install Python dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 sentricore && \
    mkdir -p /app/data /app/logs && \
    chown -R sentricore:sentricore /app

USER sentricore

# Expose DNS (UDP) and web dashboard ports
EXPOSE 5300/udp 5000/tcp

# Default to the DNS proxy; docker-compose overrides per service
CMD ["python", "-m", "app.dns.proxy"]