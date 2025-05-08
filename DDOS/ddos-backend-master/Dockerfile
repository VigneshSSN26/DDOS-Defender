FROM python:3.9-slim

WORKDIR /app

# Install system dependencies including build essentials
RUN apt-get update && apt-get install -y \
    tcpdump \
    hping3 \
    iptables \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as root for scapy and iptables
USER root

# Use PORT environment variable (required by Render)
CMD ["gunicorn", "--bind", "0.0.0.0:$PORT", "wsgi:app"]
