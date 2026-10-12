FROM python:3.11-slim

WORKDIR /app

# libpcap0.8 lets scapy load its optional pcap-based providers (not required
# for offline file parsing, but avoids warnings and enables all layers).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/uploads
ENV MAX_UPLOAD_MB=200
EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--timeout", "120", "app:app"]
