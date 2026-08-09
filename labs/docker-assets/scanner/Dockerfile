FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        awscli \
        build-essential \
        curl \
        dnsutils \
        iproute2 \
        nmap \
        netcat-openbsd \
        python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY requirements.txt /tmp/inventa-requirements.txt
RUN pip install --no-cache-dir -r /tmp/inventa-requirements.txt

ENTRYPOINT ["python3", "inventa.py"]
