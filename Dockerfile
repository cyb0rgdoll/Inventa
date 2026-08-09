# Inventa community scanner image.
# Includes Python, nmap, masscan, and common network utilities.

FROM python:3.13-slim

LABEL maintainer="cyb0rgdoll"
LABEL description="Inventa defensive asset discovery scanner"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    dnsutils \
    git \
    iproute2 \
    iputils-ping \
    jq \
    libcap2-bin \
    masscan \
    net-tools \
    netcat-openbsd \
    nmap \
    openssh-client \
    python3-dev \
    whois \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /inventa

COPY requirements.txt /tmp/inventa-requirements.txt
RUN pip install --no-cache-dir -r /tmp/inventa-requirements.txt

COPY inventa.py /inventa/
COPY analysis/ /inventa/analysis/
COPY core/ /inventa/core/
COPY lib/ /inventa/lib/
COPY modules/ /inventa/modules/
COPY recon/ /inventa/recon/
COPY reporting/ /inventa/reporting/
COPY scanning/ /inventa/scanning/
COPY agent/ /inventa/agent/
COPY scope.txt targets.txt /inventa/

RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/nmap || true && \
    setcap cap_net_raw,cap_net_admin=eip /usr/bin/masscan || true

RUN useradd -m -u 1000 inventa && \
    chown -R inventa:inventa /inventa

USER inventa

ENTRYPOINT ["python3", "inventa.py"]
CMD ["--help"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 inventa.py doctor >/dev/null || exit 1
