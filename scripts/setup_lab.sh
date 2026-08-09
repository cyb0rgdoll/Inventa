#!/bin/bash
# Inventa Lab Setup — Docker on WSL2 (Kali/Debian)
# Creates a hybrid network test environment (cloud enumeration via real AWS)
#
# Architecture:
#   corp-lan (172.20.1.0/24) — Internal corporate network
#     - web-server     172.20.1.20  (Apache + SSH)
#     - db-server      172.20.1.21  (MySQL + SSH)
#     - file-server    172.20.1.22  (Samba/FTP + SSH)
#
#   dmz-net (172.20.2.0/24) — Hybrid boundary / DMZ
#     - dmz-web        172.20.2.20  (Nginx + FTP + SSH)
#     - dmz-mail       172.20.2.21  (Postfix SMTP stub + SSH)
#
#   AWS Cloud — Real AWS resources (requires configured credentials)
#
#   Host (WSL2) acts as scanner node on both networks
#
# Total ground-truth assets: 6+ containers + real AWS resources

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} Inventa Hybrid Lab Setup${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# --- Step 1: Create Docker networks ---
echo -e "${YELLOW}[1/5] Creating Docker networks...${NC}"

docker network create --subnet=172.20.1.0/24 corp-lan 2>/dev/null && \
  echo -e "  ${GREEN}✓ corp-lan (172.20.1.0/24) created${NC}" || \
  echo -e "  ${YELLOW}~ corp-lan already exists${NC}"

docker network create --subnet=172.20.2.0/24 dmz-net 2>/dev/null && \
  echo -e "  ${GREEN}✓ dmz-net (172.20.2.0/24) created${NC}" || \
  echo -e "  ${YELLOW}~ dmz-net already exists${NC}"

echo ""

# --- Step 2: Start corporate network containers ---
echo -e "${YELLOW}[2/5] Starting corporate network assets...${NC}"

# Web Server (Apache + SSH)
docker run -d \
  --name inventa-web-server \
  --hostname web-server \
  --network corp-lan \
  --ip 172.20.1.20 \
  debian:12-slim \
  bash -c "
    apt-get update -qq && \
    apt-get install -y -qq apache2 openssh-server net-tools procps > /dev/null 2>&1 && \
    mkdir -p /run/sshd && \
    echo 'root:inventa' | chpasswd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    service ssh start && \
    apachectl -D FOREGROUND
  " 2>/dev/null
echo -e "  ${GREEN}✓ web-server (172.20.1.20) — Apache:80, SSH:22${NC}"

# Database Server (MySQL + SSH)
docker run -d \
  --name inventa-db-server \
  --hostname db-server \
  --network corp-lan \
  --ip 172.20.1.21 \
  -e MYSQL_ROOT_PASSWORD=inventatest \
  -e MYSQL_DATABASE=assets_db \
  mysql:8.0 2>/dev/null
echo -e "  ${GREEN}✓ db-server (172.20.1.21) — MySQL:3306${NC}"

# File Server (FTP + SSH)
docker run -d \
  --name inventa-file-server \
  --hostname file-server \
  --network corp-lan \
  --ip 172.20.1.22 \
  debian:12-slim \
  bash -c "
    apt-get update -qq && \
    apt-get install -y -qq vsftpd openssh-server net-tools procps > /dev/null 2>&1 && \
    mkdir -p /run/sshd && \
    echo 'root:inventa' | chpasswd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/listen=NO/listen=YES/' /etc/vsftpd.conf 2>/dev/null; \
    sed -i 's/listen_ipv6=YES/listen_ipv6=NO/' /etc/vsftpd.conf 2>/dev/null; \
    service ssh start && \
    vsftpd /etc/vsftpd.conf
  " 2>/dev/null
echo -e "  ${GREEN}✓ file-server (172.20.1.22) — FTP:21, SSH:22${NC}"

echo ""

# --- Step 3: Start DMZ containers ---
echo -e "${YELLOW}[3/5] Starting DMZ network assets...${NC}"

# DMZ Web Server (Nginx + SSH)
docker run -d \
  --name inventa-dmz-web \
  --hostname dmz-web \
  --network dmz-net \
  --ip 172.20.2.20 \
  debian:12-slim \
  bash -c "
    apt-get update -qq && \
    apt-get install -y -qq nginx openssh-server net-tools procps > /dev/null 2>&1 && \
    mkdir -p /run/sshd && \
    echo 'root:inventa' | chpasswd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    service ssh start && \
    nginx -g 'daemon off;'
  " 2>/dev/null
echo -e "  ${GREEN}✓ dmz-web (172.20.2.20) — Nginx:80, SSH:22${NC}"

# DMZ Mail Server (Postfix stub + SSH)
docker run -d \
  --name inventa-dmz-mail \
  --hostname dmz-mail \
  --network dmz-net \
  --ip 172.20.2.21 \
  debian:12-slim \
  bash -c "
    apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postfix openssh-server net-tools procps > /dev/null 2>&1 && \
    mkdir -p /run/sshd && \
    echo 'root:inventa' | chpasswd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    service ssh start && \
    postfix start && \
    tail -f /var/log/mail.log
  " 2>/dev/null
echo -e "  ${GREEN}✓ dmz-mail (172.20.2.21) — SMTP:25, SSH:22${NC}"

echo ""

# --- Step 4: AWS Cloud Enumeration Setup ---
echo -e "${YELLOW}[4/5] AWS cloud enumeration setup...${NC}"
echo -e "  ${GREEN}✓ LocalStack removed — using real AWS credentials${NC}"
echo -e "  ${YELLOW}ℹ Configure AWS credentials: aws configure${NC}"

echo ""

# --- Step 5: Connect scanner host to both networks ---
echo -e "${YELLOW}[5/5] Connecting WSL host to lab networks...${NC}"

# The host can reach containers directly via Docker networking
echo -e "  ${GREEN}✓ Host connected to corp-lan via Docker bridge${NC}"
echo -e "  ${GREEN}✓ Host connected to dmz-net via Docker bridge${NC}"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} Lab Setup Complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Ground-Truth Inventory (11 assets):"
echo "─────────────────────────────────────"
echo "  CORP-LAN (172.20.1.0/24):"
echo "    172.20.1.20  web-server     Debian 12  Apache:80, SSH:22"
echo "    172.20.1.21  db-server      MySQL 8.0  MySQL:3306"
echo "    172.20.1.22  file-server    Debian 12  FTP:21, SSH:22"
echo ""
echo "  DMZ-NET (172.20.2.0/24):"
echo "    172.20.2.20  dmz-web        Debian 12  Nginx:80, SSH:22"
echo "    172.20.2.21  dmz-mail       Debian 12  SMTP:25, SSH:22"
echo ""
echo "─────────────────────────────────────"
echo ""
echo "To scan with Inventa:"
echo "  # Configure AWS credentials"
echo "  aws configure"
echo ""
echo "  # Internal scan"
echo "  python3 inventa.py -s scope.txt -t targets.txt"
echo ""
echo "  # Cloud scan (requires AWS credentials)"
echo "  python3 inventa.py -s scope.txt --cloud-enum --cloud-provider aws"
echo ""
echo "To tear down:  bash scripts/teardown_lab.sh"
