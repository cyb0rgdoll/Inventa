# Setup Scanning Tools for Inventa

Your Inventa enhanced scanner needs **Nmap** and **Masscan** to work properly.

---

## Quick Setup (Recommended)

### Linux (Ubuntu/Debian)
```bash
# Automatic installation
bash scripts/install-scanning-tools.sh

# Or manual installation
sudo apt-get install -y nmap masscan nmap-scripts
```

### macOS
```bash
# Using Homebrew
brew install nmap masscan
```

### Docker (All-in-one)
```bash
# Build Docker image with all tools
docker build -t inventa-scanner .
docker run -it inventa-scanner bash
```

---

## What Gets Installed

| Tool | Purpose | Package |
|------|---------|---------|
| **Nmap** | Port scanning + service detection | `nmap` |
| **Masscan** | Fast port discovery (10x faster) | `masscan` |
| **NSE Scripts** | Deep service enumeration | `nmap-scripts` |

---

## Verify Installation

```bash
# Check Nmap
nmap --version
ls /usr/share/nmap/scripts/ | wc -l  # Should show 40+

# Check Masscan
masscan --version

# Quick test
nmap -p 22 localhost -Pn
```

---

## Why These Tools?

### Nmap (`nmap`)
- **Port discovery:** Finds open ports (standard approach)
- **Service detection:** Identifies services running on ports (-sV)
- **NSE scripts:** 40+ automation scripts for enumeration
- **Part of:** Inventa Phase 2 & 3

### Masscan (`masscan`)
- **Speed:** 10x faster than Nmap for port discovery
- **Approach:** Asynchronous scanning
- **Use case:** Fast initial sweep before detailed Nmap scan
- **Part of:** Inventa Phase 1

### NSE Scripts (`nmap-scripts`)
- **Deep enumeration:** Extract detailed service info
- **Common services:** SMB, SSH, HTTP, SSL/TLS, SNMP, etc.
- **Count:** 40+ scripts covering service discovery, vulnerability checks
- **Part of:** Inventa Phase 3 (enumeration)

---

## How Inventa Uses These Tools

```
Your Scanner Input: 10.0.2.5
                         ↓
    [Phase 1] Masscan sweep (10 seconds)
              → Find ~26 open ports
                         ↓
    [Phase 2] Nmap scan (-sV -p 1-10000)
              → Confirm ports + service versions
                         ↓
    [Phase 3] NSE enumeration (40+ scripts)
              → Extract SMB shares, SSH keys, HTTP headers, etc.
                         ↓
    [Phase 4] Fingerprint & correlate
              → Merge all data into unified report
                         ↓
    Output: 26 ports + 40+ NSE findings
```

---

## Troubleshooting

### Masscan not working?
```bash
# If not in /usr/bin/masscan, compile from source
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
sudo make install
```

### NSE scripts not found?
```bash
# Download/install NSE scripts
sudo apt-get install -y nmap-scripts

# Or manually download
mkdir -p /usr/share/nmap/scripts/
cd /usr/share/nmap/scripts/
svn co https://svn.nmap.org/nmap/scripts/
```

### Permission denied when running Nmap?
```bash
# Nmap needs sudo for certain operations
sudo nmap -p 1-10000 <target>

# Or use capabilities instead of sudo
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/nmap
nmap -p 1-10000 <target>  # No sudo needed
```

---

## Installation Script

Automated installation is provided:

```bash
# Make it executable
chmod +x scripts/install-scanning-tools.sh

# Run it
bash scripts/install-scanning-tools.sh
```

This will:
1. Install Nmap with NSE scripts
2. Install Masscan (compile if needed)
3. Verify all tools are working
4. Run quick tests

---

## Expected Output After Setup

```bash
$ python3 inventa.py doctor

[Standard Nmap] Scanning 10.0.2.5...
[+] Found 26 open ports

[Enhanced Inventa] Scanning 10.0.2.5...
[Phase 1] Masscan: 26 ports in 2 seconds
[Phase 2] Nmap scan: 26 ports confirmed
[Phase 3] NSE scripts: 40+ findings
[+] Enhanced Inventa: Found 26 ports + 40 NSE items

✓ SUCCESS: Full port discovery + deep enumeration!
```

---

## Next Steps

1. **Run setup:** `bash scripts/install-scanning-tools.sh`
2. **Verify:** Check that all tools are installed
3. **Test:** Run your first authorized scan
   ```bash
   python3 inventa.py scan
   ```
4. **Review:** Check results in `evaluation/results/`

---

## Verification

Once tools are installed:
- ✅ Masscan works (Phase 1)
- ✅ Nmap works (Phase 2)
- ✅ NSE scripts work (Phase 3)
- ✅ Full discovery workflows are available

---

**Questions?** Check `TROUBLESHOOTING.md` for common issues.

---

## Optional External Recon Tools

Inventa can drive several third-party recon tools when they are present. These
are **not** bundled in the repository (to avoid redistributing other projects'
code and licenses). Inventa detects whether each one is installed and skips it
gracefully if it is missing — install only the ones you need.

Clone each into the root `tools/` directory (git-ignored) using the path
Inventa expects:

```bash
mkdir -p tools

# Subdomain / DNS / cloud recon
git clone https://github.com/initstring/cloud_enum.git   tools/cloud_enum
pip install -r tools/cloud_enum/requirements.txt

git clone https://github.com/codingo/VHostScan.git       tools/VHostScan
pip install -e tools/VHostScan

git clone https://github.com/bhavsec/reconspider.git     tools/reconspider
```

Other optional integrations Inventa recognises (install from their upstream
projects into the matching `tools/<name>/` path, or via `install.sh`):
CloudScraper → `tools/CloudScraper`, Striker → `tools/Striker`,
inSp3ctor → `tools/inSp3ctor`, plus binary scanners `naabu`, `zmap`, and
`smap` (see `scripts/install-scanning-tools.sh`).

### zgrab2 (git submodule)

`zgrab2` is tracked as a git submodule. After cloning Inventa:

```bash
git submodule update --init --recursive
# build it (requires Go):
cd tools/zgrab2 && make && cd ../..
```

If you started a fresh repository and need to add it:

```bash
git submodule add https://github.com/zmap/zgrab2.git tools/zgrab2
```

> Anything you place under `tools/` is git-ignored by design — external tool
> source should never be committed into Inventa's repository.
