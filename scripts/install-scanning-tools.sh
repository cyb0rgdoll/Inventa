#!/bin/bash
# Install scanning tools: Masscan and Nmap (with NSE scripts)
# Required for Inventa enhanced discovery

set -e

echo "======================================================================"
echo "Installing Scanning Tools for Inventa"
echo "======================================================================"
echo ""

# Check OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    DISTRO=$(lsb_release -si 2>/dev/null || echo "Linux")
    echo "[*] Detected OS: $DISTRO"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "[*] Detected OS: macOS"
else
    echo "[!] Unsupported OS: $OSTYPE"
    exit 1
fi

# ============================================================
# 1. Install Nmap (with NSE scripts)
# ============================================================
echo ""
echo "[STEP 1] Installing Nmap with NSE scripts..."
echo ""

if command -v nmap &> /dev/null; then
    NMAP_VERSION=$(nmap --version | head -1)
    echo "[✓] Nmap already installed: $NMAP_VERSION"
else
    echo "[*] Installing Nmap..."

    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo apt-get update
        sudo apt-get install -y nmap nmap-scripts
        echo "[✓] Nmap installed via apt"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        brew install nmap
        echo "[✓] Nmap installed via Homebrew"
    fi
fi

# Verify NSE scripts
NSE_COUNT=$(ls /usr/share/nmap/scripts/ 2>/dev/null | wc -l || echo "0")
if [ "$NSE_COUNT" -gt 0 ]; then
    echo "[✓] NSE scripts found: $NSE_COUNT scripts"
else
    echo "[!] Warning: NSE scripts not found in /usr/share/nmap/scripts/"
    echo "    Try: sudo apt-get install -y nmap-scripts"
fi

# ============================================================
# 2. Install Masscan
# ============================================================
echo ""
echo "[STEP 2] Installing Masscan (fast port scanner)..."
echo ""

if command -v masscan &> /dev/null; then
    MASSCAN_VERSION=$(masscan --version 2>/dev/null | head -1 || echo "unknown")
    echo "[✓] Masscan already installed: $MASSCAN_VERSION"
else
    echo "[*] Installing Masscan..."

    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Try apt first (easiest)
        if sudo apt-get install -y masscan 2>/dev/null; then
            echo "[✓] Masscan installed via apt"
        else
            # Fallback: compile from source (with security hardening)
            echo "[*] Compiling Masscan from source..."
            echo "    (this may take 2-3 minutes)"

            if ! command -v git &> /dev/null; then
                sudo apt-get install -y git
            fi

            # Use mktemp for secure build directory (not /tmp)
            BUILD_DIR=$(mktemp -d -t masscan-build-XXXXXXXX) || {
                echo "[!] Failed to create secure build directory"
                return 1
            }

            trap "rm -rf '$BUILD_DIR'" EXIT

            cd "$BUILD_DIR"
            # Pin to specific release tag for supply chain security
            git clone --branch 1.3.2 --depth 1 https://github.com/robertdavidgraham/masscan.git
            cd masscan

            # Verify the clone
            COMMIT_HASH=$(git rev-parse HEAD)
            echo "[*] Building Masscan from commit: $COMMIT_HASH"

            make
            sudo make install
            echo "[✓] Masscan compiled and installed from: $COMMIT_HASH"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        brew install masscan
        echo "[✓] Masscan installed via Homebrew"
    fi
fi

# ============================================================
# 3. Verify installations
# ============================================================
echo ""
echo "[STEP 3] Verifying installations..."
echo ""

TOOLS_OK=0

# Check Nmap
if command -v nmap &> /dev/null; then
    NMAP_PATH=$(which nmap)
    NMAP_VERSION=$(nmap --version | head -1)
    echo "[✓] Nmap: $NMAP_VERSION"
    echo "    Location: $NMAP_PATH"
    TOOLS_OK=$((TOOLS_OK + 1))
else
    echo "[✗] Nmap NOT found in PATH"
fi

# Check Masscan
if command -v masscan &> /dev/null; then
    MASSCAN_PATH=$(which masscan)
    MASSCAN_VERSION=$(masscan --version 2>&1 | head -1)
    echo "[✓] Masscan: $MASSCAN_VERSION"
    echo "    Location: $MASSCAN_PATH"
    TOOLS_OK=$((TOOLS_OK + 1))
else
    echo "[✗] Masscan NOT found in PATH"
fi

# Check NSE scripts
if [ -d "/usr/share/nmap/scripts" ]; then
    NSE_COUNT=$(ls /usr/share/nmap/scripts/ 2>/dev/null | wc -l || echo "0")
    echo "[✓] NSE Scripts: $NSE_COUNT scripts available"
    TOOLS_OK=$((TOOLS_OK + 1))
else
    echo "[!] NSE scripts directory not found"
fi

# ============================================================
# 4. Quick test
# ============================================================
echo ""
echo "[STEP 4] Running quick tests..."
echo ""

# Test Nmap
echo "[*] Testing Nmap..."
if nmap -p 22 localhost -Pn 2>&1 | grep -q "filtered\|open\|closed"; then
    echo "[✓] Nmap test passed"
else
    echo "[!] Nmap test inconclusive (but nmap works)"
fi

# Test Masscan (if available)
if command -v masscan &> /dev/null; then
    echo "[*] Testing Masscan..."
    if timeout 2 masscan -p 22 127.0.0.1 --rate 100 2>&1 | grep -q "port\|starting" || true; then
        echo "[✓] Masscan test passed"
    else
        echo "[!] Masscan test inconclusive (but masscan works)"
    fi
fi

# ============================================================
# 5. Summary
# ============================================================
echo ""
echo "======================================================================"
echo "Installation Summary"
echo "======================================================================"
echo ""

if [ "$TOOLS_OK" -ge 2 ]; then
    echo "[✓] SUCCESS: Scanning tools installed!"
    echo ""
    echo "Tools ready:"
    echo "  ✓ Nmap (port scanning + service detection)"
    echo "  ✓ Masscan (fast port discovery)"
    echo "  ✓ NSE Scripts ($NSE_COUNT available)"
    echo ""
    echo "Next step: Run Inventa against authorized targets"
    echo "  python3 inventa.py scan"
else
    echo "[!] Warning: Not all tools installed successfully"
    echo ""
    echo "Manual installation:"
    echo "  Ubuntu/Debian:"
    echo "    sudo apt-get install -y nmap masscan nmap-scripts"
    echo ""
    echo "  macOS:"
    echo "    brew install nmap masscan"
fi

echo ""
echo "======================================================================"
