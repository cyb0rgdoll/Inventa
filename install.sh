#!/bin/bash
# Inventa Community Installation Script

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

clear

echo -e "${CYAN}${BOLD}"
cat << 'EOF'
╔════════════════════════════════════════════════════════════╗
║              INVENTA INSTALLATION WIZARD                   ║
╚════════════════════════════════════════════════════════════╝
EOF
echo -e "${RESET}"

echo ""
echo -e "${CYAN}[*] Checking system requirements...${RESET}"
echo ""

# Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo -e "${GREEN}[✓]${RESET} Python 3: $PYTHON_VERSION"
else
    echo -e "${RED}[✗]${RESET} Python 3 not found"
    echo -e "${YELLOW}[!]${RESET} Please install Python 3.8 or higher"
    exit 1
fi

# pip3
if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}[✓]${RESET} pip3: Available"
else
    echo -e "${RED}[✗]${RESET} pip3 not found"
    exit 1
fi

# git
if command -v git &> /dev/null; then
    echo -e "${GREEN}[✓]${RESET} git: Available"
else
    echo -e "${YELLOW}[!]${RESET} git not found — external tool cloning will be skipped"
fi

# Nmap
if command -v nmap &> /dev/null; then
    NMAP_VERSION=$(nmap --version | head -1 | cut -d' ' -f3)
    echo -e "${GREEN}[✓]${RESET} Nmap: $NMAP_VERSION"
else
    echo -e "${YELLOW}[!]${RESET} Nmap not found — will attempt to install"
fi

# jq
if command -v jq &> /dev/null; then
    echo -e "${GREEN}[✓]${RESET} jq: Available"
else
    echo -e "${YELLOW}[!]${RESET} jq not found — will attempt to install"
fi

echo ""
echo -e "${CYAN}[*] Installing Python packages...${RESET}"
echo ""

if [ -z "${VIRTUAL_ENV:-}" ]; then
    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
    fi
    # shellcheck disable=SC1091
    . .venv/bin/activate
fi

pip3 install --upgrade pip
pip3 install -r requirements.txt

echo -e "${GREEN}[✓]${RESET} Python packages installed"

# System packages
if ! command -v nmap &> /dev/null || ! command -v jq &> /dev/null; then
    echo ""
    echo -e "${YELLOW}[→]${RESET} Installing system packages..."

    if command -v apt-get &> /dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y nmap jq curl
    elif command -v yum &> /dev/null; then
        sudo yum install -y nmap jq curl
    elif command -v brew &> /dev/null; then
        brew install nmap jq curl
    fi

    echo -e "${GREEN}[✓]${RESET} System packages installed"
fi

echo ""
echo -e "${CYAN}[*] Setting up directory structure...${RESET}"
echo ""

mkdir -p results/{current/{latest,today,this_week},archived/{old_scans,incomplete},reports/{html,csv,json,topology,compliance}}
mkdir -p modules tools
mkdir -p ~/.inventa

echo -e "${GREEN}[✓]${RESET} Directories created"

echo ""
echo -e "${CYAN}[*] Installing optional external tools...${RESET}"
echo ""

if command -v git &> /dev/null; then
    if [ ! -d "tools/CloudScraper" ]; then
        echo -e "${YELLOW}[→]${RESET} Cloning CloudScraper (jordanpotti)..."
        git clone --depth 1 https://github.com/jordanpotti/CloudScraper tools/CloudScraper 2>/dev/null \
            && echo -e "${GREEN}[✓]${RESET} CloudScraper installed" \
            || echo -e "${YELLOW}[!]${RESET} CloudScraper clone failed (native fallback will be used)"
    else
        echo -e "${GREEN}[✓]${RESET} CloudScraper already present"
    fi

    if [ -f "tools/CloudScraper/requirements.txt" ]; then
        echo -e "${YELLOW}[→]${RESET} Installing CloudScraper dependencies..."
        pip3 install -r tools/CloudScraper/requirements.txt
        echo -e "${GREEN}[✓]${RESET} CloudScraper dependencies installed"
    fi

    if [ ! -d "tools/inSp3ctor" ]; then
        echo -e "${YELLOW}[→]${RESET} Cloning inSp3ctor (brianwarehime)..."
        git clone --depth 1 https://github.com/brianwarehime/inSp3ctor tools/inSp3ctor 2>/dev/null \
            && echo -e "${GREEN}[✓]${RESET} inSp3ctor installed" \
            || echo -e "${YELLOW}[!]${RESET} inSp3ctor clone failed (native fallback will be used)"
    else
        echo -e "${GREEN}[✓]${RESET} inSp3ctor already present"
    fi
else
    echo -e "${YELLOW}[!]${RESET} git not found — skipping external tool download (native fallback will be used)"
fi

# Go-based tools
echo ""
echo -e "${CYAN}[*] Installing Go-based tools (amass, subfinder, assetfinder, smap, zgrab2)...${RESET}"
echo ""

_install_go_tool() {
    local name="$1"
    local pkg="$2"
    local dest="tools/${name}"

    if command -v "$name" &> /dev/null; then
        echo -e "${GREEN}[✓]${RESET} ${name} already in PATH"
        return 0
    fi

    mkdir -p "$dest"

    if command -v go &> /dev/null; then
        echo -e "${YELLOW}[→]${RESET} Installing ${name} via go install..."
        GOBIN="$(pwd)/${dest}" go install "${pkg}" 2>/dev/null \
            && echo -e "${GREEN}[✓]${RESET} ${name} installed to ${dest}/" \
            && return 0
    fi

    if command -v apt-get &> /dev/null; then
        echo -e "${YELLOW}[→]${RESET} Trying apt-get for ${name}..."
        sudo apt-get install -y "$name" 2>/dev/null \
            && echo -e "${GREEN}[✓]${RESET} ${name} installed via apt-get" \
            && return 0
    fi

    echo -e "${YELLOW}[!]${RESET} Could not auto-install ${name}."
    echo -e "       Install manually and ensure it is in PATH, or place the binary at ${dest}/${name}"
}

_install_go_tool "amass"       "github.com/owasp-amass/amass/v4/...@latest"
_install_go_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
_install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"
_install_go_tool "smap"        "github.com/s0md3v/smap/cmd/smap@v0.2.0-rc"
_install_go_tool "zgrab2"      "github.com/zmap/zgrab2@latest"

# Masscan / ZMap / Nikto
echo ""
echo -e "${CYAN}[*] Installing Masscan / ZMap / Nikto...${RESET}"
echo ""

if command -v masscan &> /dev/null; then
    echo -e "${GREEN}[✓]${RESET} masscan already in PATH"
elif command -v apt-get &> /dev/null; then
    echo -e "${YELLOW}[→]${RESET} Installing masscan via apt-get..."
    sudo apt-get install -y masscan 2>/dev/null \
        && echo -e "${GREEN}[✓]${RESET} masscan installed" \
        || echo -e "${YELLOW}[!]${RESET} apt-get install failed — install manually: https://github.com/robertdavidgraham/masscan/releases"
elif command -v brew &> /dev/null; then
    echo -e "${YELLOW}[→]${RESET} Installing masscan via Homebrew..."
    brew install masscan 2>/dev/null \
        && echo -e "${GREEN}[✓]${RESET} masscan installed" \
        || echo -e "${YELLOW}[!]${RESET} brew install failed — install manually: https://github.com/robertdavidgraham/masscan/releases"
else
    echo -e "${YELLOW}[!]${RESET} Could not auto-install masscan."
    echo -e "       Compile: git clone https://github.com/robertdavidgraham/masscan && cd masscan && make"
fi

if command -v zmap &> /dev/null; then
    echo -e "${GREEN}[✓]${RESET} zmap already in PATH"
elif command -v apt-get &> /dev/null; then
    echo -e "${YELLOW}[→]${RESET} Installing zmap via apt-get..."
    sudo apt-get install -y zmap 2>/dev/null \
        && echo -e "${GREEN}[✓]${RESET} zmap installed" \
        || echo -e "${YELLOW}[!]${RESET} apt-get install failed — install manually: https://github.com/zmap/zmap"
elif command -v brew &> /dev/null; then
    echo -e "${YELLOW}[→]${RESET} Installing zmap via Homebrew..."
    brew install zmap 2>/dev/null \
        && echo -e "${GREEN}[✓]${RESET} zmap installed" \
        || echo -e "${YELLOW}[!]${RESET} brew install failed — install manually: https://github.com/zmap/zmap"
else
    echo -e "${YELLOW}[!]${RESET} Could not auto-install zmap."
    echo -e "       Build from source: https://github.com/zmap/zmap"
fi

if command -v nikto &> /dev/null; then
    echo -e "${GREEN}[✓]${RESET} nikto already in PATH"
elif command -v apt-get &> /dev/null; then
    echo -e "${YELLOW}[→]${RESET} Installing nikto via apt-get..."
    sudo apt-get install -y nikto 2>/dev/null \
        && echo -e "${GREEN}[✓]${RESET} nikto installed" \
        || echo -e "${YELLOW}[!]${RESET} apt-get install failed — install manually: https://github.com/sullo/nikto/wiki"
elif command -v brew &> /dev/null; then
    echo -e "${YELLOW}[→]${RESET} Installing nikto via Homebrew..."
    brew install nikto 2>/dev/null \
        && echo -e "${GREEN}[✓]${RESET} nikto installed" \
        || echo -e "${YELLOW}[!]${RESET} brew install failed — install manually: https://github.com/sullo/nikto/wiki"
else
    echo -e "${YELLOW}[!]${RESET} Could not auto-install nikto."
    echo -e "       Install manually: https://github.com/sullo/nikto/wiki"
fi

# Make scripts executable
echo ""
echo -e "${CYAN}[*] Configuring scripts...${RESET}"
echo ""

chmod +x install.sh 2>/dev/null || true
chmod +x inventa.py 2>/dev/null || true

echo -e "${GREEN}[✓]${RESET} Scripts configured"

# Default scope and targets
echo ""
echo -e "${CYAN}[*] Creating default configuration files...${RESET}"
echo ""

if [ ! -f "scope.txt" ]; then
    cat > scope.txt << 'EOF'
# Inventa Scope File
# One authorized CIDR range per line
#
# Example:
# 192.168.1.0/24
EOF
    echo -e "${GREEN}[✓]${RESET} Default scope created: scope.txt"
else
    echo -e "${GREEN}[✓]${RESET} scope.txt already exists"
fi

if [ ! -f "targets.txt" ]; then
    cat > targets.txt << 'EOF'
# Inventa Targets File
# One authorized IP, hostname, or CIDR per line
#
# Example:
# 192.168.1.10
EOF
    echo -e "${GREEN}[✓]${RESET} Default targets created: targets.txt"
else
    echo -e "${GREEN}[✓]${RESET} targets.txt already exists"
fi

if [ ! -f "websites.txt" ]; then
    cat > websites.txt << 'EOF'
# Website / Domain Targets
# Add one website or domain per line

example.com
app.example.com
portal.example.com
EOF
    echo -e "${GREEN}[✓]${RESET} Default website target list created: websites.txt"
else
    echo -e "${GREEN}[✓]${RESET} websites.txt already exists"
fi

# API keys — written to .env (loaded by python-dotenv)
echo ""
read -p "$(echo -e ${CYAN}[?]${RESET}) Configure API keys now? (y/n): " config_api

if [ "$config_api" = "y" ]; then
    echo ""
    echo -e "${CYAN}[*] API Key Configuration${RESET}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${YELLOW}    Press Enter to skip any key you don't have yet.${RESET}"
    echo ""

    read -p "Shodan API Key:               " shodan_key
    read -p "VirusTotal API Key:           " vt_key
    read -p "Censys API ID:                " censys_id
    read -p "Censys API Secret:            " censys_secret
    read -p "IPInfo.io API Key:            " ipinfo_key
    read -p "SecurityTrails API Key:       " sectrails_key
    read -p "ZoomEye API Key:              " zoomeye_key
    read -p "IntelX API Key:               " intelx_key
    read -p "Netlas API Key:               " netlas_key
    read -p "FullHunt API Key:             " fullhunt_key
    read -p "LeakIX API Key:               " leakix_key
    read -p "BuiltWith API Key:            " builtwith_key
    read -p "ProjectDiscovery API Key:     " pd_key
    read -p "GitHub Token:                 " github_token
    read -p "Google PageSpeed API Key:     " pagespeed_key

    cat > .env << EOF
SHODAN_API_KEY=${shodan_key}
VIRUSTOTAL_API_KEY=${vt_key}
CENSYS_API_ID=${censys_id}
CENSYS_API_SECRET=${censys_secret}
IPINFO_API_KEY=${ipinfo_key}
SECURITYTRAILS_API_KEY=${sectrails_key}
ZOOMEYE_API_KEY=${zoomeye_key}
INTELX_API_KEY=${intelx_key}
NETLAS_API_KEY=${netlas_key}
FULLHUNT_API_KEY=${fullhunt_key}
LEAKIX_API_KEY=${leakix_key}
BUILTWITH_API_KEY=${builtwith_key}
PROJECTDISCOVERY_API_KEY=${pd_key}
GITHUB_TOKEN=${github_token}
GOOGLE_PAGESPEED_API_KEY=${pagespeed_key}
EOF

    chmod 600 .env
    echo ""
    echo -e "${GREEN}[✓]${RESET} API keys saved to .env"
    echo -e "${YELLOW}[!]${RESET} Ensure .env is listed in .gitignore — never commit API keys!"
fi

# .gitignore
if [ ! -f ".gitignore" ]; then
    cat > .gitignore << 'EOF'
# API Keys & Credentials
.env
api_keys.sh
*.key
*.pem

# Results
results/
results_backup_*/

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
env/

# OS
.DS_Store
Thumbs.db
desktop.ini

# Temporary
*.log
*.tmp
*.bak
nmap_*.xml
EOF
    echo ""
    echo -e "${GREEN}[✓]${RESET} .gitignore created"
fi

echo -e "${GREEN}[✓]${RESET} Quick start available: QUICK_START.md"

# Final summary
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║${RESET}${BOLD}            INSTALLATION COMPLETE                           ${RESET}${CYAN}║${RESET}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${GREEN}[✓]${RESET} Inventa is ready to use!"
echo ""
echo -e "${BOLD}Quick Start:${RESET}"
echo "  1. Edit scan scope:   nano scope.txt"
echo "  2. Edit targets:      nano targets.txt"
echo "  3. Run Inventa:       python3 inventa.py"
echo ""
echo -e "${BOLD}Or jump straight in:${RESET}"
echo "  python3 inventa.py quick"
echo ""
echo -e "${CYAN}For help, see: QUICK_START.md${RESET}"
echo ""
