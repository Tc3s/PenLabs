#!/bin/bash
# FILE: setup.sh
# CHỨC NĂNG: Thiết lập toàn bộ môi trường phát triển & tấn công an toàn cho PenLabs

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${GREEN}[+] BẮT ĐẦU THIẾT LẬP MÔI TRƯỜNG PENTEST AUTOMATION...${NC}"

# 1. Cập nhật và cài đặt System Tools
echo -e "\n${CYAN}[1/6] Kiểm tra và cài đặt/cập nhật công cụ hệ thống (APT)...${NC}"
sudo apt-get update -qq

# Hàm check và cài đặt package APT
install_or_update_apt() {
    PKG=$1
    if dpkg -l | grep -qw "$PKG"; then
        echo -e "   ${GREEN}✔ $PKG đã được cài đặt. Đang kiểm tra cập nhật...${NC}"
        sudo apt-get install -y --only-upgrade "$PKG" > /dev/null 2>&1
    else
        echo -e "   ${YELLOW}➜ Đang cài đặt $PKG...${NC}"
        sudo apt-get install -y "$PKG" > /dev/null 2>&1
    fi
}

PACKAGES=(nmap git golang-go python3-venv default-jre metasploit-framework unzip curl wget jq libssl-dev libffi-dev python3-dev build-essential exploitdb firejail iproute2 nim metagoofil)

for pkg in "${PACKAGES[@]}"; do
    install_or_update_apt "$pkg"
done

# === Xử lý riêng biệt cho wkhtmltopdf (bị xóa khỏi repo mặc định) ===
if ! command -v wkhtmltopdf &> /dev/null; then
    echo -e "   ${YELLOW}➜ Đang tải wkhtmltopdf (Debian Bookworm version for Kali compatibility)...${NC}"
    sudo apt-get install -y xfonts-75dpi xfonts-base > /dev/null 2>&1
    wget -q https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-3/wkhtmltox_0.12.6.1-3.bookworm_amd64.deb -O /tmp/wkhtmltox.deb
    sudo dpkg -i /tmp/wkhtmltox.deb > /dev/null 2>&1 || sudo apt-get install -f -y > /dev/null 2>&1
    rm -f /tmp/wkhtmltox.deb
    if command -v wkhtmltopdf &> /dev/null; then
        echo -e "   ${GREEN}✔ wkhtmltopdf đã cài đặt thành công.${NC}"
    else
        echo -e "   ${RED}✘ Không thể cài đặt wkhtmltopdf tự động. Module xuất PDF có thể lỗi.${NC}"
    fi
else
    echo -e "   ${GREEN}✔ wkhtmltopdf đã được cài đặt.${NC}"
fi

# 2. Cài đặt Go/Rust Tools — V1.0
echo -e "\n${CYAN}[2/6] Kiểm tra và cài đặt/cập nhật Go & Rust Tools (2026 Doctrine)...${NC}"

# Đảm bảo ~/go/bin nằm trên PATH
export PATH=$PATH:~/go/bin:/usr/local/bin
if ! grep -q 'go/bin' ~/.bashrc 2>/dev/null; then
    echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
fi

# Hàm helper: cài Go tool từ GitHub Releases
install_go_tool_from_releases() {
    local TOOL_NAME=$1
    local REPO=$2
    local BINARY_NAME=${3:-$TOOL_NAME}
    local DEST_NAME=${4:-$BINARY_NAME}

    if command -v "$DEST_NAME" &> /dev/null; then
        echo -e "   ${GREEN}✔ $TOOL_NAME đã được cài đặt.${NC}"
        return
    fi

    echo -e "   ${YELLOW}➜ Đang cài đặt $TOOL_NAME (latest release)...${NC}"
    local DL_URL=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep -Pi "browser_download_url.*(linux_amd64|linux-amd64)" | grep -vi "sha256" | head -1 | sed 's/.*"\(http[^"]*\)".*/\1/')
    if [ -n "$DL_URL" ]; then
        if [[ "$DL_URL" == *.zip ]]; then
            wget -q "$DL_URL" -O "/tmp/${TOOL_NAME}_latest.zip"
            unzip -o -q "/tmp/${TOOL_NAME}_latest.zip" -d "/tmp/${TOOL_NAME}_extract"
            local BIN_PATH=$(find "/tmp/${TOOL_NAME}_extract" -name "$BINARY_NAME" -type f | head -1)
            if [ -n "$BIN_PATH" ]; then
                sudo mv "$BIN_PATH" "/usr/bin/${DEST_NAME}"
                sudo chmod +x "/usr/bin/${DEST_NAME}"
            fi
            rm -rf "/tmp/${TOOL_NAME}_latest.zip" "/tmp/${TOOL_NAME}_extract"
        elif [[ "$DL_URL" == *.tar.gz ]]; then
            wget -q "$DL_URL" -O "/tmp/${TOOL_NAME}_latest.tar.gz"
            mkdir -p "/tmp/${TOOL_NAME}_extract"
            tar -xzf "/tmp/${TOOL_NAME}_latest.tar.gz" -C "/tmp/${TOOL_NAME}_extract"
            local BIN_PATH=$(find "/tmp/${TOOL_NAME}_extract" -name "$BINARY_NAME" -type f | head -1)
            if [ -n "$BIN_PATH" ]; then
                sudo mv "$BIN_PATH" "/usr/bin/${DEST_NAME}"
                sudo chmod +x "/usr/bin/${DEST_NAME}"
            fi
            rm -rf "/tmp/${TOOL_NAME}_latest.tar.gz" "/tmp/${TOOL_NAME}_extract"
        else
            # Raw binary like gowitness
            sudo wget -q "$DL_URL" -O "/usr/bin/${DEST_NAME}"
            sudo chmod +x "/usr/bin/${DEST_NAME}"
        fi
    else
        echo -e "   ${RED}✘ Không thể tải $TOOL_NAME từ GitHub Releases.${NC}"
    fi
}

# === ProjectDiscovery Ecosystem ===
install_go_tool_from_releases "subfinder" "projectdiscovery/subfinder" "subfinder"
install_go_tool_from_releases "nuclei" "projectdiscovery/nuclei" "nuclei"
install_go_tool_from_releases "naabu" "projectdiscovery/naabu" "naabu"
install_go_tool_from_releases "katana" "projectdiscovery/katana" "katana"
install_go_tool_from_releases "httpx" "projectdiscovery/httpx" "httpx" "httpx-toolkit"
install_go_tool_from_releases "dnsx" "projectdiscovery/dnsx" "dnsx"

# === ffuf — Fast web fuzzer ===
install_go_tool_from_releases "ffuf" "ffuf/ffuf" "ffuf"

# === gowitness — Headless web screenshots ===
install_go_tool_from_releases "gowitness" "sensepost/gowitness" "gowitness"

# === gau — GetAllUrls (Historical URL discovery) ===
if ! command -v gau &> /dev/null; then
    echo -e "   ${YELLOW}➜ Đang cài đặt gau (GetAllUrls)...${NC}"
    go install -v github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || true
fi

# === cloudflared — Cloudflare Tunnel (Remote Web UI) ===
if ! command -v cloudflared &> /dev/null; then
    echo -e "   ${YELLOW}➜ Đang cài đặt cloudflared (Cloudflare Tunnel)...${NC}"
    wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -O /tmp/cloudflared.deb
    sudo dpkg -i /tmp/cloudflared.deb > /dev/null 2>&1 || sudo apt-get install -f -y > /dev/null 2>&1
    rm -f /tmp/cloudflared.deb
    echo -e "   ${GREEN}✔ cloudflared đã cài đặt thành công.${NC}"
else
    echo -e "   ${GREEN}✔ cloudflared đã được cài đặt.${NC}"
fi

# === [V1.0] interactsh-client — OOB Interaction Gathering ===
install_go_tool_from_releases "interactsh-client" "projectdiscovery/interactsh" "interactsh-client"

# === Kiterunner — API Discovery ===
install_go_tool_from_releases "kiterunner" "assetnote/kiterunner" "kr" "kr"

# === [V1.0] Dalfox — XSS Scanner (Go binary) ===
if ! command -v dalfox &> /dev/null; then
    echo -e "   ${YELLOW}➜ Đang cài đặt Dalfox (XSS Scanner)...${NC}"
    go install github.com/hahwul/dalfox/v2@latest 2>/dev/null || true
    if command -v dalfox &> /dev/null; then
        echo -e "   ${GREEN}✔ Dalfox đã cài đặt thành công.${NC}"
    else
        echo -e "   ${RED}✘ Không thể cài Dalfox. Thử: go install github.com/hahwul/dalfox/v2@latest${NC}"
    fi
else
    echo -e "   ${GREEN}✔ Dalfox đã được cài đặt.${NC}"
fi

# === [V1.0] LinkFinder & SecretFinder — JS Analysis ===
LINKFINDER_DIR="$HOME/.pentools/LinkFinder"
if [ ! -d "$LINKFINDER_DIR" ]; then
    echo -e "   ${YELLOW}➜ Đang cài đặt LinkFinder (JS Endpoint Extractor)...${NC}"
    mkdir -p "$HOME/.pentools"
    git clone -q https://github.com/GerbenJavado/LinkFinder.git "$LINKFINDER_DIR" 2>/dev/null || true
    if [ -f "$LINKFINDER_DIR/requirements.txt" ]; then
        ./venv/bin/pip install -r "$LINKFINDER_DIR/requirements.txt" > /dev/null 2>&1 || true
    fi
    echo -e "   ${GREEN}✔ LinkFinder đã cài đặt tại $LINKFINDER_DIR${NC}"
else
    echo -e "   ${GREEN}✔ LinkFinder đã tồn tại.${NC}"
fi

SECRETFINDER_DIR="$HOME/.pentools/SecretFinder"
if [ ! -d "$SECRETFINDER_DIR" ]; then
    echo -e "   ${YELLOW}➜ Đang cài đặt SecretFinder (JS Secret Extractor)...${NC}"
    git clone -q https://github.com/m4ll0k/SecretFinder.git "$SECRETFINDER_DIR" 2>/dev/null || true
    if [ -f "$SECRETFINDER_DIR/requirements.txt" ]; then
        ./venv/bin/pip install -r "$SECRETFINDER_DIR/requirements.txt" > /dev/null 2>&1 || true
    fi
    echo -e "   ${GREEN}✔ SecretFinder đã cài đặt tại $SECRETFINDER_DIR${NC}"
else
    echo -e "   ${GREEN}✔ SecretFinder đã tồn tại.${NC}"
fi

# === [V1.0] Corsy — CORS Misconfiguration Scanner ===
CORSY_DIR="$HOME/.pentools/Corsy"
if [ ! -d "$CORSY_DIR" ]; then
    echo -e "   ${YELLOW}➜ Đang cài đặt Corsy (CORS Scanner)...${NC}"
    git clone -q https://github.com/s0md3v/Corsy.git "$CORSY_DIR" 2>/dev/null || true
    if [ -f "$CORSY_DIR/requirements.txt" ]; then
        ./venv/bin/pip install -r "$CORSY_DIR/requirements.txt" > /dev/null 2>&1 || true
    fi
    echo -e "   ${GREEN}✔ Corsy đã cài đặt tại $CORSY_DIR${NC}"
else
    echo -e "   ${GREEN}✔ Corsy đã tồn tại.${NC}"
fi

# === [V1.0] Kiterunner Wordlists (Assetnote) ===
if [ ! -f "wordlists/routes-small.kite" ]; then
    echo -e "   ${YELLOW}➜ Đang tải Kiterunner API wordlist (routes-small.kite)...${NC}"
    mkdir -p wordlists
    wget -q "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite" -O wordlists/routes-small.kite 2>/dev/null || true
    if [ -f "wordlists/routes-small.kite" ]; then
        echo -e "   ${GREEN}✔ Kiterunner wordlist đã tải thành công.${NC}"
    else
        echo -e "   ${YELLOW}⚠ Không thể tải wordlist. Kiterunner sẽ dùng default.${NC}"
    fi
else
    echo -e "   ${GREEN}✔ Kiterunner wordlist đã tồn tại.${NC}"
fi

# === [V1.0] Bug Bounty Extended — Go Tools ===
echo -e "\n${BOLD_WHITE}[V1.0] Cài đặt Go tools mới cho Bug Bounty V1.0...${NC}"

# crlfuzz — CRLF injection scanner
if ! command -v crlfuzz &> /dev/null && [ ! -f "$HOME/go/bin/crlfuzz" ]; then
    echo -e "   ${YELLOW}➜ Đang cài đặt crlfuzz (CRLF Scanner)...${NC}"
    go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest 2>/dev/null
fi
echo -e "   ${GREEN}✔ crlfuzz$(command -v crlfuzz &> /dev/null && echo ' ready' || echo ' (~/go/bin)')${NC}"

# gau — GetAllUrls (Wayback/CommonCrawl/URLScan)
if ! command -v gau &> /dev/null && [ ! -f "$HOME/go/bin/gau" ]; then
    echo -e "   ${YELLOW}➜ Đang cài đặt gau (Historical URL Mining)...${NC}"
    go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null
fi
echo -e "   ${GREEN}✔ gau$(command -v gau &> /dev/null && echo ' ready' || echo ' (~/go/bin)')${NC}"

# qsreplace — URL param replacer
if ! command -v qsreplace &> /dev/null && [ ! -f "$HOME/go/bin/qsreplace" ]; then
    echo -e "   ${YELLOW}➜ Đang cài đặt qsreplace (URL Param Replacer)...${NC}"
    go install github.com/tomnomnom/qsreplace@latest 2>/dev/null
fi
echo -e "   ${GREEN}✔ qsreplace$(command -v qsreplace &> /dev/null && echo ' ready' || echo ' (~/go/bin)')${NC}"

# anew — Unique line appender
if ! command -v anew &> /dev/null && [ ! -f "$HOME/go/bin/anew" ]; then
    echo -e "   ${YELLOW}➜ Đang cài đặt anew (Unique Line Filter)...${NC}"
    go install github.com/tomnomnom/anew@latest 2>/dev/null
fi
echo -e "   ${GREEN}✔ anew$(command -v anew &> /dev/null && echo ' ready' || echo ' (~/go/bin)')${NC}"

# aiohttp — Python async HTTP (for RaceCondition plugin)
pip3 install aiohttp --quiet 2>/dev/null || true
echo -e "   ${GREEN}✔ aiohttp (Python async) ready${NC}"


# === [V1.0] Nim compiler — Advanced EDR bypass stager ===
if ! command -v nim &> /dev/null; then
    echo -e "   ${YELLOW}➜ Đang cài đặt Nim compiler...${NC}"
    sudo apt-get install -y nim > /dev/null 2>&1
    if ! command -v nim &> /dev/null; then
        echo -e "   ${YELLOW}   Cài đặt tự động thất bại. Thử cài thủ công: curl https://nim-lang.org/choosenim/init.sh -sSf | sh${NC}"
    fi
else
    echo -e "   ${GREEN}✔ Nim compiler đã được cài đặt ($(nim --version 2>&1 | head -1)).${NC}"
fi

# === RustScan — Blazing fast port scanner ===
if ! command -v rustscan &> /dev/null; then
    echo -e "   ${YELLOW}➜ Đang cài đặt RustScan...${NC}"
    RUSTSCAN_URL=$(curl -sL https://api.github.com/repos/RustScan/RustScan/releases/latest | grep "browser_download_url.*rustscan\.deb" | cut -d '"' -f 4 | head -1)
    if [ -n "$RUSTSCAN_URL" ]; then
        if [[ "$RUSTSCAN_URL" == *".zip"* ]]; then
            wget -q "$RUSTSCAN_URL" -O /tmp/rustscan.deb.zip
            unzip -o -q /tmp/rustscan.deb.zip -d /tmp/rustscan_extract
            sudo dpkg -i /tmp/rustscan_extract/*.deb > /dev/null 2>&1 || sudo apt-get install -f -y > /dev/null 2>&1
            rm -rf /tmp/rustscan.deb.zip /tmp/rustscan_extract
            echo -e "   ${GREEN}✔ RustScan đã được tải và cài đặt thành công.${NC}"
        else
            wget -q "$RUSTSCAN_URL" -O /tmp/rustscan.deb
            sudo dpkg -i /tmp/rustscan.deb > /dev/null 2>&1 || sudo apt-get install -f -y > /dev/null 2>&1
            rm -f /tmp/rustscan.deb
            echo -e "   ${GREEN}✔ RustScan đã được tải và cài đặt thành công.${NC}"
        fi
    else
        echo -e "   ${RED}✘ Không thể tải RustScan từ GitHub.${NC}"
    fi
else
    echo -e "   ${GREEN}✔ RustScan đã được cài đặt.${NC}"
fi

# === NetExec — CrackMapExec successor (Internal Pentest) ===
if ! command -v netexec &> /dev/null && ! command -v nxc &> /dev/null; then
    echo -e "   ${YELLOW}➜ Đang cài đặt NetExec (CrackMapExec successor)...${NC}"
    pip3 install netexec > /dev/null 2>&1 || true
else
    echo -e "   ${GREEN}✔ NetExec đã được cài đặt.${NC}"
fi

# === TruffleHog — Secret scanner ===
if ! command -v trufflehog &> /dev/null; then
    echo -e "   ${YELLOW}➜ Đang cài đặt TruffleHog (Secret Scanner)...${NC}"
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin > /dev/null 2>&1 || true
else
    echo -e "   ${GREEN}✔ TruffleHog đã được cài đặt.${NC}"
fi

echo -e "   ${YELLOW}➜ Cập nhật DB cho Nuclei...${NC}"
nuclei -update-templates -silent > /dev/null 2>&1

# 3. Thiết lập Môi trường ảo Python (VENV) - Quy tắc OPSEC 101
echo -e "\n${CYAN}[3/6] Thiết lập Python Virtual Environment (venv)...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "   ${GREEN}✔ Đã tạo thư mục độc lập venv${NC}"
else
    echo -e "   ${GREEN}✔ Thư mục venv đã tồn tại${NC}"
fi

# 4. Cài đặt thư viện Python (Từ requirements.txt)
echo -e "\n${CYAN}[4/6] Cài đặt & cập nhật thư viện Python vào ngăn cách an toàn...${NC}"
./venv/bin/pip install --upgrade pip > /dev/null 2>&1
if [ -f "requirements.txt" ]; then
    echo -e "   ${YELLOW}➜ Đang cài đặt từ requirements.txt...${NC}"
    ./venv/bin/pip install -r requirements.txt > /dev/null 2>&1
else
    # Fallback nếu mất file
    echo -e "   ${YELLOW}➜ Đang cài đặt các thư viện cơ bản...${NC}"
    ./venv/bin/pip install requests cloudscraper python-whois python-Wappalyzer dnspython beautifulsoup4 google-generativeai pymetasploit3 pdfkit psutil playwright python-dotenv Jinja2 pytest pytest-asyncio netexec SQLAlchemy alembic rich openai > /dev/null 2>&1
fi

echo -e "   ${YELLOW}➜ Đang cài đặt các công cụ Python cho Phase 3 (emailfinder, xnLinkFinder)...${NC}"
./venv/bin/pip install emailfinder xnLinkFinder > /dev/null 2>&1 || true
if [ -f "./venv/bin/xnLinkFinder" ]; then
    echo -e "   ${GREEN}✔ xnLinkFinder đã cài đặt thành công vào ./venv/bin/xnLinkFinder${NC}"
else
    echo -e "   ${RED}✘ Cài đặt xnLinkFinder thất bại. Thử: ./venv/bin/pip install xnLinkFinder${NC}"
fi

# === [P1-2] Cloud-native Tools ===
echo -e "   ${YELLOW}➜ Cài đặt cloud-native tools (S3Scanner, cloud_enum, kube-hunter)...${NC}"
./venv/bin/pip install S3Scanner kube-hunter > /dev/null 2>&1 || true
./venv/bin/pip install "git+https://github.com/initstring/cloud_enum.git#egg=cloud_enum" > /dev/null 2>&1 || true

echo -e "   ${YELLOW}➜ Cài đặt trình duyệt headless (Chromium)...${NC}"
# Cài đặt trình duyệt headless
./venv/bin/playwright install chromium > /dev/null 2>&1

# 5. Tải tài nguyên phụ trợ Chuẩn (SecLists)
echo -e "\n${CYAN}[5/6] Cập nhật tài nguyên phụ trợ OPSEC (SecLists)...${NC}"
mkdir -p wordlists

# [P0-1 FIX] download_wordlist() — verify file size after wget
# Bug: wget -q creates empty file on failure (silent). Now we check.
download_wordlist() {
    local url="$1"
    local output="$2"
    local min_bytes="$3"  # minimum file size to consider valid
    local label="$4"

    if [ -f "$output" ] && [ -s "$output" ] && [ $(stat -c%s "$output") -ge "$min_bytes" ]; then
        echo -e "   ${GREEN}✔ $label đã tồn tại ($(wc -l < "$output") lines, $(stat -c%s "$output") bytes)${NC}"
        return 0
    fi

    # Remove empty/invalid existing file before retry
    [ -f "$output" ] && rm -f "$output"

    echo -e "   ${YELLOW}➜ Đang tải $label...${NC}"
    wget -q "$url" -O "${output}.tmp"
    local wget_exit=$?

    if [ $wget_exit -ne 0 ]; then
        echo -e "   ${RED}✘ $label download FAILED (wget exit=$wget_exit)${NC}"
        rm -f "${output}.tmp"
        return 1
    fi

    if [ ! -s "${output}.tmp" ]; then
        echo -e "   ${RED}✘ $label download FAILED (file empty)${NC}"
        rm -f "${output}.tmp"
        return 1
    fi

    local size=$(stat -c%s "${output}.tmp")
    if [ "$size" -lt "$min_bytes" ]; then
        echo -e "   ${RED}✘ $label download FAILED (only $size bytes, need ≥$min_bytes)${NC}"
        rm -f "${output}.tmp"
        return 1
    fi

    mv "${output}.tmp" "$output"
    echo -e "   ${GREEN}✔ $label downloaded ($(wc -l < "$output") lines, $size bytes)${NC}"
    return 0
}

# Bỏ wordlist hardcode nguy hiểm, dùng nguồn chuẩn công nghiệp
# Min sizes: top-1000.txt ≈ 70KB (from 10k-most-common), common.txt ≈ 35KB
# NOTE: Original URL "10-million-password-list-top-1000.txt" returns 404 on SecLists master.
#       Fall back to "10k-most-common.txt" which is reliably available.
download_wordlist \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" \
    "wordlists/top-1000.txt" \
    50000 \
    "SecLists Passwords Top-10k"

download_wordlist \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
    "wordlists/common.txt" \
    10000 \
    "SecLists Web Content Common"

download_wordlist \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" \
    "wordlists/pass.txt" \
    50000 \
    "SecLists Passwords 10k"

# 6. Thiết lập API Keys (.env)
echo -e "\n${CYAN}[6/6] Cấu hình API Keys (Nhấn Enter để BỎ QUA nếu đã có hoặc không muốn thêm)${NC}"
ENV_FILE=".env"
touch "$ENV_FILE"

# Hàm nhập API key và lưu vào .env
prompt_api_key() {
    local key_name=$1
    local prompt_msg=$2
    # Lấy giá trị hiện tại nếu có
    local current_val=$(grep "^${key_name}=" "$ENV_FILE" | cut -d '=' -f 2)
    
    echo -en "   ${YELLOW}➜ Nhập ${prompt_msg}${NC}"
    if [ -n "$current_val" ]; then
        echo -en " [Hiện đã có Key, Enter để GIỮ NGUYÊN]: "
    else
        echo -en " [Enter để BỎ QUA]: "
    fi
    
    # Đọc input từ user
    read user_input
    
    if [ -n "$user_input" ]; then
        # Cập nhật hoặc thêm mới vào file .env
        if grep -q "^${key_name}=" "$ENV_FILE"; then
            sed -i "s|^${key_name}=.*|${key_name}=${user_input}|" "$ENV_FILE"
        else
            echo "${key_name}=${user_input}" >> "$ENV_FILE"
        fi
        echo -e "     ${GREEN}✔ Đã lưu ${key_name}.${NC}"
    fi
}

prompt_api_key "VT_API_KEY" "VirusTotal API Key"
prompt_api_key "SHODAN_KEY" "Shodan API Key"
prompt_api_key "HUNTER_API_KEY" "Hunter.how API Key"
prompt_api_key "CHAOS_KEY" "Chaos / ProjectDiscovery API Key"

# Hỏi bật Cloudflare Tunnel
echo -en "\n   ${YELLOW}➜ Bạn có muốn bật giao diện Web UI qua Cloudflare Tunnel không? (Y/n): ${NC}"
read -r enable_tunnel
if [[ "$enable_tunnel" =~ ^([yY][eE][sS]|[yY]|"")$ ]]; then
    if grep -q "^CLOUDFLARE_TUNNEL_ENABLED=" "$ENV_FILE"; then
        sed -i "s|^CLOUDFLARE_TUNNEL_ENABLED=.*|CLOUDFLARE_TUNNEL_ENABLED=true|" "$ENV_FILE"
    else
        echo "CLOUDFLARE_TUNNEL_ENABLED=true" >> "$ENV_FILE"
    fi
    echo -e "     ${GREEN}✔ Đã BẬT tính năng Web UI Tunnel.${NC}"
else
    if grep -q "^CLOUDFLARE_TUNNEL_ENABLED=" "$ENV_FILE"; then
        sed -i "s|^CLOUDFLARE_TUNNEL_ENABLED=.*|CLOUDFLARE_TUNNEL_ENABLED=false|" "$ENV_FILE"
    else
        echo "CLOUDFLARE_TUNNEL_ENABLED=false" >> "$ENV_FILE"
    fi
    echo -e "     ${YELLOW}✔ Đã TẮT tính năng Web UI Tunnel.${NC}"
fi

# 7. Cấu hình PERSISTENCE / C2 (Reverse Shell Callback)
echo -e "\n${CYAN}[7/9] Cấu hình PERSISTENCE / C2 (Reverse Shell Callback)${NC}"

# Tự động lấy IP nội bộ đầu tiên làm gợi ý cho C2_LHOST
default_ip=$(ip addr show $(ip route | awk '/default/ { print $5 }') | grep "inet " | head -1 | awk '{print $2}' | cut -d/ -f1)

prompt_c2_lhost() {
    local current_val=$(grep "^C2_LHOST=" "$ENV_FILE" | cut -d '=' -f 2)
    echo -en "   ${YELLOW}➜ Nhập Attacker IP (C2_LHOST) [Gợi ý: ${default_ip}]${NC}"
    if [ -n "$current_val" ]; then
        echo -en " [Hiện tại: ${current_val}, Enter để GIỮ NGUYÊN]: "
    else
        echo -en " [Enter để DÙNG GỢI Ý]: "
    fi
    read user_input
    if [ -n "$user_input" ]; then
        if grep -q "^C2_LHOST=" "$ENV_FILE"; then
            sed -i "s|^C2_LHOST=.*|C2_LHOST=${user_input}|" "$ENV_FILE"
        else
            echo "C2_LHOST=${user_input}" >> "$ENV_FILE"
        fi
        echo -e "     ${GREEN}✔ Đã lưu C2_LHOST.${NC}"
    elif [ -z "$current_val" ]; then
        echo "C2_LHOST=${default_ip}" >> "$ENV_FILE"
        echo -e "     ${GREEN}✔ Đã dùng gợi ý: ${default_ip}.${NC}"
    fi
}

prompt_c2_lport() {
    local current_val=$(grep "^C2_LPORT=" "$ENV_FILE" | cut -d '=' -f 2)
    echo -en "   ${YELLOW}➜ Nhập Callback Port (C2_LPORT) [Mặc định: 4444]${NC}"
    if [ -n "$current_val" ]; then
        echo -en " [Hiện tại: ${current_val}, Enter để GIỮ NGUYÊN]: "
    else
        echo -en " [Enter để BỎ QUA]: "
    fi
    read user_input
    if [ -n "$user_input" ]; then
        if grep -q "^C2_LPORT=" "$ENV_FILE"; then
            sed -i "s|^C2_LPORT=.*|C2_LPORT=${user_input}|" "$ENV_FILE"
        else
            echo "C2_LPORT=${user_input}" >> "$ENV_FILE"
        fi
        echo -e "     ${GREEN}✔ Đã lưu C2_LPORT.${NC}"
    elif [ -z "$current_val" ]; then
        echo "C2_LPORT=4444" >> "$ENV_FILE"
        echo -e "     ${GREEN}✔ Đã lưu mặc định 4444.${NC}"
    fi
}

prompt_c2_lhost
prompt_c2_lport

# 8. Cấu hình MSFRPC Daemon
echo -e "\n${CYAN}[8/9] Cấu hình Metasploit RPC Server (Background)...${NC}"
current_rpc_pass=$(grep "^MSF_RPC_PASS=" "$ENV_FILE" | cut -d '=' -f 2)
if [ -z "$current_rpc_pass" ]; then
    echo -en "   ${YELLOW}\u27a2 Nhập Metasploit RPC Password [\u0110ể trống = Tạo ngẫu nhiên, tối thiểu 32 ký tự]: ${NC}"
    read -r rpc_pass
    if [ -z "$rpc_pass" ]; then
        rpc_pass=$(openssl rand -hex 24)  # 48 ký tự hex
        echo -e "     ${GREEN}✔ Đã sinh password ngẫu nhiên (48 ký tự): $rpc_pass${NC}"
    elif [ ${#rpc_pass} -lt 12 ]; then
        echo -e "     ${RED}✘ Mật khẩu quá ngắn (tối thiểu 12 ký tự). Đang tạo ngẫu nhiên thay thế...${NC}"
        rpc_pass=$(openssl rand -hex 24)
        echo -e "     ${GREEN}✔ Mật khẩu ngẫu nhiên: $rpc_pass${NC}"
    fi
    echo "MSF_RPC_PASS=$rpc_pass" >> "$ENV_FILE"
    current_rpc_pass=$rpc_pass
else
    # [Security Fix] Kiểm tra password hiện tại có quá yếu không
    if [ ${#current_rpc_pass} -lt 12 ]; then
        echo -e "   ${RED}[!] CẢNH BÁO: MSF_RPC_PASS hiện tại ('$current_rpc_pass') quá ngắn!${NC}"
        echo -e "   ${YELLOW}\u27a2 Muốn thay bằng password mạnh hơn? (Y/n, Enter = Tạo ngẫu nhiên): ${NC}"
        read -r change_pass
        if [[ "$change_pass" =~ ^([yY][eE][sS]|[yY]|"")$ ]]; then
            new_pass=$(openssl rand -hex 24)
            sed -i "s|^MSF_RPC_PASS=.*|MSF_RPC_PASS=$new_pass|" "$ENV_FILE"
            current_rpc_pass=$new_pass
            echo -e "     ${GREEN}✔ Đã cập nhật MSF_RPC_PASS mới: $new_pass${NC}"
        fi
    else
        echo -e "   ${GREEN}✔ Đã có MSF_RPC_PASS trong .env${NC}"
    fi
fi

if ! grep -q "^MSF_RPC_HOST=" "$ENV_FILE"; then echo "MSF_RPC_HOST=127.0.0.1" >> "$ENV_FILE"; fi
if ! grep -q "^MSF_RPC_PORT=" "$ENV_FILE"; then echo "MSF_RPC_PORT=55553" >> "$ENV_FILE"; fi

# [V2026] Cấu hình Proxy hệ thống
echo -e "\n${CYAN}[+] Thiết lập biến môi trường Proxy (System-Wide Proxy Routing)...${NC}"
if ! grep -q "^EXPLOIT_PROXY=" "$ENV_FILE"; then
    cat >> "$ENV_FILE" << 'EOF'

# ==========================================
# [V2026] PROXY ROUTING CONFIGURATION
# ==========================================
# RECON_PROXY và FUZZ_PROXY để trống mặc định là kết nối trực tiếp
RECON_PROXY=
FUZZ_PROXY=

# EXPLOIT_PROXY mặc định sử dụng mạng Tor để ẩn danh khi deliver payload
EXPLOIT_PROXY=socks5h://127.0.0.1:9050

# JA3_SPOOF_ENABLED quyết định xem các công cụ Go (nuclei, httpx) có route 
# qua local SOCKS5 proxy để giả mạo vân tay TLS hay không.
JA3_SPOOF_ENABLED=true
JA3_PROXY_HOST=127.0.0.1
JA3_PROXY_PORT=1080
EOF
    echo -e "   ${GREEN}✔ Đã thêm block cấu hình Proxy vào .env${NC}"
fi

echo -e "   ${YELLOW}➜ Đang khởi tạo msfrpcd...${NC}"
if command -v msfrpcd &> /dev/null; then
    if pgrep -f msfrpcd > /dev/null; then
        echo -e "     ${GREEN}✔ msfrpcd đã đang chạy nền.${NC}"
    else
        msfrpcd -P "$current_rpc_pass" -S -a 127.0.0.1 -p 55553 > /dev/null 2>&1
        sleep 2
        pgrep -n -f msfrpcd > .msfrpcd_pid
        echo -e "     ${GREEN}✔ msfrpcd đã được bật thành công trên port 55553.${NC}"
    fi
else
    echo -e "     ${RED}✘ msfrpcd chưa được cài đặt, dù metasploit-framework có trong danh sách APT. Vui lòng kiểm tra lại.${NC}"
fi


# 9. Tạo cấu trúc thư mục output an toàn
echo -e "\n${CYAN}[9/9] Tạo cấu trúc thư mục output (chế độ 0700)...${NC}"
mkdir -p output/c2_logs output data wordlists 
chmod 700 output output/c2_logs 2>/dev/null || true
touch output/audit.log
chmod 600 output/audit.log 2>/dev/null || true
echo -e "   ${GREEN}✔ output/ & output/c2_logs/ đã tạo (permission 0700)${NC}"
echo -e "   ${GREEN}✔ output/audit.log đã tạo (permission 0600)${NC}"

# ═══════════════════════════════════════════════
# [NEW] Generate MSF Module Map V2 (Offline Smart Index)
# ═══════════════════════════════════════════════
echo -e "\n${CYAN}[+] Tạo MSF Module Map V2 (Offline Smart Index)...${NC}"
if [ -f "scripts/generate_msf_map_v2.py" ]; then
    python3 scripts/generate_msf_map_v2.py --include-post 2>&1 | tail -5
    if [ -f "data/msf_module_map.json" ]; then
        MODULE_COUNT=$(python3 -c "import json; d=json.load(open('data/msf_module_map.json')); print(d.get('_meta',{}).get('total_modules',0))" 2>/dev/null || echo "?")
        echo -e "   ${GREEN}✔ MSF Module Map: ${MODULE_COUNT} modules indexed → data/msf_module_map.json${NC}"
    else
        echo -e "   ${YELLOW}⚠ MSF Module Map generation failed. Smart Lookup sẽ fallback về msfconsole.${NC}"
    fi
else
    echo -e "   ${YELLOW}⚠ generate_msf_map_v2.py not found. Skipping.${NC}"
fi

echo -e "\n${GREEN}✅ THIẾT LẬP HOÀN TẤT AN TOÀN! (PenLabs V1.0 — The Apex Engine)${NC}"
echo -e "\n📌 Hướng dẫn chạy:"
echo -e "   source venv/bin/activate"
echo -e "   python3 main.py --target [target] --profile [stealth|fast|web-vuln|full-audit|continuous]"
echo -e ""
echo -e "📌 Tùy chọn OPSEC mới:"
echo -e "   --scope scope.txt       # Giới hạn target theo file"
echo -e "   --permissive            # Bỏ qua scope check (lab/CTF)"
echo -e ""
echo -e "📜 Audit Log: output/audit.log"
