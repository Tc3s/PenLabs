#!/bin/bash
# scripts/download_wordlists.sh
# Kéo các từ điển (Wordlists) phục vụ Fuzzing và Brute-force hiện đại.

WORDLIST_DIR="$(dirname "$0")/../wordlists"
mkdir -p "$WORDLIST_DIR"
cd "$WORDLIST_DIR" || exit 1

echo -e "\033[96m[*] Đang tải các Wordlists chuyên dụng từ SecLists...\033[0m"

# 1. Common Directory Fuzzing
if [ ! -f "common.txt" ]; then
    echo "  -> Tải common.txt..."
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" -O common.txt
fi

# 2. Raft Large Directories (Thay cho wordlists nặng chục GB)
if [ ! -f "raft-large-directories.txt" ]; then
    echo "  -> Tải raft-large-directories.txt..."
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt" -O raft-large-directories.txt
fi

# 3. Parameters Fuzzing (XSS/SSRF)
if [ ! -f "params.txt" ]; then
    echo "  -> Tải params.txt (Burp Param Miner)..."
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt" -O params.txt
fi

# 4. Top 10000 Passwords (Mở rộng từ top-1000.txt)
if [ ! -f "top-10000-passwords.txt" ]; then
    echo "  -> Tải top-10000-passwords.txt..."
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" -O top-10000-passwords.txt
fi

# 5. [Custom] Sensitive Paths 2026. Nhắm vào Dev/Cloud Leaks
if [ ! -f "sensitive_paths_2026.txt" ]; then
    echo "  -> Bổ sung sensitive_paths_2026.txt..."
    cat <<EOF > sensitive_paths_2026.txt
.env
.env.backup
.env.dev
.env.staging
.env.localhost
.env.test
.git/config
.git/HEAD
.gitignore
.aws/credentials
.aws/config
.ssh/id_rsa
.ssh/id_ed25519
.dockerignore
docker-compose.yml
docker-compose.yaml
serverless.yml
swagger.yaml
swagger.json
api-docs
api/swagger
actuator/env
actuator/health
v1/api-docs
v2/api-docs
v3/api-docs
phpinfo.php
info.php
test.php
.idea/workspace.xml
.vscode/settings.json
config/database.yml
db/seeds.rb
composer.json
composer.lock
package.json
package-lock.json
yarn.lock
pom.xml
build.gradle
sitemap.xml
robots.txt
crossdomain.xml
clientaccesspolicy.xml
EOF
fi

echo -e "\033[92m[+] Việc tải Wordlists đã hoàn tất!\033[0m"
ls -lh
