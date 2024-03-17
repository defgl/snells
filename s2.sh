#!/bin/bash

# SCP Foundation - Snell with Shadow-TLS Deployment Protocol Simplified

# Define color codes
red='\e[31m'
green='\e[92m' 
yellow='\e[33m'  
reset='\e[0m'
underline='\e[4m'
blink='\e[5m'  
cyan='\e[96m'
purple='\e[35m'

# Color print functions
_red() { echo -e "${red}$@${reset}"; }
_green() { echo -e "${green}$@${reset}"; }
_yellow() { echo -e "${yellow}$@${reset}"; }  
_cyan() { echo -e "${cyan}$@${reset}"; }
_magenta() { echo -e "${purple}$@${reset}"; }  
_red_bg() { echo -e "\e[41m$@${reset}"; }

is_err=$(_red_bg "ERROR!")
is_warn=$(_red_bg "WARNING!")

err() {  
    echo -e "\n$is_err $@\n" && return 1
}

warn() {
    echo -e "\n$is_warn $@\n"  
}

# Function to display log messages
msg() {
    case $1 in
        err) echo -e "${red}[ERROR] $2${reset}" ;;
        warn) echo -e "${yellow}[WARN] $2${reset}" ;;
        ok) echo -e "${green}[OK] $2${reset}" ;;
        info) echo -e "[INFO] $2" ;;
        *) echo -e "[LOG] $2" ;;
    esac
}

# Check for root privileges 
[[ $EUID -ne 0 ]] && msg err "Root clearance required." && exit 1

# Detect package manager
cmd=$(type -P apt-get || type -P yum)  
[[ ! $cmd ]] && echo "This script is only working with ${yellow}(Ubuntu or Debian or CentOS)${none}, ya dig?" && exit 1

# We gotta have systemd 
[[ ! $(type -P systemctl) ]] && {
    echo "Your system's missing ${yellow}(systemctl)${none}, try running: ${yellow} ${cmd} update -y;${cmd} install systemd -y ${none} for fixing.." && exit 1  
}

# Initialization  
snell_workspace="/etc/snell-server"
snell_service="/etc/systemd/system/snell.service"
shadow_tls_workspace="/etc/shadow-tls"  
shadow_tls_service="/etc/systemd/system/shadow-tls.service"
dependencies="wget unzip jq net-tools curl cron"

# Simplified installation of missing packages  
install_pkg() {
    msg info "Checking and installing missing dependencies..."  
    apt-get update -y
    apt-get install -y dnsutils ${dependencies[@]}  
}

# Function to generate a random PSK
generate_random_psk() {
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32  
}

# Function to generate a random password  
generate_random_password() {
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16
}

# Function to find an unused port  
find_unused_port() {
    local port
    while :; do  
        port=$(shuf -i 10000-60000 -n 1)
        if ! ss -tuln | grep -q ":${port} " ; then
            echo $port  
            break
        fi
    done
}

# Create systemd service file for Snell
create_snell_systemd() {
    cat > $snell_service << EOF  
    [Unit]
    Description=Snell Proxy Service
    After=network.target

    [Service]  
    User=root
    WorkingDirectory=${snell_workspace}
    ExecStart=${snell_workspace}/snell-server -c snell-server.conf
    Restart=on-failure
    RestartPreventExitStatus=1
    RestartSec=5

    [Install]
    WantedBy=multi-user.target  
EOF
    systemctl daemon-reload
    systemctl enable snell
    msg ok "Snell systemd service created."
}

# Create Snell server configuration file  
create_snell_conf() {
    read -rp "Assign a port for Snell (Leave it blank for a random one): " snell_port 
    [[ -z ${snell_port} ]] && snell_port=$(find_unused_port) && echo "[INFO] Assigned a random port for Snell: $snell_port"
    read -rp "Enter PSK for Snell (Leave it blank to generate a random one): " snell_psk
    [[ -z ${snell_psk} ]] && snell_psk=$(generate_random_psk) && echo "[INFO] Generated a random PSK for Snell: $snell_psk"

    cat > ${snell_workspace}/snell-server.conf << EOF
[snell-server]  
listen = 0.0.0.0:${snell_port}
psk = ${snell_psk}

EOF

    msg ok "Snell configuration established."
}

# Create systemd service file for Shadow-TLS 
create_shadow_tls_systemd() {
    cat > $shadow_tls_service << EOF
    [Unit]  
    Description=Shadow-TLS Proxy Service
    After=network.target
    
    [Service]
    Type=simple  
    ExecStart=/usr/local/bin/shadow-tls -- v3 server --listen 0.0.0.0:${shadow_tls_port} --server 127.0.0.1:${snell_port} --tls ${shadow_tls_tls_domain}:443 --password ${shadow_tls_password}
    SyslogIdentifier=shadow-tls
    
    [Install]
    WantedBy=multi-user.target  
EOF
    systemctl daemon-reload
    systemctl enable shadow-tls
    msg ok "Shadow-TLS systemd service created."  
}

# Configure Shadow-TLS  
config_shadow_tls() { 
    read -rp "Assign a port for Shadow-TLS (Default: 8443): " shadow_tls_port
    [[ -z ${shadow_tls_port} ]] && shadow_tls_port=$(find_unused_port) && echo "[INFO] Generated a random port for Shadow-TLS: $shadow_tls_port"
    read -rp "Enter TLS domain for Shadow-TLS (Default: gateway.icloud.com): " shadow_tls_tls_domain  
    [[ -z ${shadow_tls_tls_domain} ]] && shadow_tls_tls_domain="gateway.icloud.com"
    read -rp "Enter password for Shadow-TLS (Leave it blank to generate a random one): " shadow_tls_password
    [[ -z ${shadow_tls_password} ]] && shadow_tls_password=$(generate_random_password) && echo "[INFO] Generated a random password for Shadow-TLS: $shadow_tls_password"

    msg ok "Shadow-TLS configuration established."
    
    echo -e "Proxy-TUIC = snell, your-server-ip, ${shadow_tls_port}, psk=${snell_psk}, version=3, shadow-tls-password=${shadow_tls_password}, shadow-tls-sni=${shadow_tls_tls_domain}, shadow-tls-version=3"
}

# Install Snell and Shadow-TLS  
install() {
    if [[ -e "${snell_workspace}/snell-server" ]] || [[ -e "/usr/local/bin/shadow-tls" ]]; then
        read -rp "Snell or Shadow-TLS is already installed. Reinstall? (y/n): " input
        case "$input" in
            y|Y) uninstall ;;
            *) return 0 ;;
        esac
    fi

    install_pkg

    # Install Snell
    msg info "Downloading Snell..."
    mkdir -p "${snell_workspace}"
    cd "${snell_workspace}" || exit 1
    arch=$(uname -m)
    case $arch in
        x86_64) snell_url="https://dl.nssurge.com/snell/snell-server-v4.0.1-linux-amd64.zip" ;;
        aarch64) snell_url="https://dl.nssurge.com/snell/snell-server-v4.0.1-linux-aarch64.zip" ;;
        *) msg err "Unsupported architecture: $arch" && exit 1 ;;
    esac
    wget -O snell-server.zip "${snell_url}"
    unzip -o snell-server.zip
    rm snell-server.zip
    chmod +x snell-server

    create_snell_systemd
    create_snell_conf

    # Install Shadow-TLS
    msg info "Downloading Shadow-TLS..."
    mkdir -p "${shadow_tls_workspace}"
    cd "${shadow_tls_workspace}" || exit 1

    # Get the latest release of Shadow-TLS from GitHub API
    latest_release=$(wget -qO- https://api.github.com/repos/ihciah/shadow-tls/releases/latest)
    latest_version=$(echo "$latest_release" | jq -r '.tag_name')
    case $arch in
        x86_64) shadow_tls_url=$(echo "$latest_release" | jq -r '.assets[] | select(.name | contains("x86_64-unknown-linux-musl")) | .browser_download_url') ;;
        aarch64) shadow_tls_url=$(echo "$latest_release" | jq -r '.assets[] | select(.name | contains("aarch64-unknown-linux-musl")) | .browser_download_url') ;;
        *) msg err "Unsupported architecture: $arch" && exit 1 ;;
    esac

    wget -O shadow-tls "${shadow_tls_url}"
    chmod +x shadow-tls
    mv shadow-tls /usr/local/bin/

    config_shadow_tls
    create_shadow_tls_systemd

    run
    msg ok "Snell with Shadow-TLS ${latest_version} deployed successfully."
}

# Uninstall Snell and Shadow-TLS  
uninstall() {
    stop  
    systemctl disable snell
    systemctl disable shadow-tls

    # Remove service files and workspaces  
    rm -f "${snell_service}"
    rm -f "${shadow_tls_service}"  
    rm -rf "${snell_workspace}"
    rm -rf "${shadow_tls_workspace}"
    rm -f "/usr/local/bin/shadow-tls"  

    systemctl daemon-reload
    
    msg ok "Snell and Shadow-TLS have been uninstalled."  
}

# Run Snell and Shadow-TLS  
run() {
    systemctl start snell  
    systemctl start shadow-tls
    sleep 2
    if systemctl is-active --quiet snell && systemctl is-active --quiet shadow-tls; then  
        msg ok "Snell and Shadow-TLS are running now."
    else
        msg err "Failed to start Snell or Shadow-TLS. Please check the logs."  
    fi
}

# Stop Snell and Shadow-TLS
stop() {  
    systemctl stop snell
    systemctl stop shadow-tls
    msg ok "Snell and Shadow-TLS have been stopped."  
}

# Restart Snell and Shadow-TLS  
restart() {
    systemctl restart snell
    systemctl restart shadow-tls  
    sleep 2
    if systemctl is-active --quiet snell && systemctl is-active --quiet shadow-tls; then
        msg ok "Snell and Shadow-TLS have been restarted."  
    else
        msg err "Failed to restart Snell or Shadow-TLS. Please check the logs."
    fi  
}

# Check Snell and Shadow-TLS configuration  
checkconfig() {
    if [ -f "${snell_workspace}/snell-server.conf" ]; then  
        echo "Snell configuration:"
        cat "${snell_workspace}/snell-server.conf"
    else
        msg err "Snell configuration file not found."  
    fi

    echo "Shadow-TLS configuration:"  
    systemctl cat shadow-tls | grep -E "listen|server|tls|password"
}

# Modify Snell and Shadow-TLS configuration  
modify() {
    _green "1. Modify Snell Configuration"
    _yellow "2. Modify Shadow-TLS Configuration"
    echo "3. Back to Main Menu"  
    read -p "Select operation (1-3): " operation
    
    case $operation in  
        1) vi "${snell_workspace}/snell-server.conf" ;;
        2) vi "${shadow_tls_service}" ;;
        3) menu ;;  
        *) msg err "Invalid operation." ;;
    esac

    msg ok "Don't forget to restart services to apply changes: ./snell-shadowtls.sh restart"  
}

# Manage Snell and Shadow-TLS services  
manage() {
    _green "1. Start" 
    _red "2. Stop"
    _yellow "3. Restart"
    echo "4. Modify Config"
    echo "5. Back to Main Menu"  
    read -p "Select operation (1-5): " operation
    
    case $operation in
        1) run ;;  
        2) stop ;;
        3) restart ;;
        4) modify ;; 
        5) menu ;;
        *) msg err "Invalid operation." ;;
    esac  
}

# Main menu
menu() {  
    _cyan "${cyan}${underline}${blink}Snell with Shadow-TLS, double the speed, double the fun!${reset}\n"
    _green "1. Install"
    _red "2. Uninstall"
    _yellow "3. Manage"
    echo "4. Exit"  
    read -p "Select operation (1-4): " operation

    case $operation in  
        1) install ;;
        2) uninstall ;;
        3) manage ;;
        4) exit 0 ;;  
        *) msg err "Invalid operation." ;;
    esac
}

# Script starts here  
menu