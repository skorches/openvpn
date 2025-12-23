#!/bin/bash
# OpenVPN Server Installation Script
# Optimized for bypassing network blocks and censorship
# Compatible with Debian, Ubuntu, CentOS, Fedora, Arch Linux, and more

set -euo pipefail

# Color definitions
if [[ -t 1 ]] || [[ "${FORCE_COLOR:-}" == "1" ]]; then
	readonly COLOR_RESET='\033[0m'
	readonly COLOR_RED='\033[0;31m'
	readonly COLOR_GREEN='\033[0;32m'
	readonly COLOR_YELLOW='\033[0;33m'
	readonly COLOR_BLUE='\033[0;34m'
	readonly COLOR_CYAN='\033[0;36m'
	readonly COLOR_BOLD='\033[1m'
else
	readonly COLOR_RESET=''
	readonly COLOR_RED=''
	readonly COLOR_GREEN=''
	readonly COLOR_YELLOW=''
	readonly COLOR_BLUE=''
	readonly COLOR_CYAN=''
	readonly COLOR_BOLD=''
fi

# Logging functions
log_info() {
	echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*"
}

log_success() {
	echo -e "${COLOR_GREEN}[OK]${COLOR_RESET} $*"
}

log_warn() {
	echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*"
}

log_error() {
	echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $*" >&2
}

log_fatal() {
	echo -e "${COLOR_RED}[FATAL]${COLOR_RESET} $*" >&2
	exit 1
}

# Check if running as root
check_root() {
	if [[ $EUID -ne 0 ]]; then
		log_fatal "This script must be run as root. Use sudo or run as root user."
	fi
}

# Detect OS
detect_os() {
	if [[ -f /etc/os-release ]]; then
		. /etc/os-release
		OS=$ID
		OS_VERSION=$VERSION_ID
	else
		log_fatal "Cannot detect OS. /etc/os-release not found."
	fi
}

# Install dependencies
install_dependencies() {
	log_info "Installing dependencies..."
	
	case $OS in
		ubuntu|debian)
			export DEBIAN_FRONTEND=noninteractive
			apt-get update -qq
			apt-get install -y -qq openvpn openssl ca-certificates iptables curl wget
			;;
		centos|rhel|rocky|almalinux|oracle)
			if command -v dnf &> /dev/null; then
				dnf install -y -q epel-release
				dnf install -y -q openvpn openssl ca-certificates iptables curl wget
			else
				yum install -y -q epel-release
				yum install -y -q openvpn openssl ca-certificates iptables curl wget
			fi
			;;
		fedora)
			dnf install -y -q openvpn openssl ca-certificates iptables curl wget
			;;
		arch|manjaro)
			pacman -Sy --noconfirm openvpn openssl ca-certificates iptables curl wget
			;;
		*)
			log_fatal "Unsupported OS: $OS"
			;;
	esac
	
	log_success "Dependencies installed"
}

# Get public IP
get_public_ip() {
	local ip
	ip=$(curl -s https://api.ipify.org || curl -s https://ifconfig.me || curl -s https://icanhazip.com)
	if [[ -z "$ip" ]]; then
		log_warn "Could not detect public IP automatically"
		read -p "Enter your server's public IP address: " ip
	fi
	echo "$ip"
}

# Interactive configuration
configure_server() {
	log_info "Configuring OpenVPN server..."
	
	# Get server IP
	if [[ -z "${SERVER_IP:-}" ]]; then
		SERVER_IP=$(get_public_ip)
	fi
	
	# Bypass mode selection (for countries with extensive blocking like Russia)
	if [[ -z "${BYPASS_MODE:-}" ]]; then
		echo ""
		echo "Select bypass mode (for countries with extensive blocking):"
		echo "1) Standard (default OpenVPN settings)"
		echo "2) Aggressive (optimized for Russia/China - TCP 443, advanced obfuscation)"
		read -p "Bypass mode [2]: " bypass_choice
		bypass_choice=${bypass_choice:-2}
		
		case $bypass_choice in
			1) BYPASS_MODE="standard" ;;
			2) BYPASS_MODE="aggressive" ;;
			*) BYPASS_MODE="aggressive" ;;
		esac
	fi
	
	# Protocol selection
	if [[ -z "${PROTOCOL:-}" ]]; then
		if [[ "$BYPASS_MODE" == "aggressive" ]]; then
			# For aggressive mode, default to TCP on port 443
			PROTOCOL="tcp"
			log_info "Aggressive mode: Using TCP protocol (better for bypassing DPI)"
		else
			echo ""
			echo "Select protocol:"
			echo "1) UDP (recommended, faster)"
			echo "2) TCP (more reliable, can bypass some firewalls)"
			read -p "Protocol [1]: " protocol_choice
			protocol_choice=${protocol_choice:-1}
			
			case $protocol_choice in
				1) PROTOCOL="udp" ;;
				2) PROTOCOL="tcp" ;;
				*) PROTOCOL="udp" ;;
			esac
		fi
	fi
	
	# Port selection
	if [[ -z "${PORT:-}" ]]; then
		if [[ "$BYPASS_MODE" == "aggressive" ]]; then
			# Port 443 looks like HTTPS traffic - hardest to block
			PORT=443
			log_info "Aggressive mode: Using port 443 (HTTPS port - best for bypassing blocks)"
		else
			read -p "Port [1194]: " port_input
			PORT=${port_input:-1194}
		fi
	fi
	
	# DNS selection
	if [[ -z "${DNS:-}" ]]; then
		echo ""
		echo "Select DNS provider:"
		echo "1) Cloudflare (1.1.1.1)"
		echo "2) Google (8.8.8.8)"
		echo "3) Quad9 (9.9.9.9)"
		echo "4) OpenDNS (208.67.222.222)"
		echo "5) Custom"
		read -p "DNS [1]: " dns_choice
		dns_choice=${dns_choice:-1}
		
		case $dns_choice in
			1) DNS="1.1.1.1" ;;
			2) DNS="8.8.8.8" ;;
			3) DNS="9.9.9.9" ;;
			4) DNS="208.67.222.222" ;;
			5)
				read -p "Enter custom DNS: " DNS
				;;
			*) DNS="1.1.1.1" ;;
		esac
	fi
	
	# Cipher selection
	if [[ -z "${CIPHER:-}" ]]; then
		echo ""
		echo "Select cipher (for bypassing blocks, AES-256-GCM is recommended):"
		echo "1) AES-256-GCM (recommended, strong)"
		echo "2) AES-128-GCM (faster)"
		echo "3) CHACHA20-POLY1305 (modern, fast)"
		read -p "Cipher [1]: " cipher_choice
		cipher_choice=${cipher_choice:-1}
		
		case $cipher_choice in
			1) CIPHER="AES-256-GCM" ;;
			2) CIPHER="AES-128-GCM" ;;
			3) CIPHER="CHACHA20-POLY1305" ;;
			*) CIPHER="AES-256-GCM" ;;
		esac
	fi
	
	# Compression
	if [[ -z "${COMPRESSION:-}" ]]; then
		if [[ "$BYPASS_MODE" == "aggressive" ]]; then
			# Disable compression in aggressive mode (can help with obfuscation)
			COMPRESSION=""
		else
			echo ""
			read -p "Enable compression? (y/n) [n]: " compression_choice
			compression_choice=${compression_choice:-n}
			if [[ "$compression_choice" =~ ^[Yy]$ ]]; then
				COMPRESSION="compress lz4-v2"
			else
				COMPRESSION=""
			fi
		fi
	fi
	
	# MTU settings for aggressive mode
	if [[ "$BYPASS_MODE" == "aggressive" ]]; then
		MTU=1200
		FRAGMENT=1200
		MSSFIX=1200
	else
		MTU=1500
		FRAGMENT=""
		MSSFIX=""
	fi
}

# Setup EasyRSA
setup_easyrsa() {
	log_info "Setting up EasyRSA for certificate generation..."
	
	local easyrsa_dir="/etc/openvpn/easy-rsa"
	local easyrsa_version="3.1.7"
	
	mkdir -p "$easyrsa_dir"
	cd "$easyrsa_dir"
	
	if [[ ! -f easyrsa ]]; then
		wget -q "https://github.com/OpenVPN/easy-rsa/releases/download/v${easyrsa_version}/EasyRSA-${easyrsa_version}.tgz"
		tar xzf "EasyRSA-${easyrsa_version}.tgz" --strip-components=1
		rm -f "EasyRSA-${easyrsa_version}.tgz"
	fi
	
	# Initialize PKI
	./easyrsa init-pki
	
	# Build CA
	./easyrsa --batch build-ca nopass
	
	# Build server certificate
	./easyrsa --batch build-server-full server nopass
	
	# Generate DH parameters
	./easyrsa gen-dh
	
	# Generate tls-crypt key for obfuscation (bypasses DPI)
	openvpn --genkey --secret pki/tls-crypt.key
	
	log_success "EasyRSA setup complete"
}

# Configure firewall
configure_firewall() {
	log_info "Configuring firewall..."
	
	if command -v ufw &> /dev/null; then
		ufw allow ${PORT}/${PROTOCOL} >/dev/null 2>&1 || true
		log_success "UFW firewall configured"
	elif command -v firewall-cmd &> /dev/null; then
		firewall-cmd --permanent --add-port=${PORT}/${PROTOCOL} >/dev/null 2>&1 || true
		firewall-cmd --reload >/dev/null 2>&1 || true
		log_success "Firewalld configured"
	elif command -v iptables &> /dev/null; then
		iptables -I INPUT -p ${PROTOCOL} --dport ${PORT} -j ACCEPT >/dev/null 2>&1 || true
		if command -v iptables-save &> /dev/null; then
			iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
		fi
		log_success "iptables configured"
	fi
}

# Enable IP forwarding
enable_ip_forwarding() {
	log_info "Enabling IP forwarding..."
	
	sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
	
	# Make it persistent
	if [[ -f /etc/sysctl.conf ]]; then
		if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
			echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
		fi
	fi
	
	log_success "IP forwarding enabled"
}

# Create server configuration
create_server_config() {
	log_info "Creating OpenVPN server configuration..."
	
	local server_config="/etc/openvpn/server.conf"
	local easyrsa_dir="/etc/openvpn/easy-rsa"
	
	# Build configuration based on bypass mode
	local obfuscation_settings=""
	if [[ "${BYPASS_MODE:-}" == "aggressive" ]]; then
		obfuscation_settings="# Advanced obfuscation for bypassing extensive DPI (Russia/China)
# Smaller MTU makes packets harder to analyze
tun-mtu ${MTU}
fragment ${FRAGMENT}
mssfix ${MSSFIX}

# Packet size randomization (helps evade pattern detection)
txqueuelen 1000

# Additional buffer optimizations
sndbuf 393216
rcvbuf 393216

# Fast I/O for better performance with obfuscation
fast-io

# Reduce packet patterns
explicit-exit-notify 0"
	else
		obfuscation_settings="# Standard obfuscation settings
sndbuf 0
rcvbuf 0"
	fi

	cat > "$server_config" <<EOF
# OpenVPN Server Configuration
# Optimized for bypassing network blocks
# Bypass Mode: ${BYPASS_MODE:-standard}

# Network settings
port ${PORT}
proto ${PROTOCOL}
dev tun

# Certificate files
ca ${easyrsa_dir}/pki/ca.crt
cert ${easyrsa_dir}/pki/issued/server.crt
key ${easyrsa_dir}/pki/private/server.key
dh ${easyrsa_dir}/pki/dh.pem

# Security settings
cipher ${CIPHER}
data-ciphers ${CIPHER}
auth SHA256
tls-version-min 1.2
tls-crypt ${easyrsa_dir}/pki/tls-crypt.key

# Network topology
topology subnet
server 10.8.0.0 255.255.255.0

# Push routes and DNS
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS ${DNS}"
push "block-outside-dns"

# Keepalive (shorter intervals for aggressive mode)
keepalive 10 120

# Compression
${COMPRESSION}

# Performance
user nobody
group nogroup
persist-key
persist-tun

# Logging (reduced verbosity in aggressive mode for security)
verb 2
mute 20

# Security enhancements
remote-cert-tls client
tls-server

${obfuscation_settings}
EOF

	log_success "Server configuration created"
}

# Start OpenVPN service
start_service() {
	log_info "Starting OpenVPN service..."
	
	# Try different service names based on distribution
	local service_started=false
	
	# Try openvpn@server (Debian/Ubuntu style)
	if systemctl list-unit-files | grep -q "openvpn@"; then
		systemctl enable openvpn@server >/dev/null 2>&1 || true
		if systemctl start openvpn@server >/dev/null 2>&1; then
			sleep 2
			if systemctl is-active --quiet openvpn@server; then
				service_started=true
			fi
		fi
	fi
	
	# Try openvpn-server@server (CentOS/Fedora/Arch style)
	if [[ "$service_started" == "false" ]]; then
		if systemctl list-unit-files | grep -q "openvpn-server@"; then
			systemctl enable openvpn-server@server >/dev/null 2>&1 || true
			if systemctl start openvpn-server@server >/dev/null 2>&1; then
				sleep 2
				if systemctl is-active --quiet openvpn-server@server; then
					service_started=true
				fi
			fi
		fi
	fi
	
	# Try direct openvpn service
	if [[ "$service_started" == "false" ]]; then
		if systemctl list-unit-files | grep -q "^openvpn.service"; then
			systemctl enable openvpn >/dev/null 2>&1 || true
			if systemctl start openvpn >/dev/null 2>&1; then
				sleep 2
				if systemctl is-active --quiet openvpn; then
					service_started=true
				fi
			fi
		fi
	fi
	
	if [[ "$service_started" == "true" ]]; then
		log_success "OpenVPN service started"
	else
		log_warn "OpenVPN service may not have started automatically."
		log_warn "You may need to start it manually:"
		log_warn "  systemctl start openvpn@server      # Debian/Ubuntu"
		log_warn "  systemctl start openvpn-server@server  # CentOS/Fedora/Arch"
		log_warn "Or check the service status and logs"
	fi
}

# Create client configuration function
create_client_config() {
	local client_name="$1"
	
	log_info "Creating client certificate for: $client_name"
	
	local easyrsa_dir="/etc/openvpn/easy-rsa"
	cd "$easyrsa_dir"
	
	# Generate client certificate
	./easyrsa --batch build-client-full "$client_name" nopass
	
	# Create client directory
	local client_dir="/root/${client_name}"
	mkdir -p "$client_dir"
	
	# Copy certificates
	cp "${easyrsa_dir}/pki/ca.crt" "$client_dir/"
	cp "${easyrsa_dir}/pki/issued/${client_name}.crt" "$client_dir/"
	cp "${easyrsa_dir}/pki/private/${client_name}.key" "$client_dir/"
	cp "${easyrsa_dir}/pki/tls-crypt.key" "$client_dir/"
	
	# Build client obfuscation settings
	local client_obfuscation=""
	if [[ "${BYPASS_MODE:-}" == "aggressive" ]]; then
		client_obfuscation="# Advanced obfuscation settings for bypassing DPI
tun-mtu ${MTU}
fragment ${FRAGMENT}
mssfix ${MSSFIX}
txqueuelen 1000
sndbuf 393216
rcvbuf 393216
fast-io
explicit-exit-notify 0"
	else
		client_obfuscation="# Standard obfuscation
sndbuf 0
rcvbuf 0"
	fi

	# Create client configuration
	cat > "$client_dir/${client_name}.ovpn" <<EOF
# OpenVPN Client Configuration
# Generated for bypassing network blocks
# Bypass Mode: ${BYPASS_MODE:-standard}

client
dev tun
proto ${PROTOCOL}
remote ${SERVER_IP} ${PORT}
resolv-retry infinite
nobind
persist-key
persist-tun

# Security
remote-cert-tls server
tls-client
cipher ${CIPHER}
data-ciphers ${CIPHER}
auth SHA256
tls-version-min 1.2
tls-crypt tls-crypt.key

# Compression
${COMPRESSION}

# Performance
verb 2
mute 20

${client_obfuscation}

# Certificates
<ca>
$(cat "$client_dir/ca.crt")
</ca>
<cert>
$(cat "$client_dir/${client_name}.crt")
</cert>
<key>
$(cat "$client_dir/${client_name}.key")
</key>
<tls-crypt>
$(cat "$client_dir/tls-crypt.key")
</tls-crypt>
EOF

	# Clean up separate certificate files
	rm -f "$client_dir/ca.crt" "$client_dir/${client_name}.crt" "$client_dir/${client_name}.key" "$client_dir/tls-crypt.key"
	
	log_success "Client configuration created: $client_dir/${client_name}.ovpn"
	echo ""
	echo "Client configuration file: $client_dir/${client_name}.ovpn"
	echo "Transfer this file to your client device and import it into your OpenVPN client."
}

# Main installation function
main_install() {
	log_info "Starting OpenVPN server installation..."
	
	check_root
	detect_os
	install_dependencies
	configure_server
	setup_easyrsa
	enable_ip_forwarding
	configure_firewall
	create_server_config
	start_service
	
	echo ""
	log_success "OpenVPN server installation completed!"
	echo ""
	echo "Server IP: ${SERVER_IP}"
	echo "Port: ${PORT}"
	echo "Protocol: ${PROTOCOL}"
	echo "DNS: ${DNS}"
	echo ""
	echo "To create a client configuration, run:"
	echo "  $0 add-client <client-name>"
	echo ""
}

# Add client function
add_client() {
	if [[ -z "${1:-}" ]]; then
		log_fatal "Please provide a client name: $0 add-client <client-name>"
	fi
	
	check_root
	create_client_config "$1"
}

# Main menu
show_menu() {
	while true; do
		echo ""
		echo "OpenVPN Server Manager"
		echo "======================"
		echo "1) Install OpenVPN server"
		echo "2) Add a new client"
		echo "3) Exit"
		echo ""
		read -p "Select an option [1-3]: " choice
		
		case $choice in
			1)
				main_install
				;;
			2)
				read -p "Enter client name: " client_name
				if [[ -n "$client_name" ]]; then
					add_client "$client_name"
				fi
				;;
			3)
				exit 0
				;;
			*)
				log_error "Invalid option"
				;;
		esac
	done
}

# Main script logic
case "${1:-}" in
	install)
		main_install
		;;
	add-client)
		add_client "${2:-}"
		;;
	"")
		show_menu
		;;
	*)
		echo "Usage: $0 [install|add-client <name>]"
		exit 1
		;;
esac

