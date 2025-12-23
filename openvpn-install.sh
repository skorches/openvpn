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

# Auto-configure server with smart defaults
configure_server() {
	log_info "Configuring OpenVPN server with optimal settings..."
	
	# Get server IP
	if [[ -z "${SERVER_IP:-}" ]]; then
		SERVER_IP=$(get_public_ip)
		log_info "Detected server IP: ${SERVER_IP}"
	fi
	
	# Use aggressive mode by default (best for bypassing blocks)
	BYPASS_MODE=${BYPASS_MODE:-aggressive}
	
	# Set optimal defaults for aggressive mode
	if [[ "$BYPASS_MODE" == "aggressive" ]]; then
		PROTOCOL=${PROTOCOL:-tcp}
		PORT=${PORT:-443}
		CIPHER=${CIPHER:-AES-256-GCM}
		DNS=${DNS:-1.1.1.1}
		COMPRESSION=""
		MTU=1200
		FRAGMENT=1200
		MSSFIX=1200
		log_info "Using aggressive bypass mode (Port 443 TCP - optimized for Russia/China)"
	else
		PROTOCOL=${PROTOCOL:-udp}
		PORT=${PORT:-1194}
		CIPHER=${CIPHER:-AES-256-GCM}
		DNS=${DNS:-1.1.1.1}
		COMPRESSION=""
		MTU=1500
		FRAGMENT=""
		MSSFIX=""
	fi
	
	log_info "Configuration: ${PROTOCOL}://${SERVER_IP}:${PORT} | Cipher: ${CIPHER} | DNS: ${DNS}"
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
	crl-verify /etc/openvpn/crl.pem

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
	
	# Copy certificates (temporarily for embedding)
	cp "${easyrsa_dir}/pki/ca.crt" "$client_dir/"
	cp "${easyrsa_dir}/pki/issued/${client_name}.crt" "$client_dir/"
	cp "${easyrsa_dir}/pki/private/${client_name}.key" "$client_dir/"
	cp "${easyrsa_dir}/pki/tls-crypt.key" "$client_dir/"
	
	# Read and clean keys for mobile compatibility (remove trailing whitespace, normalize line endings)
	local ca_cert cert key tls_crypt_key
	ca_cert=$(cat "$client_dir/ca.crt" | sed 's/[[:space:]]*$//' | tr -d '\r')
	cert=$(cat "$client_dir/${client_name}.crt" | sed 's/[[:space:]]*$//' | tr -d '\r')
	key=$(cat "$client_dir/${client_name}.key" | sed 's/[[:space:]]*$//' | tr -d '\r')
	tls_crypt_key=$(cat "$client_dir/tls-crypt.key" | sed 's/[[:space:]]*$//' | tr -d '\r')
	
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

# Compression
${COMPRESSION}

# Performance
verb 2
mute 20

${client_obfuscation}

# Certificates (embedded for mobile compatibility)
<ca>
${ca_cert}
</ca>
<cert>
${cert}
</cert>
<key>
${key}
</key>
<tls-crypt>
${tls_crypt_key}
</tls-crypt>
EOF

	# Clean up separate certificate files
	rm -f "$client_dir/ca.crt" "$client_dir/${client_name}.crt" "$client_dir/${client_name}.key" "$client_dir/tls-crypt.key"
	
	echo ""
	log_success "Client configuration created!"
	echo ""
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo "  File location: $client_dir/${client_name}.ovpn"
	echo ""
	echo "  To use this file:"
	echo "  1. Transfer it to your device (scp, email, etc.)"
	echo "  2. Import it into your OpenVPN client"
	echo "  3. Connect!"
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo ""
}

# Main installation function
main_install() {
	echo ""
	log_info "🚀 Starting OpenVPN server installation..."
	echo ""
	
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
	log_success "✅ OpenVPN server installation completed!"
	echo ""
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo "  Server Configuration:"
	echo "  • IP Address: ${SERVER_IP}"
	echo "  • Port: ${PORT}"
	echo "  • Protocol: ${PROTOCOL}"
	echo "  • Cipher: ${CIPHER}"
	echo "  • DNS: ${DNS}"
	echo "  • Bypass Mode: ${BYPASS_MODE}"
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo ""
	echo "To add a user, run:"
	echo "  $0 add <username>"
	echo ""
}

# Add client function (simplified command)
add_client() {
	if [[ -z "${1:-}" ]]; then
		log_fatal "Please provide a username: $0 add <username>"
	fi
	
	local client_name="$1"
	
	# Validate client name (alphanumeric and hyphens only)
	if [[ ! "$client_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
		log_fatal "Invalid username. Use only letters, numbers, hyphens, and underscores."
	fi
	
	check_root
	
	# Check if server is installed
	if [[ ! -f /etc/openvpn/server.conf ]]; then
		log_fatal "OpenVPN server is not installed. Run '$0 install' first."
	fi
	
	# Load server configuration
	if [[ -f /etc/openvpn/server.conf ]]; then
		# Try to extract settings from existing config
		PORT=${PORT:-$(grep "^port " /etc/openvpn/server.conf | awk '{print $2}' || echo "443")}
		PROTOCOL=${PROTOCOL:-$(grep "^proto " /etc/openvpn/server.conf | awk '{print $2}' || echo "tcp")}
		CIPHER=${CIPHER:-$(grep "^cipher " /etc/openvpn/server.conf | awk '{print $2}' || echo "AES-256-GCM")}
		DNS=${DNS:-$(grep "dhcp-option DNS" /etc/openvpn/server.conf | awk '{print $3}' | head -1 || echo "1.1.1.1")}
		SERVER_IP=${SERVER_IP:-$(get_public_ip)}
		
		# Detect bypass mode
		if grep -q "tun-mtu 1200" /etc/openvpn/server.conf 2>/dev/null; then
			BYPASS_MODE="aggressive"
			MTU=1200
			FRAGMENT=1200
			MSSFIX=1200
		else
			BYPASS_MODE="standard"
			MTU=1500
			FRAGMENT=""
			MSSFIX=""
		fi
		
		if grep -q "compress" /etc/openvpn/server.conf 2>/dev/null; then
			COMPRESSION="compress lz4-v2"
		else
			COMPRESSION=""
		fi
	fi
	
	log_info "Adding user: $client_name"
	create_client_config "$client_name"
	
	echo ""
	log_success "✅ User '$client_name' added successfully!"
	echo ""
}

# Uninstall OpenVPN server
uninstall_server() {
	check_root
	
	echo ""
	log_warn "⚠️  This will completely remove OpenVPN server and all configurations!"
	echo ""
	
	# Read port and protocol from config for firewall cleanup (if config exists)
	local port protocol
	if [[ -f /etc/openvpn/server.conf ]]; then
		port=$(grep "^port " /etc/openvpn/server.conf 2>/dev/null | awk '{print $2}' || echo "443")
		protocol=$(grep "^proto " /etc/openvpn/server.conf 2>/dev/null | awk '{print $2}' || echo "tcp")
		log_info "Detected configuration: Port ${port}, Protocol ${protocol}"
	else
		port="443"
		protocol="tcp"
		log_warn "OpenVPN server does not appear to be installed."
	fi
	
	echo ""
	read -p "Are you sure you want to uninstall OpenVPN? (y/n) [n]: " confirm
	if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
		log_info "Uninstallation cancelled."
		exit 0
	fi
	
	echo ""
	log_info "🗑️  Starting OpenVPN uninstallation..."
	
	# Stop and disable services
	log_info "Stopping OpenVPN services..."
	
	# Try different service names
	if systemctl list-units --type=service 2>/dev/null | grep -q "openvpn@server"; then
		systemctl stop openvpn@server >/dev/null 2>&1 || true
		systemctl disable openvpn@server >/dev/null 2>&1 || true
	fi
	
	if systemctl list-units --type=service 2>/dev/null | grep -q "openvpn-server@server"; then
		systemctl stop openvpn-server@server >/dev/null 2>&1 || true
		systemctl disable openvpn-server@server >/dev/null 2>&1 || true
	fi
	
	if systemctl list-units --type=service 2>/dev/null | grep -q "^openvpn.service"; then
		systemctl stop openvpn >/dev/null 2>&1 || true
		systemctl disable openvpn >/dev/null 2>&1 || true
	fi
	
	# Kill any remaining OpenVPN processes
	pkill -f openvpn >/dev/null 2>&1 || true
	sleep 1
	
	log_success "Services stopped"
	
	# Remove firewall rules
	log_info "Removing firewall rules..."
	
	if command -v ufw &> /dev/null; then
		ufw delete allow ${port}/${protocol} >/dev/null 2>&1 || true
		log_success "UFW rules removed"
	elif command -v firewall-cmd &> /dev/null; then
		firewall-cmd --permanent --remove-port=${port}/${protocol} >/dev/null 2>&1 || true
		firewall-cmd --reload >/dev/null 2>&1 || true
		log_success "Firewalld rules removed"
	elif command -v iptables &> /dev/null; then
		iptables -D INPUT -p ${protocol} --dport ${port} -j ACCEPT >/dev/null 2>&1 || true
		if command -v iptables-save &> /dev/null; then
			iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
		fi
		log_success "iptables rules removed"
	fi
	
	# Detect OS for package removal
	detect_os
	
	# Remove packages
	log_info "Removing OpenVPN packages..."
	
	case $OS in
		ubuntu|debian)
			apt-get remove --purge -y openvpn >/dev/null 2>&1 || true
			apt-get autoremove -y >/dev/null 2>&1 || true
			;;
		centos|rhel|rocky|almalinux|oracle)
			if command -v dnf &> /dev/null; then
				dnf remove -y openvpn >/dev/null 2>&1 || true
			else
				yum remove -y openvpn >/dev/null 2>&1 || true
			fi
			;;
		fedora)
			dnf remove -y openvpn >/dev/null 2>&1 || true
			;;
		arch|manjaro)
			pacman -R --noconfirm openvpn >/dev/null 2>&1 || true
			;;
	esac
	
	log_success "Packages removed"
	
	# Remove configuration files
	log_info "Removing configuration files..."
	
	rm -rf /etc/openvpn
	rm -rf /root/*.ovpn 2>/dev/null || true
	
	# Remove client directories
	for dir in /root/*/; do
		if [[ -f "$dir"*.ovpn ]]; then
			rm -rf "$dir"
		fi
	done 2>/dev/null || true
	
	log_success "Configuration files removed"
	
	# Note: We don't revert IP forwarding as it might be used by other services
	# Users can manually revert if needed: sysctl -w net.ipv4.ip_forward=0
	
	echo ""
	log_success "✅ OpenVPN server uninstallation completed!"
	echo ""
	log_info "Note: IP forwarding is still enabled. If not needed, you can disable it with:"
	log_info "  sysctl -w net.ipv4.ip_forward=0"
	echo ""
}

# List all users/clients
list_users() {
	check_root
	
	if [[ ! -f /etc/openvpn/server.conf ]]; then
		log_fatal "OpenVPN server is not installed. Run '$0 install' first."
	fi
	
	local easyrsa_dir="/etc/openvpn/easy-rsa"
	
	if [[ ! -d "$easyrsa_dir/pki/issued" ]]; then
		log_warn "No clients found."
		return
	fi
	
	echo ""
	log_info "📋 OpenVPN Users/Clients:"
	echo ""
	
	local count=0
	for cert in "$easyrsa_dir/pki/issued"/*.crt; do
		[[ -f "$cert" ]] || continue
		local name=$(basename "$cert" .crt)
		
		# Skip server certificate
		[[ "$name" == "server" ]] && continue
		
		# Check if revoked
		if [[ -f "$easyrsa_dir/pki/revoked/certs_by_serial.txt" ]] && \
		   grep -q "$name" "$easyrsa_dir/pki/revoked/certs_by_serial.txt" 2>/dev/null; then
			continue
		fi
		
		# Check if .ovpn file exists
		local ovpn_file="/root/${name}/${name}.ovpn"
		if [[ -f "$ovpn_file" ]]; then
			local file_size=$(du -h "$ovpn_file" | cut -f1)
			echo "  ✅ $name (config: $ovpn_file, size: $file_size)"
		else
			echo "  ⚠️  $name (certificate exists but no .ovpn file)"
		fi
		((count++))
	done
	
	if [[ $count -eq 0 ]]; then
		log_warn "No active clients found."
	else
		echo ""
		log_info "Total active clients: $count"
	fi
	echo ""
}

# Remove/revoke a user
remove_user() {
	if [[ -z "${1:-}" ]]; then
		log_fatal "Please provide a username: $0 remove <username>"
	fi
	
	local client_name="$1"
	check_root
	
	if [[ ! -f /etc/openvpn/server.conf ]]; then
		log_fatal "OpenVPN server is not installed."
	fi
	
	local easyrsa_dir="/etc/openvpn/easy-rsa"
	
	# Check if client exists
	if [[ ! -f "$easyrsa_dir/pki/issued/${client_name}.crt" ]]; then
		log_fatal "User '$client_name' not found."
	fi
	
	# Skip server certificate
	if [[ "$client_name" == "server" ]]; then
		log_fatal "Cannot remove server certificate."
	fi
	
	echo ""
	log_warn "⚠️  This will revoke user '$client_name' and remove their configuration."
	read -p "Are you sure? (y/n) [n]: " confirm
	if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
		log_info "Cancelled."
		exit 0
	fi
	
	echo ""
	log_info "Revoking certificate for: $client_name"
	
	cd "$easyrsa_dir"
	./easyrsa --batch revoke "$client_name" >/dev/null 2>&1 || true
	./easyrsa --batch gen-crl >/dev/null 2>&1 || true
	
	# Copy CRL to OpenVPN directory
	cp "$easyrsa_dir/pki/crl.pem" /etc/openvpn/crl.pem 2>/dev/null || true
	
	# Remove client directory and files
	rm -rf "/root/${client_name}" 2>/dev/null || true
	
	# Update server config to use CRL if not already
	if ! grep -q "^crl-verify" /etc/openvpn/server.conf 2>/dev/null; then
		sed -i '/^# Security enhancements/a crl-verify /etc/openvpn/crl.pem' /etc/openvpn/server.conf 2>/dev/null || true
		# Restart service to apply CRL
		if systemctl is-active --quiet openvpn@server 2>/dev/null || \
		   systemctl is-active --quiet openvpn-server@server 2>/dev/null; then
			log_info "Restarting OpenVPN service to apply changes..."
			systemctl restart openvpn@server 2>/dev/null || \
			systemctl restart openvpn-server@server 2>/dev/null || true
		fi
	fi
	
	echo ""
	log_success "✅ User '$client_name' has been revoked and removed!"
	echo ""
}

# Show server status
show_status() {
	check_root
	
	echo ""
	log_info "📊 OpenVPN Server Status:"
	echo ""
	
	# Check if installed
	if [[ ! -f /etc/openvpn/server.conf ]]; then
		log_warn "OpenVPN server is not installed."
		echo ""
		return
	fi
	
	# Service status
	local service_status="❌ Stopped"
	if systemctl is-active --quiet openvpn@server 2>/dev/null || \
	   systemctl is-active --quiet openvpn-server@server 2>/dev/null; then
		service_status="✅ Running"
	fi
	
	echo "  Service Status: $service_status"
	
	# Read config
	local port protocol server_ip
	port=$(grep "^port " /etc/openvpn/server.conf 2>/dev/null | awk '{print $2}' || echo "N/A")
	protocol=$(grep "^proto " /etc/openvpn/server.conf 2>/dev/null | awk '{print $2}' || echo "N/A")
	server_ip=$(get_public_ip)
	
	echo "  Server IP: $server_ip"
	echo "  Port: $port"
	echo "  Protocol: $protocol"
	
	# Count clients
	local easyrsa_dir="/etc/openvpn/easy-rsa"
	local client_count=0
	if [[ -d "$easyrsa_dir/pki/issued" ]]; then
		for cert in "$easyrsa_dir/pki/issued"/*.crt; do
			[[ -f "$cert" ]] || continue
			local name=$(basename "$cert" .crt)
			[[ "$name" == "server" ]] && continue
			((client_count++))
		done
	fi
	
	echo "  Total Clients: $client_count"
	
	# Check if CRL is enabled
	if grep -q "^crl-verify" /etc/openvpn/server.conf 2>/dev/null; then
		echo "  Certificate Revocation: ✅ Enabled"
	else
		echo "  Certificate Revocation: ⚠️  Not enabled"
	fi
	
	echo ""
}

# Show server information
show_info() {
	check_root
	
	if [[ ! -f /etc/openvpn/server.conf ]]; then
		log_fatal "OpenVPN server is not installed. Run '$0 install' first."
	fi
	
	echo ""
	log_info "ℹ️  OpenVPN Server Information:"
	echo ""
	
	# Read configuration
	local port protocol cipher dns bypass_mode server_ip
	port=$(grep "^port " /etc/openvpn/server.conf 2>/dev/null | awk '{print $2}' || echo "N/A")
	protocol=$(grep "^proto " /etc/openvpn/server.conf 2>/dev/null | awk '{print $2}' || echo "N/A")
	cipher=$(grep "^cipher " /etc/openvpn/server.conf 2>/dev/null | awk '{print $2}' || echo "N/A")
	dns=$(grep "dhcp-option DNS" /etc/openvpn/server.conf 2>/dev/null | awk '{print $3}' | head -1 || echo "N/A")
	server_ip=$(get_public_ip)
	
	if grep -q "tun-mtu 1200" /etc/openvpn/server.conf 2>/dev/null; then
		bypass_mode="Aggressive (Port 443, optimized for bypassing blocks)"
	else
		bypass_mode="Standard"
	fi
	
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo "  Server Configuration:"
	echo "  • IP Address: $server_ip"
	echo "  • Port: $port"
	echo "  • Protocol: $protocol"
	echo "  • Cipher: $cipher"
	echo "  • DNS: $dns"
	echo "  • Bypass Mode: $bypass_mode"
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo ""
	
	# Show connection command
	echo "  To connect, use the .ovpn file generated with:"
	echo "    $0 add <username>"
	echo ""
}

# Restart OpenVPN service
restart_service() {
	check_root
	
	if [[ ! -f /etc/openvpn/server.conf ]]; then
		log_fatal "OpenVPN server is not installed. Run '$0 install' first."
	fi
	
	log_info "Restarting OpenVPN service..."
	
	# Try different service names
	local restarted=false
	
	if systemctl list-units --type=service 2>/dev/null | grep -q "openvpn@server"; then
		systemctl restart openvpn@server >/dev/null 2>&1 && restarted=true
	elif systemctl list-units --type=service 2>/dev/null | grep -q "openvpn-server@server"; then
		systemctl restart openvpn-server@server >/dev/null 2>&1 && restarted=true
	elif systemctl list-units --type=service 2>/dev/null | grep -q "^openvpn.service"; then
		systemctl restart openvpn >/dev/null 2>&1 && restarted=true
	fi
	
	sleep 1
	
	if [[ "$restarted" == "true" ]]; then
		log_success "✅ OpenVPN service restarted"
	else
		log_error "Failed to restart service. Check status manually."
	fi
	echo ""
}

# View OpenVPN logs
view_logs() {
	check_root
	
	if [[ ! -f /etc/openvpn/server.conf ]]; then
		log_fatal "OpenVPN server is not installed. Run '$0 install' first."
	fi
	
	echo ""
	log_info "📄 OpenVPN Logs (last 50 lines, press Ctrl+C to exit):"
	echo ""
	
	# Try to get logs from journalctl
	if systemctl list-units --type=service 2>/dev/null | grep -q "openvpn@server"; then
		journalctl -u openvpn@server -n 50 --no-pager
	elif systemctl list-units --type=service 2>/dev/null | grep -q "openvpn-server@server"; then
		journalctl -u openvpn-server@server -n 50 --no-pager
	elif systemctl list-units --type=service 2>/dev/null | grep -q "^openvpn.service"; then
		journalctl -u openvpn -n 50 --no-pager
	else
		log_warn "Could not find OpenVPN service logs."
		echo ""
		log_info "You can also check:"
		echo "  • /var/log/syslog (Debian/Ubuntu)"
		echo "  • /var/log/messages (CentOS/RHEL)"
		echo "  • journalctl -u openvpn@server -f (follow logs)"
	fi
	echo ""
}

# Show usage/help
show_usage() {
	cat <<EOF
OpenVPN Server Manager - Complete management tool

Usage:
  $0 install              Install OpenVPN server (automatic setup)
  $0 add <username>       Add a new user/client
  $0 remove <username>    Revoke and remove a user
  $0 list                 List all users/clients
  $0 status               Show server status
  $0 info                 Show server configuration
  $0 restart              Restart OpenVPN service
  $0 logs                 View OpenVPN logs
  $0 uninstall            Uninstall OpenVPN server completely
  $0 help                 Show this help message

Examples:
  $0 install              # Install server with optimal settings
  $0 add john              # Add user 'john'
  $0 add alice             # Add user 'alice'
  $0 list                  # List all users
  $0 remove john           # Revoke and remove user 'john'
  $0 status                # Check server status
  $0 info                  # Show server configuration
  $0 restart               # Restart the service
  $0 logs                  # View recent logs
  $0 uninstall             # Remove OpenVPN server completely

The installation uses aggressive bypass mode by default:
  • Port 443 TCP (looks like HTTPS)
  • Advanced obfuscation for bypassing DPI
  • Optimized for countries with extensive blocking (Russia, China, etc.)

EOF
}

# Main script logic
case "${1:-}" in
	install)
		main_install
		;;
	add|user|client)
		add_client "${2:-}"
		;;
	remove|revoke|delete)
		remove_user "${2:-}"
		;;
	list|users|clients)
		list_users
		;;
	status)
		show_status
		;;
	info|config)
		show_info
		;;
	restart|reload)
		restart_service
		;;
	logs|log)
		view_logs
		;;
	uninstall)
		uninstall_server
		;;
	help|--help|-h)
		show_usage
		;;
	"")
		show_usage
		;;
	*)
		log_error "Unknown command: $1"
		echo ""
		show_usage
		exit 1
		;;
esac

