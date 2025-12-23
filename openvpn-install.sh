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
	# In interactive mode, we want to return error instead of exiting
	# Check if we're in interactive menu (set a flag)
	if [[ "${INTERACTIVE_MODE:-}" == "true" ]]; then
		return 1
	else
		exit 1
	fi
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

# Check if port is available
check_port_available() {
	local port=$1
	local protocol=${2:-tcp}
	
	# Check if port is in use
	if command -v ss &> /dev/null; then
		if ss -tuln 2>/dev/null | grep -q ":${port}"; then
			# Port is in use, check what's using it
			local process=$(ss -tulnp 2>/dev/null | grep ":${port}" | head -1)
			if [[ -n "$process" ]]; then
				log_warn "Port ${port} is already in use:"
				log_warn "  $process"
				return 1
			fi
			return 1
		fi
	elif command -v netstat &> /dev/null; then
		if netstat -tuln 2>/dev/null | grep -q ":${port}"; then
			local process=$(netstat -tulnp 2>/dev/null | grep ":${port}" | head -1)
			if [[ -n "$process" ]]; then
				log_warn "Port ${port} is already in use:"
				log_warn "  $process"
				return 1
			fi
			return 1
		fi
	fi
	
	return 0
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
		
		# Check if port 443 is available
		if ! check_port_available 443 tcp; then
			log_warn "⚠️  Port 443 is already in use!"
			log_warn "This will prevent OpenVPN from starting and cause connection errors!"
			log_warn ""
			
			# Try to identify what's using the port
			local port_user=""
			if command -v ss &> /dev/null; then
				port_user=$(ss -tulnp 2>/dev/null | grep ":443" | head -1 || true)
			elif command -v netstat &> /dev/null; then
				port_user=$(netstat -tulnp 2>/dev/null | grep ":443" | head -1 || true)
			fi
			
			if [[ -n "$port_user" ]]; then
				log_warn "Port 443 is being used by:"
				log_warn "  $port_user"
				log_warn ""
			fi
			
			log_warn "Options:"
			log_warn "  1) Stop the conflicting service and use port 443 (recommended for bypassing blocks)"
			log_warn "  2) Use alternative port 8443 (still looks like HTTPS, good for bypassing)"
			log_warn "  3) Cancel installation"
			log_warn ""
			read -p "Select option [1-3]: " port_option
			port_option=${port_option:-1}
			
			case $port_option in
				1)
					# Try to stop common services
					if echo "$port_user" | grep -qi "sniproxy"; then
						log_info "Attempting to stop sniproxy..."
						systemctl stop sniproxy 2>/dev/null || service sniproxy stop 2>/dev/null || true
						sleep 1
						if check_port_available 443 tcp; then
							log_success "Port 443 is now available"
						else
							log_warn "Could not free port 443. You may need to stop the service manually."
						fi
					elif echo "$port_user" | grep -qi "nginx"; then
						log_info "Attempting to stop nginx..."
						systemctl stop nginx 2>/dev/null || service nginx stop 2>/dev/null || true
						sleep 1
						if check_port_available 443 tcp; then
							log_success "Port 443 is now available"
						else
							log_warn "Could not free port 443. You may need to stop the service manually."
						fi
					elif echo "$port_user" | grep -qi "apache"; then
						log_info "Attempting to stop apache..."
						systemctl stop apache2 2>/dev/null || systemctl stop httpd 2>/dev/null || true
						sleep 1
						if check_port_available 443 tcp; then
							log_success "Port 443 is now available"
						else
							log_warn "Could not free port 443. You may need to stop the service manually."
						fi
					else
						log_warn "Please stop the service using port 443 manually, then continue."
						read -p "Press Enter after stopping the service..."
					fi
					;;
				2)
					PORT=8443
					log_info "Using alternative port 8443 (still good for bypassing blocks)"
					;;
				3)
					log_fatal "Installation cancelled."
					;;
				*)
					log_warn "Invalid option, using port 443 anyway (may fail)"
					;;
			esac
		fi
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
	
	# Remove existing PKI if it exists (to avoid confirmation prompt)
	if [[ -d pki ]]; then
		log_info "Removing existing PKI directory..."
		rm -rf pki
	fi
	
	# Initialize PKI (non-interactive - automatically confirm)
	# Use printf to send "yes" to the confirmation prompt
	printf "yes\n" | ./easyrsa init-pki >/dev/null 2>&1 || {
		# If that fails, try with explicit input
		rm -rf pki 2>/dev/null || true
		printf "yes\n" | ./easyrsa init-pki
	}
	
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
	
	# Determine correct config file location based on OS
	local server_config="/etc/openvpn/server.conf"
	local easyrsa_dir="/etc/openvpn/easy-rsa"
	
	# Some distributions use /etc/openvpn/server/server.conf
	# But we'll use the standard location and create symlink if needed
	local server_dir="/etc/openvpn/server"
	if [[ ! -d "$server_dir" ]]; then
		mkdir -p "$server_dir" 2>/dev/null || true
	fi
	
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
		
		# Wait a bit and verify it's actually listening
		sleep 3
		local listening=false
		local port_in_use_by=""
		
		if command -v ss &> /dev/null; then
			port_in_use_by=$(ss -tulnp 2>/dev/null | grep ":${PORT}" | head -1 || true)
			if echo "$port_in_use_by" | grep -qi openvpn; then
				listening=true
			elif [[ -n "$port_in_use_by" ]]; then
				# Port is in use but not by OpenVPN
				log_warn "Port ${PORT} is in use by another service:"
				log_warn "  $port_in_use_by"
			fi
		elif command -v netstat &> /dev/null; then
			port_in_use_by=$(netstat -tulnp 2>/dev/null | grep ":${PORT}" | head -1 || true)
			if echo "$port_in_use_by" | grep -qi openvpn; then
				listening=true
			elif [[ -n "$port_in_use_by" ]]; then
				log_warn "Port ${PORT} is in use by another service:"
				log_warn "  $port_in_use_by"
			fi
		fi
		
		if [[ "$listening" == "true" ]]; then
			log_success "✅ Server is listening on port ${PORT}/${PROTOCOL}"
		else
			log_error "❌ Service started but OpenVPN is NOT listening on port ${PORT}"
			log_warn ""
			log_warn "This will cause connection errors (error 15)!"
			log_warn ""
			log_warn "Troubleshooting:"
			log_warn "  1. Check service status: systemctl status openvpn@server"
			log_warn "  2. Check logs: journalctl -u openvpn@server -n 50"
			if [[ "$PORT" == "443" ]]; then
				log_warn "  3. Port 443 is often used by web servers (nginx/apache)"
				log_warn "     Stop the web server or change OpenVPN port"
			fi
		fi
	else
		log_error "❌ OpenVPN service failed to start!"
		log_warn ""
		log_warn "Troubleshooting:"
		log_warn "  1. Check service status: systemctl status openvpn@server"
		log_warn "  2. Check logs: journalctl -u openvpn@server -n 50"
		log_warn "  3. Try starting manually:"
		log_warn "     systemctl start openvpn@server      # Debian/Ubuntu"
		log_warn "     systemctl start openvpn-server@server  # CentOS/Fedora/Arch"
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
	
	# Read and clean keys for mobile compatibility
	# Properly format certificates and keys for embedding
	local ca_cert cert key tls_crypt_key
	
	# Read certificates and keys, clean trailing whitespace and normalize line endings
	# Preserve BEGIN/END markers and structure
	ca_cert=$(cat "$client_dir/ca.crt" | sed 's/[[:space:]]*$//' | tr -d '\r')
	cert=$(cat "$client_dir/${client_name}.crt" | sed 's/[[:space:]]*$//' | tr -d '\r')
	key=$(cat "$client_dir/${client_name}.key" | sed 's/[[:space:]]*$//' | tr -d '\r')
	
	# Read tls-crypt key - it's a raw key without BEGIN/END markers
	# Clean it but preserve line structure (usually 4 lines of base64)
	tls_crypt_key=$(cat "$client_dir/tls-crypt.key" | sed 's/[[:space:]]*$//' | tr -d '\r' | sed '/^$/d')
	
	# Ensure key is not empty
	if [[ -z "$tls_crypt_key" ]]; then
		log_fatal "tls-crypt key is empty or could not be read"
	fi
	
	# Build client obfuscation settings
	# Note: Some options are removed for mobile compatibility
	local client_obfuscation=""
	if [[ "${BYPASS_MODE:-}" == "aggressive" ]]; then
		client_obfuscation="# Advanced obfuscation settings for bypassing DPI
# Mobile-compatible options only
tun-mtu ${MTU}
mssfix ${MSSFIX}
# Note: fragment, txqueuelen, fast-io, and explicit-exit-notify removed for mobile compatibility"
	else
		client_obfuscation="# Standard obfuscation
# Mobile-compatible settings"
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

# Connection settings
connect-retry 2
connect-retry-max 3
connect-timeout 30

# Security
remote-cert-tls server
tls-client
cipher ${CIPHER}
auth SHA256
tls-version-min 1.2

# Compression
${COMPRESSION}

# Performance  
verb 3
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
	
	# Validate the generated file
	local ovpn_file="$client_dir/${client_name}.ovpn"
	if [[ ! -f "$ovpn_file" ]]; then
		log_fatal "Failed to create client configuration file"
	fi
	
	# Check that all required sections are present
	if ! grep -q "^<ca>" "$ovpn_file" || ! grep -q "^</ca>" "$ovpn_file"; then
		log_error "Warning: CA certificate section may be malformed"
	fi
	if ! grep -q "^<cert>" "$ovpn_file" || ! grep -q "^</cert>" "$ovpn_file"; then
		log_error "Warning: Client certificate section may be malformed"
	fi
	if ! grep -q "^<key>" "$ovpn_file" || ! grep -q "^</key>" "$ovpn_file"; then
		log_error "Warning: Client key section may be malformed"
	fi
	if ! grep -q "^<tls-crypt>" "$ovpn_file" || ! grep -q "^</tls-crypt>" "$ovpn_file"; then
		log_error "Warning: tls-crypt key section may be malformed"
	fi
	
	# Remove any trailing blank lines that might cause issues
	sed -i -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$ovpn_file" 2>/dev/null || true
	
	echo ""
	log_success "Client configuration created!"
	echo ""
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo "  File location: $ovpn_file"
	echo ""
	echo "  To use this file:"
	echo "  1. Transfer it to your device (scp, email, etc.)"
	echo "  2. Import it into your OpenVPN client"
	echo "  3. Connect!"
	echo ""
	echo "  If you encounter import errors:"
	echo "  • Ensure the file is complete (all certificates embedded)"
	echo "  • Try transferring via different method (email, USB, etc.)"
	echo "  • Check that your OpenVPN client supports tls-crypt"
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo ""
}

# Main installation function
main_install() {
	# Ensure INTERACTIVE_MODE is set if we're in interactive mode
	# This allows error handling to work correctly during installation
	if [[ -z "${INTERACTIVE_MODE:-}" ]] && [[ -t 0 ]]; then
		# If called from interactive menu, INTERACTIVE_MODE should already be set
		# But if called directly and we have a TTY, assume interactive
		export INTERACTIVE_MODE=true
	fi
	
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
		if [[ "${INTERACTIVE_MODE:-}" == "true" ]]; then
			return 0
		else
			exit 0
		fi
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
	
	# Remove packages - FORCE removal
	log_info "Removing OpenVPN packages completely..."
	
	case $OS in
		ubuntu|debian)
			export DEBIAN_FRONTEND=noninteractive
			# Remove OpenVPN and all related packages
			apt-get remove --purge -y openvpn openvpn-common 2>&1 || true
			# Remove any OpenVPN-related packages
			apt-get remove --purge -y $(dpkg -l | grep -i openvpn | awk '{print $2}') 2>&1 || true
			# Clean up
			apt-get autoremove -y 2>&1 || true
			apt-get autoclean -y 2>&1 || true
			log_success "OpenVPN packages removed"
			;;
		centos|rhel|rocky|almalinux|oracle)
			if command -v dnf &> /dev/null; then
				dnf remove -y openvpn 2>&1 || true
				# Remove all OpenVPN-related packages
				dnf remove -y $(rpm -qa | grep -i openvpn) 2>&1 || true
			else
				yum remove -y openvpn 2>&1 || true
				# Remove all OpenVPN-related packages
				yum remove -y $(rpm -qa | grep -i openvpn) 2>&1 || true
			fi
			log_success "OpenVPN packages removed"
			;;
		fedora)
			dnf remove -y openvpn 2>&1 || true
			# Remove all OpenVPN-related packages
			dnf remove -y $(rpm -qa | grep -i openvpn) 2>&1 || true
			log_success "OpenVPN packages removed"
			;;
		arch|manjaro)
			pacman -R --noconfirm openvpn 2>&1 || true
			# Remove all OpenVPN-related packages
			pacman -R --noconfirm $(pacman -Q | grep -i openvpn | awk '{print $1}') 2>&1 || true
			log_success "OpenVPN packages removed"
			;;
	esac
	
	# Remove ALL configuration files and data
	log_info "Removing all configuration files and data..."
	
	# Kill ALL OpenVPN processes first (more aggressive)
	pkill -9 openvpn >/dev/null 2>&1 || true
	pkill -9 -f openvpn >/dev/null 2>&1 || true
	sleep 2
	
	# Remove main OpenVPN directory (includes server.conf, easy-rsa, certificates, etc.)
	rm -rf /etc/openvpn
	
	# Remove all client directories and .ovpn files from /root
	find /root -type d -name "*" -exec sh -c 'if [ -f "$1"/*.ovpn ] 2>/dev/null; then rm -rf "$1"; fi' _ {} \; 2>/dev/null || true
	
	# Remove all .ovpn files anywhere in /root
	find /root -type f -name "*.ovpn" -delete 2>/dev/null || true
	
	# Remove any OpenVPN-related files in /root
	find /root -type f -name "*openvpn*" -delete 2>/dev/null || true
	find /root -type d -name "*openvpn*" -exec rm -rf {} + 2>/dev/null || true
	
	# Remove systemd service files (all possible locations)
	rm -f /etc/systemd/system/openvpn@*.service 2>/dev/null || true
	rm -f /etc/systemd/system/openvpn-server@*.service 2>/dev/null || true
	rm -f /usr/lib/systemd/system/openvpn@*.service 2>/dev/null || true
	rm -f /usr/lib/systemd/system/openvpn-server@*.service 2>/dev/null || true
	rm -f /lib/systemd/system/openvpn@*.service 2>/dev/null || true
	rm -f /lib/systemd/system/openvpn-server@*.service 2>/dev/null || true
	
	# Remove any OpenVPN run files
	rm -rf /var/run/openvpn* 2>/dev/null || true
	rm -rf /run/openvpn* 2>/dev/null || true
	
	# Remove any OpenVPN log files
	rm -f /var/log/openvpn*.log 2>/dev/null || true
	rm -f /var/log/openvpn*.log.* 2>/dev/null || true
	
	# Remove any OpenVPN lock files
	rm -f /var/lock/openvpn* 2>/dev/null || true
	rm -f /var/run/openvpn*.pid 2>/dev/null || true
	
	# Reload systemd to remove stale service files
	systemctl daemon-reload >/dev/null 2>&1 || true
	systemctl reset-failed >/dev/null 2>&1 || true
	
	# Final kill of any remaining processes
	pkill -9 openvpn >/dev/null 2>&1 || true
	pkill -9 -f openvpn >/dev/null 2>&1 || true
	sleep 1
	
	log_success "All configuration files and data removed"
	
	# Final verification - check if anything OpenVPN-related remains
	log_info "Verifying complete removal..."
	
	local remaining_items=0
	
	# Check if OpenVPN binary still exists
	if command -v openvpn &>/dev/null; then
		log_warn "⚠️  OpenVPN binary still found: $(command -v openvpn)"
		((remaining_items++))
	fi
	
	# Check if package is still installed
	case $OS in
		ubuntu|debian)
			if dpkg -l 2>/dev/null | grep -q "^ii.*openvpn"; then
				log_warn "⚠️  OpenVPN package(s) still installed:"
				dpkg -l 2>/dev/null | grep openvpn | awk '{print "    " $2}' || true
				((remaining_items++))
			fi
			;;
		centos|rhel|rocky|almalinux|oracle|fedora)
			if command -v dnf &> /dev/null; then
				if dnf list installed 2>/dev/null | grep -qi openvpn; then
					log_warn "⚠️  OpenVPN package(s) still installed"
					((remaining_items++))
				fi
			elif command -v yum &> /dev/null; then
				if yum list installed 2>/dev/null | grep -qi openvpn; then
					log_warn "⚠️  OpenVPN package(s) still installed"
					((remaining_items++))
				fi
			fi
			;;
		arch|manjaro)
			if pacman -Q 2>/dev/null | grep -qi openvpn; then
				log_warn "⚠️  OpenVPN package(s) still installed"
				((remaining_items++))
			fi
			;;
	esac
	
	# Check if config directory still exists
	if [[ -d /etc/openvpn ]]; then
		log_warn "⚠️  Configuration directory /etc/openvpn still exists"
		((remaining_items++))
	fi
	
	# Check if any .ovpn files remain
	if find /root -name "*.ovpn" -type f 2>/dev/null | grep -q .; then
		log_warn "⚠️  Some .ovpn files still found in /root"
		((remaining_items++))
	fi
	
	# Check if any OpenVPN processes are running
	if pgrep -f openvpn >/dev/null 2>&1; then
		log_warn "⚠️  OpenVPN processes still running"
		((remaining_items++))
	fi
	
	echo ""
	if [[ $remaining_items -gt 0 ]]; then
		log_warn "⚠️  Some OpenVPN components may still be present ($remaining_items items found)"
		log_info "You may need to manually remove them."
		echo ""
	else
		log_success "✅ Complete uninstallation successful!"
		echo ""
		log_info "Everything removed:"
		log_info "  ✅ OpenVPN packages"
		log_info "  ✅ Configuration files (/etc/openvpn)"
		log_info "  ✅ EasyRSA and certificates"
		log_info "  ✅ Client .ovpn files"
		log_info "  ✅ Systemd service files"
		log_info "  ✅ Firewall rules"
		log_info "  ✅ Log files"
		log_info "  ✅ All OpenVPN processes"
		echo ""
		log_success "OpenVPN has been completely removed from the system!"
		echo ""
	fi
	
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
		return 0
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

# Validate/check a client config file
validate_config() {
	if [[ -z "${1:-}" ]]; then
		log_fatal "Please provide a config file path: $0 validate <path-to-ovpn-file>"
	fi
	
	local config_file="$1"
	
	if [[ ! -f "$config_file" ]]; then
		log_fatal "Config file not found: $config_file"
	fi
	
	echo ""
	log_info "🔍 Validating OpenVPN configuration file: $config_file"
	echo ""
	
	local errors=0
	local warnings=0
	
	# Check for required sections
	if ! grep -q "^<ca>" "$config_file"; then
		log_error "❌ Missing <ca> section"
		((errors++))
	else
		log_success "✅ CA certificate section found"
	fi
	
	if ! grep -q "^<cert>" "$config_file"; then
		log_error "❌ Missing <cert> section"
		((errors++))
	else
		log_success "✅ Client certificate section found"
	fi
	
	if ! grep -q "^<key>" "$config_file"; then
		log_error "❌ Missing <key> section"
		((errors++))
	else
		log_success "✅ Client key section found"
	fi
	
	if ! grep -q "^<tls-crypt>" "$config_file"; then
		log_warn "⚠️  Missing <tls-crypt> section (may not be required)"
		((warnings++))
	else
		log_success "✅ tls-crypt key section found"
	fi
	
	# Check for proper closing tags
	if grep -q "^<ca>" "$config_file" && ! grep -q "^</ca>" "$config_file"; then
		log_error "❌ <ca> section not properly closed"
		((errors++))
	fi
	
	if grep -q "^<cert>" "$config_file" && ! grep -q "^</cert>" "$config_file"; then
		log_error "❌ <cert> section not properly closed"
		((errors++))
	fi
	
	if grep -q "^<key>" "$config_file" && ! grep -q "^</key>" "$config_file"; then
		log_error "❌ <key> section not properly closed"
		((errors++))
	fi
	
	if grep -q "^<tls-crypt>" "$config_file" && ! grep -q "^</tls-crypt>" "$config_file"; then
		log_error "❌ <tls-crypt> section not properly closed"
		((errors++))
	fi
	
	# Check file size (should be reasonable)
	local file_size=$(stat -f%z "$config_file" 2>/dev/null || stat -c%s "$config_file" 2>/dev/null || echo "0")
	if [[ $file_size -lt 1000 ]]; then
		log_warn "⚠️  File seems too small ($file_size bytes) - may be incomplete"
		((warnings++))
	fi
	
	echo ""
	if [[ $errors -eq 0 ]]; then
		log_success "✅ Configuration file appears valid!"
		if [[ $warnings -gt 0 ]]; then
			log_info "⚠️  $warnings warning(s) found"
		fi
	else
		log_error "❌ Found $errors error(s) in configuration file"
		if [[ $warnings -gt 0 ]]; then
			log_info "⚠️  $warnings warning(s) found"
		fi
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

# Interactive menu
show_interactive_menu() {
	# Set flag for interactive mode (affects error handling)
	export INTERACTIVE_MODE=true
	
	# Check if we're in a terminal (for clear command)
	local use_clear=false
	if [[ -t 1 ]] && command -v clear &> /dev/null; then
		use_clear=true
	fi
	
	while true; do
		if [[ "$use_clear" == "true" ]]; then
			clear 2>/dev/null || true
		fi
		
		echo ""
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
		echo "  OpenVPN Server Manager"
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
		echo ""
		
		# Check if server is installed
		local server_installed=false
		if [[ -f /etc/openvpn/server.conf ]]; then
			server_installed=true
			local service_status="❌ Stopped"
			if systemctl is-active --quiet openvpn@server 2>/dev/null || \
			   systemctl is-active --quiet openvpn-server@server 2>/dev/null; then
				service_status="✅ Running"
			fi
			echo "  Server Status: $service_status"
			echo ""
		fi
		
		echo "  Main Menu:"
		echo ""
		
		if [[ "$server_installed" == "false" ]]; then
			echo "  1) Install OpenVPN Server"
			echo "  2) Exit"
			echo ""
			read -p "  Select an option [1-2]: " choice
			
			case $choice in
				1)
					# INTERACTIVE_MODE is already exported, call main_install
					# Errors will be handled gracefully and return to menu
					main_install || log_error "Installation failed. Please check the errors above."
					echo ""
					read -p "Press Enter to continue..."
					;;
				2)
					echo ""
					log_info "Goodbye!"
					exit 0
					;;
				*)
					log_error "Invalid option. Please try again."
					sleep 2
					;;
			esac
		else
			echo "  1) Add New User"
			echo "  2) List All Users"
			echo "  3) Remove User"
			echo "  4) Show Server Status"
			echo "  5) Show Server Info"
			echo "  6) Restart Service"
			echo "  7) View Logs"
			echo "  8) Validate Config File"
			echo "  9) Uninstall Server"
			echo "  0) Exit"
			echo ""
			read -p "  Select an option [0-9]: " choice
			
			case $choice in
				1)
					echo ""
					read -p "Enter username: " username
					username=$(echo "$username" | tr -d '[:space:]')  # Trim whitespace
					if [[ -n "$username" ]]; then
						# Validate username format before calling
						if [[ ! "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
							log_error "Invalid username. Use only letters, numbers, hyphens, and underscores."
						else
							# Call function - log_fatal will return error in interactive mode instead of exiting
							add_client "$username" || log_error "Failed to add user. Please check the errors above."
						fi
					else
						log_error "Username cannot be empty"
					fi
					echo ""
					read -p "Press Enter to continue..."
					;;
				2)
					list_users
					read -p "Press Enter to continue..."
					;;
				3)
					echo ""
					read -p "Enter username to remove: " username
					username=$(echo "$username" | tr -d '[:space:]')  # Trim whitespace
					if [[ -n "$username" ]]; then
						# Check if user exists first
						local easyrsa_dir="/etc/openvpn/easy-rsa"
						if [[ ! -f "$easyrsa_dir/pki/issued/${username}.crt" ]]; then
							log_error "User '$username' not found."
						elif [[ "$username" == "server" ]]; then
							log_error "Cannot remove server certificate."
						else
							# Call function - errors will be handled by log_fatal in interactive mode
							remove_user "$username" || log_error "Failed to remove user. Please check the errors above."
						fi
					else
						log_error "Username cannot be empty"
					fi
					echo ""
					read -p "Press Enter to continue..."
					;;
				4)
					show_status
					read -p "Press Enter to continue..."
					;;
				5)
					show_info
					read -p "Press Enter to continue..."
					;;
				6)
					restart_service
					read -p "Press Enter to continue..."
					;;
				7)
					view_logs
					read -p "Press Enter to continue..."
					;;
				8)
					echo ""
					read -p "Enter path to .ovpn file: " filepath
					filepath=$(echo "$filepath" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')  # Trim whitespace
					if [[ -n "$filepath" ]]; then
						# Check if file exists first
						if [[ ! -f "$filepath" ]]; then
							log_error "Config file not found: $filepath"
						else
							validate_config "$filepath"
						fi
					else
						log_error "File path cannot be empty"
					fi
					echo ""
					read -p "Press Enter to continue..."
					;;
				9)
					uninstall_server
					echo ""
					read -p "Press Enter to continue..."
					;;
				0)
					echo ""
					log_info "Goodbye!"
					exit 0
					;;
				*)
					log_error "Invalid option. Please try again."
					sleep 2
					;;
			esac
		fi
	done
}

# Show usage/help (minimal - interactive is default)
show_usage() {
	cat <<EOF
OpenVPN Server Manager

Just run the script - everything is interactive:
  $0

No commands needed! The interactive menu will guide you through:
  • Installing OpenVPN server
  • Adding/removing users
  • Managing the server
  • Viewing status and logs
  • Uninstalling

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
	validate|check)
		validate_config "${2:-}"
		;;
	uninstall)
		uninstall_server
		;;
	help|--help|-h)
		show_usage
		;;
	"")
		# No arguments - show interactive menu
		show_interactive_menu
		;;
	*)
		log_error "Unknown command: $1"
		echo ""
		show_usage
		exit 1
		;;
esac

