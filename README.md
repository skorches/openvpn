# OpenVPN Installation Script

A one-time installation script for setting up an OpenVPN server on a VPS, optimized for bypassing network blocks and censorship.

**Repository**: [https://github.com/skorches/openvpn](https://github.com/skorches/openvpn)

## Features

- **One-time installation**: Simple, automated setup process
- **Multi-distribution support**: Works on Debian, Ubuntu, CentOS, Fedora, Arch Linux, and more
- **Bypass optimization**: Includes features to bypass DPI (Deep Packet Inspection) and network blocks:
  - `tls-crypt` encryption for control channel obfuscation
  - Modern cipher support (AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305)
  - Configurable protocols (UDP/TCP)
  - Buffer optimizations for better obfuscation
- **Security**: Strong encryption and authentication
- **Easy client management**: Simple command to generate client configurations

## Quick Start

### Installation

1. Download the script to your VPS:
```bash
wget https://raw.githubusercontent.com/skorches/openvpn/main/openvpn-install.sh
chmod +x openvpn-install.sh
```

2. Run the script (interactive menu):
```bash
sudo ./openvpn-install.sh
```

The script will show an interactive menu where you can:
- Install OpenVPN server (fully automatic)
- Add users
- List users
- Remove users
- View status and logs
- And much more!

**That's it!** Just run the script and follow the menu. Everything is automatic:
- Detects your server IP
- Uses optimal settings (Port 443 TCP, aggressive bypass mode)
- Configures everything automatically
- Starts the service

### Quick Start

1. **Install server**: Run the script and select option 1
2. **Add users**: After installation, select option 1 from the menu
3. **Manage**: Use the menu to list, remove, or manage users

The generated `.ovpn` files are in `/root/username/username.ovpn` - transfer them to your device and import into your OpenVPN client.

## Usage

### Interactive Mode (Recommended)

Simply run the script without any arguments:

```bash
sudo ./openvpn-install.sh
```

This will show an interactive menu with all available options:
- **Install OpenVPN Server** - One-click installation
- **Add New User** - Create client configurations
- **List All Users** - See all active clients
- **Remove User** - Revoke and remove a user
- **Show Server Status** - Check if server is running
- **Show Server Info** - View configuration details
- **Restart Service** - Restart OpenVPN
- **View Logs** - Check server logs
- **Validate Config** - Validate a .ovpn file
- **Uninstall Server** - Remove everything

**No commands to remember - just run the script and use the menu!**

### Command-Line Mode (Optional)

For automation or scripts, you can still use command-line arguments:

```bash
# Install server
sudo ./openvpn-install.sh install

# Add a user
sudo ./openvpn-install.sh add john

# List users
sudo ./openvpn-install.sh list

# Remove user
sudo ./openvpn-install.sh remove john

# Show status
sudo ./openvpn-install.sh status

# View logs
sudo ./openvpn-install.sh logs

# Uninstall
sudo ./openvpn-install.sh uninstall
```

### Examples

**Interactive mode:**
```bash
sudo ./openvpn-install.sh
# Then select options from the menu
```

**Command-line mode:**
```bash
# Quick install
sudo ./openvpn-install.sh install

# Add multiple users quickly
sudo ./openvpn-install.sh add john
sudo ./openvpn-install.sh add alice
sudo ./openvpn-install.sh add bob

# Check status
sudo ./openvpn-install.sh status
```

The installation is fully automatic with optimal defaults - just select from the menu!

## Configuration Options

During installation, you'll be prompted for:

- **Bypass Mode**: 
  - Standard (default OpenVPN settings)
  - **Aggressive** (recommended for Russia/China - uses port 443 TCP, advanced obfuscation)
- **Protocol**: UDP (faster) or TCP (more reliable, auto-selected in aggressive mode)
- **Port**: Default is 1194 (standard) or 443 (aggressive mode - looks like HTTPS)
- **DNS**: Choose from Cloudflare, Google, Quad9, OpenDNS, or custom
- **Cipher**: AES-256-GCM (recommended), AES-128-GCM, or CHACHA20-POLY1305
- **Compression**: Optional LZ4 compression (disabled in aggressive mode)

## Bypass Features

This script includes multiple methods to bypass network blocks, especially effective against extensive DPI systems (like in Russia, China, Iran):

### Standard Mode
- **tls-crypt**: Encrypts and authenticates all control channel packets, making it harder to identify OpenVPN traffic
- **Modern ciphers**: Uses AEAD ciphers (GCM mode) which are harder to detect
- **Buffer optimizations**: Helps with obfuscation
- **Flexible protocols**: Support for both UDP and TCP

### Aggressive Mode (Recommended for Russia/China)
All standard features PLUS:
- **Port 443 TCP**: Uses HTTPS port - traffic looks like normal HTTPS, extremely hard to block
- **MTU/Fragment tuning**: Smaller packets (1200 bytes) with fragmentation - harder to pattern-match
- **Advanced buffer optimization**: Enhanced packet obfuscation
- **Optimized for DPI evasion**: Specifically designed to bypass Deep Packet Inspection

**For countries with extensive blocking (Russia, China, etc.), always select "Aggressive" mode during installation.**

See [BYPASS_METHODS.md](BYPASS_METHODS.md) for detailed explanation of all bypass techniques.

## Client Setup

### Linux
```bash
sudo apt-get install openvpn  # Debian/Ubuntu
sudo yum install openvpn      # CentOS/RHEL
sudo openvpn --config client1.ovpn
```

### Windows
1. Download [OpenVPN GUI](https://openvpn.net/community-downloads/)
2. Install and import the `.ovpn` file
3. Connect

### macOS
1. Download [Tunnelblick](https://tunnelblick.net/)
2. Import the `.ovpn` file
3. Connect

### Android/iOS
1. Install [OpenVPN Connect](https://play.google.com/store/apps/details?id=net.openvpn.openvpn) (Android) or from App Store (iOS)
2. Import the `.ovpn` file
3. Connect

## Troubleshooting

### Service not starting
Check the service status:
```bash
systemctl status openvpn@server      # Debian/Ubuntu
systemctl status openvpn-server@server  # CentOS/Fedora/Arch
```

Check logs:
```bash
journalctl -u openvpn@server -f
```

### Firewall issues
Make sure the port is open:
```bash
# UFW
sudo ufw allow 1194/udp

# Firewalld
sudo firewall-cmd --permanent --add-port=1194/udp
sudo firewall-cmd --reload

# iptables
sudo iptables -I INPUT -p udp --dport 1194 -j ACCEPT
```

### Connection issues
- Verify the server IP address is correct
- Check that the port is not blocked by your ISP or firewall
- Try switching between UDP and TCP protocols
- Ensure certificates are correctly generated

## Security Notes

- Keep your server updated: `sudo apt update && sudo apt upgrade` (Debian/Ubuntu)
- Use strong passwords for server access
- Regularly rotate client certificates
- Consider using a non-standard port
- Monitor server logs for suspicious activity

## Uninstallation

To completely remove OpenVPN server and all configurations:

```bash
sudo ./openvpn-install.sh uninstall
```

This will:
- Stop and disable OpenVPN services
- Remove OpenVPN packages
- Remove all configuration files
- Remove client certificates and .ovpn files
- Clean up firewall rules
- Ask for confirmation before proceeding

**Note:** IP forwarding will remain enabled (in case other services need it). You can manually disable it with:
```bash
sysctl -w net.ipv4.ip_forward=0
```

## License

MIT License - feel free to use and modify as needed.

## Credits

Inspired by [angristan/openvpn-install](https://github.com/angristan/openvpn-install)

