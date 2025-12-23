# OpenVPN Installation Script

A one-time installation script for setting up an OpenVPN server on a VPS, optimized for bypassing network blocks and censorship.

**Repository**: [https://github.com/skorches/openvpn-install](https://github.com/skorches/openvpn-install)

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
wget https://raw.githubusercontent.com/skorches/openvpn-install/master/openvpn-install.sh
# Or upload the script to your server
```

2. Make it executable:
```bash
chmod +x openvpn-install.sh
```

3. Run the installation:
```bash
sudo ./openvpn-install.sh install
```

Or run interactively:
```bash
sudo ./openvpn-install.sh
```

### Adding Clients

After installation, create client configurations:

```bash
sudo ./openvpn-install.sh add-client client1
```

This will create a `.ovpn` file in `/root/client1/client1.ovpn` that you can transfer to your client device.

## Usage

### Interactive Mode
```bash
sudo ./openvpn-install.sh
```

This will show a menu with options to:
1. Install OpenVPN server
2. Add a new client
3. Exit

### Command Line Mode

**Install server:**
```bash
sudo ./openvpn-install.sh install
```

**Add client:**
```bash
sudo ./openvpn-install.sh add-client <client-name>
```

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

To remove OpenVPN:

```bash
# Stop and disable service
sudo systemctl stop openvpn@server
sudo systemctl disable openvpn@server

# Remove packages
sudo apt-get remove --purge openvpn  # Debian/Ubuntu
sudo yum remove openvpn              # CentOS/RHEL

# Remove configuration
sudo rm -rf /etc/openvpn
sudo rm -rf /root/*.ovpn
```

## License

MIT License - feel free to use and modify as needed.

## Credits

Inspired by [angristan/openvpn-install](https://github.com/angristan/openvpn-install)

