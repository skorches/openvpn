# OpenVPN Bypass Methods Explained

This document explains all the methods used in this script to bypass network blocks, especially for countries with extensive DPI (Deep Packet Inspection) like Russia.

## Current Bypass Methods

### 1. **tls-crypt Encryption** ⭐⭐⭐⭐⭐
**Effectiveness: Very High**

- **What it does**: Encrypts and authenticates ALL control channel packets before TLS handshake
- **Why it works**: Makes OpenVPN traffic look like random encrypted data, not recognizable OpenVPN patterns
- **Russian DPI**: Very effective - hides the OpenVPN handshake signature that DPI systems look for

```
tls-crypt pki/tls-crypt.key
```

### 2. **Port 443 TCP (Aggressive Mode)** ⭐⭐⭐⭐⭐
**Effectiveness: Very High**

- **What it does**: Uses HTTPS port (443) with TCP protocol
- **Why it works**: Port 443 traffic is rarely blocked as it's used for legitimate HTTPS websites
- **Russian DPI**: Extremely effective - traffic blends in with normal HTTPS traffic
- **Note**: This is automatically enabled in "Aggressive" bypass mode

### 3. **Modern AEAD Ciphers** ⭐⭐⭐⭐
**Effectiveness: High**

- **What it does**: Uses AES-256-GCM, AES-128-GCM, or CHACHA20-POLY1305
- **Why it works**: These ciphers don't have recognizable patterns that older ciphers had
- **Russian DPI**: Effective - harder to fingerprint than CBC mode ciphers

### 4. **MTU/Fragment Tuning (Aggressive Mode)** ⭐⭐⭐⭐
**Effectiveness: High**

- **What it does**: Reduces packet size to 1200 bytes and enables fragmentation
- **Why it works**: Smaller, fragmented packets are harder to analyze and pattern-match
- **Russian DPI**: Effective - breaks up traffic patterns that DPI systems analyze

```
tun-mtu 1200
fragment 1200
mssfix 1200
```

### 5. **Buffer Optimizations** ⭐⭐⭐
**Effectiveness: Medium-High**

- **What it does**: Adjusts send/receive buffers to reduce packet patterns
- **Why it works**: Helps prevent traffic analysis based on packet timing and sizes
- **Russian DPI**: Moderately effective - reduces fingerprinting opportunities

### 6. **TCP Protocol (Aggressive Mode)** ⭐⭐⭐⭐
**Effectiveness: High**

- **What it does**: Uses TCP instead of UDP
- **Why it works**: TCP traffic on port 443 looks exactly like HTTPS
- **Russian DPI**: Very effective - most DPI systems don't deep-inspect HTTPS traffic

### 7. **Reduced Logging (Aggressive Mode)** ⭐⭐
**Effectiveness: Low (Security)**

- **What it does**: Reduces verbosity to minimize log exposure
- **Why it works**: Less information leakage if server is compromised
- **Russian DPI**: Not directly related to bypassing, but improves security

## Bypass Mode Comparison

### Standard Mode
- Uses default OpenVPN port (1194)
- UDP or TCP (user choice)
- Basic obfuscation (tls-crypt, modern ciphers)
- **Best for**: Countries with light/moderate blocking

### Aggressive Mode (Recommended for Russia)
- **Port 443 TCP** (looks like HTTPS)
- **Smaller MTU** (1200 bytes)
- **Fragmentation enabled**
- **Advanced buffer tuning**
- **All standard obfuscation methods**
- **Best for**: Russia, China, Iran, and other countries with extensive DPI

## Why These Methods Work Against Russian DPI

Russian DPI systems (like SORM) typically:

1. **Pattern Matching**: Look for OpenVPN handshake signatures
   - **Solution**: `tls-crypt` encrypts handshake, hiding signatures

2. **Port Blocking**: Block known VPN ports (1194, 1723, etc.)
   - **Solution**: Port 443 looks like legitimate HTTPS

3. **Traffic Analysis**: Analyze packet sizes, timing, and patterns
   - **Solution**: MTU tuning, fragmentation, buffer optimization break patterns

4. **Protocol Detection**: Detect OpenVPN protocol characteristics
   - **Solution**: TCP on 443 + tls-crypt makes it indistinguishable from HTTPS

5. **Deep Inspection**: Analyze packet contents for VPN signatures
   - **Solution**: Modern AEAD ciphers + encryption make content unreadable

## Additional Recommendations for Russia

### 1. Use Aggressive Mode
Always select "Aggressive" mode during installation for maximum effectiveness.

### 2. VPS Location
- Choose VPS in countries with good connectivity to Russia
- Consider: Finland, Germany, Netherlands, or other EU countries
- Avoid: VPS in countries that Russia has poor relations with (may be slower)

### 3. DNS Settings
- Use Cloudflare (1.1.1.1) or Google (8.8.8.8) DNS
- These are less likely to be blocked than Russian DNS servers

### 4. Connection Tips
- If connection fails, try reconnecting (some blocks are temporary)
- Use TCP protocol (automatically selected in aggressive mode)
- Consider using during off-peak hours if blocks are time-based

### 5. Alternative: Shadowsocks/V2Ray
If OpenVPN still gets blocked, consider:
- **Shadowsocks**: Very effective against Chinese/Russian DPI
- **V2Ray/Xray**: Advanced obfuscation, multiple protocols
- **WireGuard with obfuscation**: Newer, faster, but less tested

## Technical Details

### How tls-crypt Works
```
Normal OpenVPN:
Client → [Unencrypted handshake] → Server (DPI can see this!)

With tls-crypt:
Client → [Encrypted handshake with pre-shared key] → Server (DPI sees random data!)
```

### Why Port 443 is Effective
- Port 443 is used by millions of websites for HTTPS
- Blocking it would break most of the internet
- DPI systems rarely deep-inspect HTTPS traffic (it's encrypted anyway)
- Your OpenVPN traffic looks identical to normal HTTPS

### MTU and Fragmentation
- Normal MTU: 1500 bytes (easy to analyze)
- Reduced MTU: 1200 bytes (harder to pattern-match)
- Fragmentation: Breaks large packets into smaller ones
- Result: Traffic patterns are less recognizable

## Limitations

1. **Not 100% Guaranteed**: Advanced DPI systems may still detect VPN traffic
2. **Performance**: Aggressive mode may slightly reduce speed (worth it for bypassing)
3. **Server IP**: If your VPS IP is blacklisted, you may need a new server
4. **Time-based Blocks**: Some ISPs block VPNs during certain hours

## Testing Your Setup

After installation, test from Russia:

1. **Basic Test**: Try connecting - if it works, great!
2. **Speed Test**: Check if speed is acceptable
3. **Stability Test**: Leave connected for several hours
4. **DNS Leak Test**: Visit https://dnsleaktest.com to verify DNS routing

## Troubleshooting

### Connection Fails Immediately
- Check if port 443 is open: `telnet your-server-ip 443`
- Verify firewall rules on server
- Try different DNS (Cloudflare vs Google)

### Connection Works But Drops Frequently
- This may indicate DPI interference
- Try reducing MTU further (1000 instead of 1200)
- Consider using a different VPS provider/IP

### Very Slow Connection
- Normal in aggressive mode (encryption overhead)
- Try different cipher (AES-128-GCM is faster than AES-256-GCM)
- Check VPS server performance

## Security Note

While these methods help bypass blocks, they also improve security:
- `tls-crypt` prevents man-in-the-middle attacks
- Modern ciphers are more secure
- Port 443 reduces visibility to attackers

Your VPN is both more private AND more secure with these settings!



