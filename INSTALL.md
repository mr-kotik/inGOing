# 📥 Installation Guide

## 📋 Table of Contents
- [System Requirements](#system-requirements)
- [Environment Setup](#environment-setup)
- [Server Installation](#server-installation)
- [Client Installation](#client-installation)
- [Advanced Features](#advanced-features)
- [Installation Verification](#installation-verification)
- [Troubleshooting](#troubleshooting)

## System Requirements

### Server
- Go 1.15 or higher
- OpenSSL for certificate generation
- Linux/Windows OS
- Minimum 512MB RAM
- 100MB free disk space

### Client
- Go 1.15 or higher
- Administrator rights (optional)
- 50MB free disk space

## Environment Setup

### 1. Installing Go
```bash
# Linux
wget https://golang.org/dl/go1.15.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.15.linux-amd64.tar.gz
echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.bashrc
source ~/.bashrc

# Windows
# Download installer from https://golang.org/dl/
# Run the installer and follow the instructions
```

### 2. Installing OpenSSL
```bash
# Linux
sudo apt-get update
sudo apt-get install openssl

# Windows
# Download installer from https://slproweb.com/products/Win32OpenSSL.html
# Run the installer and follow the instructions
```

## Server Installation

1. Clone the repository:
```bash
git clone https://github.com/mr-kotik/inGOing.git
cd inGOing
```

2. Generate TLS certificates:
```bash
# Create certificate and key
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes

# When prompted for information:
# - Common Name (CN): your server's domain name or IP
# - Other fields can be left empty
```

3. Configure settings:
- Open `mainserver.go`
- Modify the following constants:
  - `ServerPort` - port for connections
  - `SecretKey` - authentication key
  - Other parameters as needed

4. Build the server:
```bash
go build -o mainserver mainserver.go
```

5. Configure firewall:
```bash
# Linux
sudo ufw allow 443/tcp

# Windows
netsh advfirewall firewall add rule name="inGOing Server" dir=in action=allow protocol=TCP localport=443
```

## Client Installation

1. Configure settings:
- Open `backdoor.go`
- Modify the following parameters:
  - `ServerAddress` - your server's IP/domain
  - `ServerPort` - server port
  - `SecretKey` - authentication key (must match server's key)

2. Build the client:
```bash
# Regular version
go build -o backdoor backdoor.go

# Debug version
go build -o backdoor_debug backdoor_debug.go
```

## Advanced Features

### Exploit Compilation Requirements
If you plan to use privilege escalation features, additional tools are required:

#### Linux
- GCC and build essentials:
```bash
sudo apt-get install build-essential
```
- Required for:
  - Kernel exploit compilation
  - Local privilege escalation
  - System manipulation modules

#### Windows
- Visual Studio with C++ support
- Windows SDK
- Required for:
  - System-level exploits
  - Token manipulation
  - Service exploitation

Note: These tools are only needed if you plan to use advanced privilege escalation features.

## Installation Verification

### Server
1. Start the server:
```bash
./mainserver
```

2. Verify operation:
- Control menu should appear
- Check server status through "Server Status" option
- Ensure there are no errors in logs

### Client
1. Start the client:
```bash
./backdoor
```

2. Verify connection:
- New client should appear in server menu
- Test command sending capability
- Verify result reception

## Troubleshooting

### Connection Issues
1. Check firewall settings
2. Ensure ports are open
3. Verify IP/domain correctness
4. Check authentication key matching

### Build Errors
1. Ensure correct Go version is installed
2. Check all dependencies are present
3. Verify file permissions

### Certificate Errors
1. Check certificate generation process
2. Verify certificate file paths
3. Check certificate file permissions

### General Recommendations
- Check server and client logs
- Use debug version for diagnostics
- Ensure all components use same protocol version
- Update all components to latest version if needed 