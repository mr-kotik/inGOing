# inGOing - Advanced Remote Administration Tool

<div align="center">

![Go Version](https://img.shields.io/badge/Go-1.15%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)
![Stage](https://img.shields.io/badge/Stage-Research-red)

</div>

<div align="center">
<i>A powerful cross-platform remote administration tool written in Go for security research and system administration learning.</i>
</div>

---

## ⚠️ Legal Disclaimer

This tool is intended SOLELY for:
- 📚 Educational purposes
- 🔬 Security research
- 🛡️ Testing and improving security of your OWN systems
- 📖 Learning about system administration and security concepts

**PROHIBITED USE:**
1. ❌ Any unauthorized access to computer systems
2. ❌ Any malicious or harmful activities
3. ❌ Any illegal activities under local, state, or federal laws
4. ❌ Any activities violating individual privacy or security

**The author:**
- 🚫 Assumes NO responsibility for any misuse of this tool
- ⚠️ Makes NO warranties about the safety or effectiveness of this tool
- 🛑 Is NOT liable for any damages resulting from the use of this tool
- ⛔ Does NOT endorse any malicious or illegal activities

**By using this tool, you agree to:**
1. ✅ Use it only for legal and ethical purposes
2. ✅ Take full responsibility for your actions
3. ✅ Comply with all applicable laws and regulations
4. ✅ Obtain proper authorization before testing any systems

**USE AT YOUR OWN RISK.**

---

## 🌟 Features

### 🖥️ Server Features
- 🔐 Secure TLS communication
- 👥 Multi-client support
- 📊 Real-time monitoring
- 📡 Command broadcasting
- 🔌 Module loading system
- 🔄 Automatic updates
- ✅ Connection validation
- 💾 Session persistence

### 🔧 Backdoor Features
- 🌐 Cross-platform support (Windows/Linux)
- 🔑 Privilege escalation capabilities
- 🛡️ Anti-analysis protection
- 🎭 Process masking
- 🌫️ Network traffic masking
- 🔄 Self-update mechanism
- 🔁 Self-recovery capabilities
- 🔒 Automatic persistence
- 🧹 Log cleaning

### Security Features
- TLS 1.2+ encryption
- Strong cipher suites
- Certificate validation
- Connection filtering
- Data obfuscation
- Anti-debugging measures
- VM detection
- Binary protection

### Privilege Escalation
The system includes multiple privilege escalation methods:

#### Linux
- CVE-2021-4034 (PwnKit)
- CVE-2022-0847 (Dirty Pipe)
- CVE-2022-2588 (nft_object UAF)
- CVE-2023-0179 (netfilter)
- CVE-2023-32233 (GameNetworkingSockets UAF)
- CVE-2023-35001 (FUSE UAF)
- CVE-2023-4911 (Looney Tunables)
- CVE-2023-3269 (netfilter)

#### Windows
- PrintNightmare
- HiveNightmare
- CVE-2023-21768 (CLFS Driver)
- CVE-2023-36802 (WER)
- CVE-2023-28252 (Win32k)
- CVE-2023-24932 (CLFS)
- CVE-2023-29360 (WinSock)
- CVE-2023-36884 (Office Click-to-Run)
- CVE-2023-38146 (PPTP)

## 🛠️ Requirements

### Server
- Go 1.15+
- OpenSSL for certificate generation
- Linux/Windows OS

### Backdoor
- Go 1.15+
- GCC (Linux) or MSVC (Windows) for exploit compilation
- Admin rights for installation (optional)

## 📥 Installation

1. Clone the repository:
```bash
git clone https://github.com/mr-kotik/inGOing.git
cd inGOing
```

2. Generate TLS certificates:
```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
```

3. Build the server:
```bash
go build -o mainserver mainserver.go
```

4. Build the backdoor:
```bash
go build -o backdoor backdoor.go
```

## 📚 Documentation

- [API Documentation](API.md)
- [Technical Details](TECHNICAL.md)
- [Security Considerations](SECURITY.md)

## 🤝 Contributing

We welcome contributions for research and educational purposes! Please read our [Contributing Guidelines](CONTRIBUTING.md) before making any changes.

Key points:
- Follow the code style guidelines
- Add tests for new features
- Update documentation
- Ensure cross-platform compatibility
- Adhere to security best practices

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed information.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 References

- [Go Documentation](https://golang.org/doc/)
- [TLS Security](https://en.wikipedia.org/wiki/Transport_Layer_Security)
- [System Administration](https://en.wikipedia.org/wiki/System_administrator)

---

<div align="center">
Made with ❤️ for educational purposes only
</div>

## Usage

### Server
1. Start the server:
```bash
./mainserver
```

2. Use the interactive menu to:
- List active backdoors
- Send commands
- Load modules
- Update backdoors
- View backdoor information
- Broadcast commands

### Backdoor
1. Configure the backdoor:
- Set WizardServerIP to your server's IP/domain
- Adjust other constants as needed

2. Deploy the backdoor:
```bash
./backdoor
```

The backdoor will:
- Attempt to gain elevated privileges
- Establish persistence
- Connect to the server
- Execute received commands

## Security Considerations

- Generate strong TLS certificates
- Change default SecretKey
- Use proper firewall rules
- Monitor for suspicious connections
- Regularly update exploits
- Use secure deployment methods

## Architecture

### Server Components
- TLS Server
- Connection Handler
- Command Processor
- Update Manager
- Module Loader
- Monitor System

### Backdoor Components
- Connection Manager
- Privilege Handler
- Anti-Analysis System
- Exploit Manager
- Recovery System
- Persistence Manager

## Network Protocol

1. Initial Connection:
   - TLS Handshake
   - Authentication
   - System Information Exchange

2. Command Protocol:
   - Obfuscated Commands
   - Result Reporting
   - Heartbeat System

3. Update Protocol:
   - Version Check
   - Binary Verification
   - Atomic Updates

## Development

### Adding New Exploits
1. Create exploit structure
2. Implement Check() function
3. Implement Run() function
4. Add to appropriate array

### Adding New Features
1. Update protocol if needed
2. Maintain backward compatibility
3. Update documentation
4. Test thoroughly

USE AT YOUR OWN RISK. 