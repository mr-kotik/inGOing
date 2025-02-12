<div align="center">

<h1 align="center">Pentest Remote Access & Control Toolkit</h1>

<pre>
██╗███╗   ██╗ ██████╗  ██████╗ ██╗███╗   ██╗ ██████╗ 
██║████╗  ██║██╔════╝ ██╔═══██╗██║████╗  ██║██╔════╝ 
██║██╔██╗ ██║██║  ███╗██║   ██║██║██╔██╗ ██║██║  ███╗
██║██║╚██╗██║██║   ██║██║   ██║██║██║╚██╗██║██║   ██║
██║██║ ╚████║╚██████╔╝╚██████╔╝██║██║ ╚████║╚██████╔╝
╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝ 
</pre>

![Go Version](https://img.shields.io/badge/Go-1.15%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)
![Stage](https://img.shields.io/badge/Stage-Research-red)

</div>

<div align="center">
<i>A powerful cross-platform remote administration tool written in Go for security research and system administration learning.</i>
</div>

---

## 📑 Table of Contents
- [⚠️ Legal Disclaimer](#️-legal-disclaimer)
- [🌟 Features](#-features)
- [🚀 Getting Started](#-getting-started)
- [📚 Documentation](#-documentation)
- [🔒 Security](#-security)
- [🏗️ Architecture](#️-architecture)
- [🛠️ Development](#️-development)
- [🤝 Contributing](#-contributing)
- [📝 License](#-license)
- [🔗 References](#-references)

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

**DISCLAIMER:**
- 🚫 The author bears ABSOLUTELY NO RESPONSIBILITY for any malicious use of this tool
- 🚫 The author is NOT LIABLE for any criminal activities or damage
- 🚫 The author DOES NOT ENDORSE any harmful or illegal activities
- 🚫 The author DISCLAIMS ALL LIABILITY for any consequences

**By using this tool/code, you agree to:**
1. ✅ Use it only for legal and ethical purposes
2. ✅ Take FULL responsibility for your actions
3. ✅ Comply with ALL applicable laws and regulations
4. ✅ Obtain proper authorization before testing any systems
5. ✅ Author of the repository does not participate in your actions

**USE ENTIRELY AT YOUR OWN RISK AND RESPONSIBILITY.**

## 🌟 Features

### Core Features
- 🔐 Secure TLS communication with multi-client support
- 🌐 Cross-platform support (Windows/Linux)
- 🔑 Advanced privilege management and escalation
- 🛡️ Comprehensive security features and anti-analysis protection
- 🔄 Self-update and recovery mechanisms
- 🐛 Debug mode for testing and development

### Advanced Features
- **Modular Architecture**: Flexible plugin system for extending functionality
- **Adaptive Behavior**: Automatically adapts to Windows/Linux environments
- **Stealth Capabilities**: 
  - Process masking
  - File hiding
  - Network traffic obfuscation
  - System log cleaning
- **Persistence Mechanisms**: Multiple methods to maintain system presence
- **Anti-Analysis Protection**:
  - VM/Sandbox detection
  - Debugger detection
  - Binary obfuscation
  - Memory protection
- **Active Defense**:
  - Antivirus detection and bypass
  - Self-protection measures
  - Polymorphic encryption

### Privilege Escalation Support
- Latest CVE implementations for Windows and Linux
- UAC bypass techniques
- Token manipulation
- Service exploitation

## 🚀 Getting Started

### Requirements
- Go 1.15+
- OpenSSL
- Admin rights (optional)

See [Installation Guide](INSTALL.md) for detailed setup instructions.

## 📚 Documentation
- [API Documentation](API.md)
- [Technical Details](TECHNICAL.md)
- [Security Guide](SECURITY.md)
- [Installation Guide](INSTALL.md)

## 🔒 Security

### Key Security Features
- TLS 1.2+ encryption
- Strong authentication
- Traffic obfuscation
- Anti-debugging measures
- Binary protection

See [Security Guide](SECURITY.md) for detailed security information.

## 🏗️ Architecture

### Core Components
- **Server**: Connection management, command processing, client monitoring
- **Backdoor**: System interaction, privilege management, stealth operations
- **Protocol**: Secure communication, data obfuscation, session management

See [Technical Details](TECHNICAL.md) for complete architecture documentation.

## 🛠️ Development

### Development Features
- Modular architecture for easy feature addition
- Debug mode for testing and development
- Comprehensive logging and monitoring
- Cross-platform compatibility

See [Contributing Guidelines](CONTRIBUTING.md) for development documentation.

## 🤝 Contributing
We welcome contributions! Please read our [Contributing Guidelines](CONTRIBUTING.md) before making any changes.

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
