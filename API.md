# API Documentation

## Legal Disclaimer

This API documentation is provided SOLELY for:
- Educational and research purposes only
- Understanding system security concepts
- Learning about API implementation
- Testing security of authorized systems

**PROHIBITED USE:**
1. ❌ Any unauthorized access to computer systems
2. ❌ Any malicious or harmful activities
3. ❌ Any illegal activities under local, state, or federal laws
4. ❌ Any activities violating individual privacy or security

**DISCLAIMER:**
- 🚫 The author bears ABSOLUTELY NO RESPONSIBILITY for any malicious use
- 🚫 The author is NOT LIABLE for any criminal activities or damage
- 🚫 The author DOES NOT ENDORSE any harmful or illegal activities
- 🚫 The author DISCLAIMS ALL LIABILITY for any consequences

**USE ENTIRELY AT YOUR OWN RISK AND RESPONSIBILITY.**

## Network Protocol

### Authentication

Initial connection requires authentication using a pre-shared secret key.

```
-> [Base64(SecretKey)]\n
<- [Base64(Result)]\n
```

### System Information

After successful authentication, the client sends system information.

Format:
```
-> [Base64("privileges|os|arch|isAdmin|version|canElevate|hasUAC")]\n
```

Example:
```
-> [Base64("user|windows|amd64|true|1.0.0|true|true")]\n
```

### Commands

#### Standard Command
```
-> [Base64(command)]\n
<- [Base64(result)]\n
```

#### Update Check
```
-> [Base64("check_update:current_version")]\n
<- [Base64("new_version:checksum:url")] or [Base64("no_update")]\n
```

#### Get Checksum
```
-> [Base64("get_checksum")]\n
<- [Base64(checksum)]\n
```

#### Get Binary
```
-> [Base64("get_binary")]\n
<- [Base64(url)]\n
```

#### Heartbeat
```
-> [Base64("heartbeat")]\n
<- [Base64("ok")]\n
```

## Command Reference

### System Commands
- `sysinfo` - Get detailed system information
- `whoami` - Get current user information
- `hostname` - Get system hostname
- `ps` - List running processes
- `netstat` - Network connections
- `ifconfig/ipconfig` - Network interfaces

### File Operations
- `ls [path]` - List directory contents
- `cd [path]` - Change directory
- `pwd` - Print working directory
- `cat [file]` - View file contents
- `rm [file]` - Remove file
- `mkdir [dir]` - Create directory
- `rmdir [dir]` - Remove directory
- `cp [src] [dst]` - Copy file
- `mv [src] [dst]` - Move file
- `chmod [mode] [file]` - Change file permissions (Linux)
- `attrib [attributes] [file]` - Change file attributes (Windows)

### Process Management
- `kill [pid]` - Terminate process
- `start [program]` - Start program
- `tasklist` - List processes (Windows)
- `taskkill [pid]` - Kill process (Windows)
- `service [action] [name]` - Manage services

### Network Operations
- `download [url] [path]` - Download file
- `upload [path]` - Upload file
- `portfwd add [port]` - Add port forward
- `portfwd remove [port]` - Remove port forward
- `proxy [on/off]` - Toggle SOCKS proxy

### Privilege Operations
- `getsystem` - Attempt privilege escalation
- `getprivs` - List current privileges
- `runas [user] [cmd]` - Run as different user
- `sudo [cmd]` - Run with elevated privileges (Linux)
- `uac bypass` - Attempt UAC bypass (Windows)

### Persistence
- `persist [method]` - Install persistence
- `unpersist [method]` - Remove persistence
- `persist list` - List persistence methods
- `persist status` - Check persistence status

### Anti-Analysis
- `checkvm` - Check for VM
- `checksandbox` - Check for sandbox
- `checkav` - List security products
- `hide` - Enable stealth mode
- `unhide` - Disable stealth mode

### Module Management
- `load [module]` - Load module
- `unload [module]` - Unload module
- `modules` - List available modules
- `reload` - Reload all modules

### Session Management
- `background` - Background session
- `foreground` - Foreground session
- `exit` - Terminate session
- `sleep [seconds]` - Set sleep time
- `connect [address]` - Connect to new server

### Logging
- `clearev` - Clear event logs
- `keyscan_start` - Start keylogger
- `keyscan_stop` - Stop keylogger
- `keyscan_dump` - Dump keylog data
- `screenshot` - Take screenshot

### Compiler Management Commands
- `check_compiler` - Check if compiler is available
- `install_compiler` - Install required compiler (MinGW for Windows, build-essential for Linux)
- `compile [source]` - Compile provided source code
- `remove_compiler` - Remove installed compiler

### Compilation Response Format
```json
{
    "status": "success|error",
    "message": "string",
    "output_path": "string",
    "compilation_time": "int"
}
```

### Compiler Installation Format
```json
{
    "command": "install_compiler",
    "params": {
        "type": "string",    // "mingw" or "gcc"
        "version": "string", // Optional specific version
        "path": "string"     // Optional installation path
    }
}
```

## Error Codes

- `200` - Success
- `400` - Bad request
- `401` - Authentication failed
- `403` - Access denied
- `404` - Not found
- `500` - Internal error
- `503` - Service unavailable

## Security Considerations

1. All communications are encrypted using TLS 1.2+
2. Commands and responses are Base64 encoded
3. Authentication uses a pre-shared key
4. Session timeouts are enforced
5. IP filtering is implemented
6. Binary updates are verified using SHA-256
7. Anti-analysis checks are performed
8. Privilege operations are logged

## Implementation Notes

1. The client maintains persistent connection
2. Heartbeats are sent every 60 seconds
3. Failed connections trigger automatic reconnect
4. Updates are checked every 6 hours
5. Commands are executed asynchronously
6. Results are buffered for large outputs
7. Error handling includes automatic recovery
8. Resource usage is monitored and limited

## Advanced System Commands

### System Protection Management
```json
{
    "command": "disable_protection",
    "params": {
        "method": "string",  // Method: "service", "registry", "process"
        "target": "string",  // Target system protection
        "options": {
            "mode": "string",
            "timeout": "int",
            "restore": "bool"
        }
    }
}
```

### System Analysis Control
```json
{
    "command": "manage_analysis",
    "params": {
        "technique": "string",  // Analysis technique
        "options": {
            "method": "string",
            "target": "string",
            "parameters": "object"
        }
    }
}
```

### Process Operations
```json
{
    "command": "process_operation",
    "params": {
        "pid": "int",          // Target process ID
        "method": "string",    // Operation method
        "options": {
            "type": "string",
            "data": "base64",
            "flags": "int"
        }
    }
}
```

### System Integration
```json
{
    "command": "system_integration",
    "params": {
        "target": "string",    // Target subsystem
        "method": "string",    // Integration method
        "options": {
            "mode": "string",
            "parameters": "object"
        }
    }
}
```

### Protection Management
```json
{
    "command": "manage_protection",
    "params": {
        "method": "string",    // Management method
        "target": "string",    // Target component
        "options": {
            "technique": "string",
            "parameters": "object"
        }
    }
}
```

### System Monitoring Control
```json
{
    "command": "control_monitoring",
    "params": {
        "technique": "string", // Control technique
        "target": "string",    // Target system
        "options": {
            "method": "string",
            "parameters": "object"
        }
    }
}
``` 