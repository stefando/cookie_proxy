# Cookie Proxy Development Instructions

## Project Overview
Development authentication proxy that eliminates cross-origin authentication pain for local development by automatically capturing session cookies from browser login flows and injecting them into API requests.

## Dependencies and Tools
- Go 1.24
- Required packages: 
  - `github.com/elazarl/goproxy v1.7.2`
  - `github.com/spf13/cobra v1.9.1`
  - `github.com/sirupsen/logrus v1.9.3`
- Build command: `go build -o cookie-proxy .`
- Binary location: `./cookie-proxy`

## Implementation Status: COMPLETE ✅
All core functionality implemented in single `main.go` file (~280 lines).

## CLI Interface
```bash
# Basic usage
cookie-proxy --domains saas.cmddev.stefando.me

# Multiple domains and cookies
cookie-proxy --domains api.example.com,auth.example.com --cookies session_id,auth_token

# Custom port and debug logging
cookie-proxy --domains myapi.com --port 9090 --log-level debug
```

## CLI Flags
- `-d, --domains strings`: Domains to manage (required)
- `-c, --cookies strings`: Cookie names to intercept (default: session_id)
- `-p, --port int`: Proxy port (default: 8080)
- `--log-level string`: Logging level (debug, info, warn, error, default: info)

## Core Components (Implemented)
1. **PAC Server**: Serves `/proxy.pac` with selective domain routing
2. **Cookie Interceptor**: Captures Set-Cookie headers for specified cookie names
3. **Request Enhancer**: Injects stored cookies into requests for managed domains
4. **Cookie Store**: Thread-safe storage with domain isolation
5. **Logout Detection**: Clears cookies on 401/403 responses
6. **CLI Interface**: Full cobra-based CLI with help and validation
7. **Structured Logging**: Logrus with detailed request/response logging

## How It Works
1. **Cookie Theft**: Intercepts `Set-Cookie` headers from managed domains for specified cookie names
2. **Cookie Storage**: Thread-safe storage per domain
3. **Cookie Injection**: Adds stored cookies to subsequent requests for same domain
4. **PAC Configuration**: Browser auto-config to only proxy managed domains
5. **Automatic Cleanup**: Clears cookies on authentication failures (401/403)

## Browser Setup
Configure automatic proxy: `http://localhost:8080/proxy.pac`

## Architecture Details
- **Single package**: All code in `main.go`
- **HTTP-only proxy**: Browser → HTTP proxy → HTTPS target
- **Thread-safe**: Concurrent cookie storage with mutex protection
- **Selective proxying**: Only managed domains go through proxy
- **Zero persistence**: In-memory storage, clears on restart