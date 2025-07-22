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
All core functionality implemented in single `main.go` file (~381 lines) with security compliance and comprehensive testing.

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
- `--bind-address string`: IP address to bind to (default: 127.0.0.1 for localhost only)
- `--log-level string`: Logging level (debug, info, warn, error, default: info)

## Core Components (Implemented)
1. **PAC Server**: Serves `/proxy.pac` with selective domain routing
2. **Cookie Interceptor**: Captures Set-Cookie headers with security validation
3. **Request Enhancer**: Injects stored cookies into requests for managed domains
4. **Cookie Store**: Thread-safe storage using `*http.Cookie` with domain isolation and lazy expiration cleanup
5. **Cookie Security**: SameSite=Strict and Secure flag validation with logging
6. **Logout Detection**: Clears cookies on 401/403 responses
7. **CLI Interface**: Full cobra-based CLI with help and validation
8. **Structured Logging**: Logrus with detailed request/response and security logging

## How It Works
1. **Cookie Theft**: Intercepts `Set-Cookie` headers using `http.ParseSetCookie()` with security validation
2. **Security Checks**: Skips SameSite=Strict and Secure cookies on HTTP with warning logs
3. **Cookie Storage**: Thread-safe storage per domain using full `*http.Cookie` structs with proper expiration handling
4. **Cookie Injection**: Adds stored cookies to subsequent requests for same domain
5. **PAC Configuration**: Browser auto-config to only proxy managed domains
6. **Automatic Cleanup**: Lazy cleanup of expired cookies during retrieval, plus clears on 401/403 responses

## Browser Setup
Configure automatic proxy: `http://localhost:8080/proxy.pac`

## Architecture Details
- **Single package**: All code in `main.go` (~381 lines)
- **HTTP-only proxy**: Browser → HTTP proxy → HTTPS target
- **Thread-safe**: Concurrent cookie storage with mutex protection using `*http.Cookie`
- **Selective proxying**: Only managed domains go through proxy
- **Zero persistence**: In-memory storage, clears on restart
- **RFC compliant**: Uses `http.ParseSetCookie()` for parsing and `*http.Cookie` for storage
- **Cookie security**: Validates SameSite and Secure flags with clear logging
- **Lazy expiration**: Automatic cleanup during cookie retrieval with proper time handling
- **Network security**: Binds to localhost by default, configurable for WSL2 scenarios

## Cookie Security Features
- **SameSite=Strict Protection**: Automatically skips cookies with SameSite=Strict (not suitable for cross-origin)
- **Secure Flag Validation**: Only processes Secure cookies for HTTPS requests
- **Expiration Handling**: Respects `Expires` and `Max-Age` headers (including negative MaxAge for immediate deletion), defaults to 1 hour TTL
- **Lazy Cleanup**: Expired cookies automatically removed during retrieval
- **Security Logging**: Clear warning messages when cookies are skipped for security reasons

## Common Security Warnings
- `"Skipping SameSite=Strict cookie - not suitable for cross-origin use"` - Cookie explicitly forbids cross-site usage
- `"Skipping Secure cookie for non-HTTPS request"` - Secure cookie cannot be used over HTTP
- `"Cookie expired and removed"` - Cookie passed its Max-Age expiration time

## Troubleshooting Authentication Issues
1. **Check security logs** - Look for cookie skip warnings
2. **Verify cookie names** - Ensure `--cookies` flag matches server's cookie names  
3. **Check SameSite settings** - Server should use SameSite=Lax or SameSite=None for cross-origin
4. **Verify HTTPS usage** - Secure cookies require HTTPS endpoints
5. **Monitor expiration** - Cookies expire based on server's `Expires`/`Max-Age` settings (default: 1 hour)
6. **Test expiration** - Use `go test -v` to run comprehensive expiration tests

## Testing
- **Unit tests**: Run `go test -v` for comprehensive testing
- **Expiration tests**: Verify lazy cleanup, MaxAge handling, and default TTL behavior
- **Security tests**: Validate SameSite and Secure flag filtering
- **Concurrency tests**: Ensure thread-safe operation under load