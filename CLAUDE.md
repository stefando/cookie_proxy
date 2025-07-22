# HTTPS Cookie Proxy - Technical Documentation

## Overview
HTTPS man-in-the-middle proxy with dynamic certificate generation that captures session cookies from login flows and injects them into subsequent API requests for local development.

## Dependencies
- Go 1.24
- `github.com/elazarl/goproxy v1.7.2`
- `github.com/spf13/cobra v1.9.1` 
- `github.com/sirupsen/logrus v1.9.3`

## Build & Run
```bash
go build -o cookie-proxy .

# Automatic mkcert CA detection (recommended)
./cookie-proxy --domains saas.cmddev.stefando.me --log-level debug

# Custom CA certificate
./cookie-proxy \
  --domains saas.cmddev.stefando.me \
  --ca-cert /path/to/ca.pem \
  --ca-key /path/to/ca-key.pem \
  --log-level debug
```

## CLI Flags
- `--domains`: HTTPS domains to intercept (required)
- `--ca-cert`: CA certificate file path (auto-detects mkcert CA if not provided) 
- `--ca-key`: CA private key file path (auto-detects mkcert CA if not provided)
- `--cookies`: Cookie names to capture (default: session_id)
- `--port`: Proxy port (default: 8080)
- `--log-level`: debug, info, warn, error (default: info)

## Certificate Management
### Automatic mkcert Detection
Proxy automatically detects mkcert CA in standard locations:
- **macOS**: `~/Library/Application Support/mkcert/`
- **Linux**: `~/.local/share/mkcert/`
- **Windows**: `%LOCALAPPDATA%\mkcert\`

### Dynamic Certificate Generation
- Certificates generated on-demand for any requested domain
- Cached in memory for performance (cleared on restart)
- Signed by CA for browser trust
- Support for both domain names and IP addresses

## Browser Configuration
**Automatic proxy configuration**: `http://localhost:8080/proxy.pac`

**Certificate trust**:
- **Chrome/Safari/Edge**: Use system trust store (mkcert handles automatically)
- **Firefox**: Manual CA import required (see `CERTIFICATE_SETUP.md`)

## How It Works
1. **HTTPS MITM**: Terminates HTTPS connections using dynamically generated certificates
2. **Cookie Capture**: Extracts `Set-Cookie` headers from decrypted HTTPS responses 
3. **Cookie Injection**: Adds stored cookies to future HTTPS requests for same domain
4. **Selective Proxying**: Only specified domains proxied (PAC file), everything else direct
5. **Security Filtering**: 
   - Skips SameSite=Strict cookies (not suitable for cross-origin)
   - Rejects cookies with negative MaxAge (immediate deletion)

## Architecture Details
- **Dynamic HTTPS MITM**: Real-time certificate generation using CA signing
- **PAC file server**: Serves `/proxy.pac` for browser auto-configuration
- **Thread-safe operations**: Concurrent certificate caching and cookie storage
- **Zero persistence**: All certificates and cookies stored in memory only
- **Domain filtering**: Request/response handlers only process managed domains
- **Certificate caching**: Generated certificates cached per domain for performance

## Security Features
- **Certificate validation**: Proper CA chain construction for browser trust
- **SameSite validation**: Automatically skips SameSite=Strict cookies with warnings
- **Expiration handling**: Respects Max-Age and Expires headers, defaults to 1-hour TTL
- **Negative MaxAge handling**: Properly rejects cookies marked for immediate deletion
- **Memory-only storage**: No sensitive data persisted to disk
- **Lazy cleanup**: Expired cookies automatically removed during retrieval

## Implementation Files
- **main.go**: Core proxy logic, HTTP handlers, CLI interface
- **certificates.go**: Dynamic certificate generation and CA management
- **main_test.go**: Comprehensive test suite

## Testing
- Run `go test -v` for comprehensive testing
- ✅ **All 16 tests pass** - full test coverage with zero failures
- Tests cover: cookie storage, expiration, security validation, concurrency, PAC generation, certificate parsing

## Development Notes
- **goproxy.Verbose = false**: Silenced for clean output
- **GetCertificate callback**: Dynamic cert generation on TLS handshake
- **Mutex protection**: Thread-safe certificate and cookie caching
- **Error handling**: Graceful fallback for certificate generation failures