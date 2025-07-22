# HTTPS Cookie Proxy

> **HTTPS man-in-the-middle proxy for local development authentication**

## Problem

Local frontend development against authenticated APIs requires session cookies. Manual cookie management involves:
- Extracting cookies from browser dev tools
- Copying session tokens to development tools
- Re-authenticating when sessions expire
- Managing multiple authentication domains

## Solution

Cookie Proxy acts as an HTTPS man-in-the-middle, intercepting Set-Cookie headers from HTTPS login flows and injecting stored cookies into subsequent HTTPS API requests. Authentication persists across development sessions until cookies expire.

```
┌─────────────┐    ┌──────────────────┐    ┌─────────────┐
│   Browser   │───▶│ HTTPS Cookie     │───▶│ HTTPS API   │
│ (Login UI)  │    │ Proxy (MITM)     │    │ Backend     │
│             │    │ • Terminates SSL │    │             │
│             │    │ • Captures       │    │             │
│             │    │ • Injects        │    │             │
└─────────────┘    └──────────────────┘    └─────────────┘
                          │
                          ▼
                   ┌──────────────┐
                   │ Your Local   │
                   │ Dev Server   │
                   │ (Frontend)   │
                   └──────────────┘
```

## Quick Start

### 1. Install mkcert (if not already installed)
```bash
# macOS
brew install mkcert
mkcert -install

# Windows  
choco install mkcert
mkcert -install
```

### 2. Build and Start Proxy
```bash
go build -o cookie-proxy .
./cookie-proxy --domains your-https-domain.com
```

### 3. Configure Browser
**Automatic proxy:** `http://localhost:8080/proxy.pac`

**Firefox users:** Import the CA certificate manually (see [Certificate Setup](CERTIFICATE_SETUP.md))

### 4. Test HTTPS Interception
Visit `https://your-https-domain.com` - you should see certificate generation logs and no browser certificate warnings.

## Configuration

```bash
# Single HTTPS domain (auto-detects mkcert CA)
./cookie-proxy --domains api.myapp.com

# Multiple HTTPS domains with specific cookies  
./cookie-proxy --domains api.myapp.com,auth.myapp.com --cookies session_id,auth_token

# Custom port with debug logging
./cookie-proxy --domains api.myapp.com --port 9090 --log-level debug

# Custom CA certificate (instead of mkcert)
./cookie-proxy --domains api.myapp.com --ca-cert /path/to/ca.pem --ca-key /path/to/ca-key.pem
```

## Certificate Setup

The proxy requires a trusted CA certificate to generate HTTPS certificates dynamically.

### Automatic (Recommended)
The proxy automatically detects and uses your mkcert CA if installed.

### Manual Setup  
For detailed certificate setup instructions including Windows, mkcert installation, and Firefox configuration, see:

**[📋 Certificate Setup Guide](CERTIFICATE_SETUP.md)**

## How It Works

1. **HTTPS Termination:** Proxy terminates HTTPS connections using dynamically generated certificates
2. **Cookie Capture:** Extracts `Set-Cookie` headers from HTTPS responses  
3. **Cookie Injection:** Adds stored cookies to future HTTPS requests for the same domain
4. **Selective Proxying:** Only specified domains go through proxy (via PAC file)

## Troubleshooting

**Certificate Errors:** See [Certificate Setup Guide](CERTIFICATE_SETUP.md) for platform-specific instructions

**No Cookie Capture:** Verify domains match exactly and cookies aren't `SameSite=Strict`

**Firefox Issues:** Manual CA certificate import required (see certificate guide)

**Cookie Expiration:** Proxy respects server-set expiration times and clears on 401/403 responses

---

*Local development use only. Never use in production.*