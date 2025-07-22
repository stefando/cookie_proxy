# Cookie Proxy

> **HTTP proxy for local development authentication**

## Problem

Local frontend development against authenticated APIs requires session cookies. Manual cookie management involves:
- Extracting cookies from browser dev tools
- Copying session tokens to development tools
- Re-authenticating when sessions expire
- Managing multiple authentication domains

## Solution

Cookie Proxy intercepts Set-Cookie headers from login flows and injects stored cookies into API requests. Authentication persists across development sessions until cookies expire or are cleared.

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│   Browser   │───▶│ Cookie Proxy │───▶│  Backend    │
│ (Login UI)  │    │ (Captures &  │    │    API      │
│             │    │  Injects)    │    │             │
└─────────────┘    └──────────────┘    └─────────────┘
                          │
                          ▼
                   ┌──────────────┐
                   │ Your Local   │
                   │ Dev Server   │
                   │ (Frontend)   │
                   └──────────────┘
```

## Usage

### 1. Build and Start
```bash
go build -o cookie-proxy .
./cookie-proxy --domains your-api-domain.com
```

### 2. Configure Browser Proxy
Set browser proxy to: `http://localhost:8080/proxy.pac`

*Proxies only specified domains; other traffic routes directly*

### 3. Authenticate
Login through browser on target domains. Proxy captures session cookies.

### 4. Development
Local development requests to specified domains include captured authentication cookies.

## Configuration

```bash
# Single domain
./cookie-proxy --domains api.myapp.com

# Multiple domains with specific cookies
./cookie-proxy --domains api.myapp.com,auth.myapp.com --cookies session_id,auth_token

# Custom port with debug logging
./cookie-proxy --domains api.myapp.com --port 9090 --log-level debug

# WSL2: Allow Windows host browser access
./cookie-proxy --domains api.myapp.com --bind-address 0.0.0.0
```

## WSL2 Setup

**Default (secure)**: Proxy binds to `127.0.0.1`, accessible only within WSL2.

**For Windows host browser access**:
1. Find WSL2 IP: `ip addr show eth0 | grep inet`
2. Either bind to specific IP: `--bind-address 172.20.240.2`
3. Or bind to all interfaces: `--bind-address 0.0.0.0`
4. Configure Windows browser proxy: `http://WSL2-IP:8080/proxy.pac`

## Troubleshooting

**Authentication failures**: Proxy clears cookies on 401/403 responses. Re-authenticate in browser.

**Security warnings**: Check troubleshooting section in `CLAUDE.md`

**Cookie issues**: Verify domain names match target API endpoints exactly

**HTTPS requirements**: Secure cookies require HTTPS endpoints

---

*Local development use only*