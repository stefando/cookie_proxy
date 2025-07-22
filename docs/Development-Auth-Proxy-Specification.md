# Development Authentication Proxy Specification

## Overview

A Go-based HTTP proxy that eliminates cross-origin authentication pain for local development. The proxy automatically captures session cookies from browser login flows and injects them into API requests, making cross-origin development feel like same-origin.

**Design Philosophy:** Replace 1000 lines of AWS API Gateway wrestling with 30 lines of elegant Go that just works.

## The Problem We're Solving

**Current Pain:**
- Frontend dev server: `localhost:3000` 
- API backend: `saas.cmddev.stefando.me`
- Cross-origin requests can't carry cookies
- Manual Authorization header management required
- Different auth methods for dev vs production

**The Solution:**
- Login once in browser (normal OAuth flow)
- Proxy captures session cookies automatically  
- All API calls magically authenticated
- Zero client code changes needed

## Architecture

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│   Browser   │───▶│  Auth Proxy  │───▶│  Target API │
│             │    │   (HTTP)     │    │  (HTTPS)    │
│ localhost:  │    │ localhost:   │    │ production  │
│ 3000        │    │ 8080         │    │ domain      │
└─────────────┘    └──────────────┘    └─────────────┘
                          │
                   ┌─────────────┐
                   │   Stolen    │
                   │   Cookies   │
                   └─────────────┘
```

**How it Works:**
1. **PAC Configuration**: Browser sends only target domain traffic through proxy
2. **Cookie Theft**: Proxy intercepts `Set-Cookie` headers during login
3. **Cookie Injection**: Proxy adds stolen cookies to subsequent requests
4. **Transparent Passthrough**: All other traffic bypasses proxy completely

## Implementation Priorities

### Priority 1: Core Functionality (Weekend MVP)

#### 1.1 PAC Server
```go
// Serves automatic proxy configuration
http.HandleFunc("/proxy.pac", servePAC)
```

**Functionality:**
- Serves JavaScript PAC file
- Configures selective proxying (only managed domains)
- Zero manual browser configuration per request

#### 1.2 Cookie Interceptor  
```go
// Intercept Set-Cookie headers
proxy.OnResponse().DoFunc(stealCookies)
```

**Functionality:**
- Parse `Set-Cookie` headers from authentication responses
- Extract session cookies (e.g., `session_id=abc123`)
- Store in memory for request injection

#### 1.3 Request Enhancer
```go
// Inject stolen cookies
proxy.OnRequest().DoFunc(injectCookies)
```

**Functionality:**
- Add `Cookie: session_id=abc123` to requests for managed domains
- Maintain original request integrity
- Transparent to client applications

#### 1.4 Basic CLI
```go
// Simple cobra CLI
auth-proxy --domains saas.cmddev.stefando.me --port 8080
```

**Functionality:**
- Port configuration
- Domain selection
- Start/stop proxy

#### 1.5 HTTP Proxy Core
```go
// Using goproxy for HTTP proxy
proxy := goproxy.NewProxyHttpServer()
http.ListenAndServe(":8080", proxy)
```

**Key Decision: HTTP-Only Proxy**
- Browser connects to proxy via HTTP
- Proxy makes HTTPS calls to target APIs
- No certificate management complexity
- Browser may show "insecure proxy" warnings (acceptable for dev)

### Priority 2: Development Experience 

#### 2.1 Logout Detection
- Monitor cookie deletion (`Max-Age=0`, expired dates)
- Clear stored sessions on 401/403 responses  
- Watch for logout endpoint patterns (`/logout`, `/signout`)

#### 2.2 Enhanced Logging
```go
// Structured logging with logrus
log.WithFields(logrus.Fields{
    "action": "cookie_captured",
    "domain": "saas.cmddev.stefando.me", 
    "session_id": "abc123...",
}).Info("Authentication captured")
```

#### 2.3 Multi-Domain Support
- Handle multiple API domains simultaneously
- Domain-specific cookie storage
- Separate session management per domain

### Priority 3: Future Enhancements

#### 3.1 HTTPS Proxy Support
- MITM proxy with certificate generation
- Full TLS interception capability
- Eliminates browser security warnings

#### 3.2 Advanced Features
- Configuration persistence
- Multi-user session support
- Request/response middleware
- Health check endpoints

## CLI Interface

```bash
# Development Authentication Proxy
auth-proxy [flags]

Core Flags:
  -d, --domains strings    Domains to manage (required)
  -p, --port int          Proxy port (default: 8080)
      --log-level string   Logging level (default: info)

Examples:
  # Basic usage
  auth-proxy --domains saas.cmddev.stefando.me
  
  # Multiple domains with debug logging  
  auth-proxy --domains api.example.com,auth.example.com --log-level debug
  
  # Custom port
  auth-proxy --domains myapi.com --port 9090
```

## Browser Setup

### One-Time Configuration

**Chrome/Edge:**
1. Settings → Advanced → System → Open proxy settings
2. LAN Settings → Use automatic configuration script  
3. Address: `http://localhost:8080/proxy.pac`

**Firefox:**
1. Settings → Network Settings → Settings
2. Automatic proxy configuration URL
3. URL: `http://localhost:8080/proxy.pac`

**PAC Configuration Logic:**
```javascript
function FindProxyForURL(url, host) {
    // Only proxy managed domains
    if (host === "saas.cmddev.stefando.me") {
        return "PROXY localhost:8080";
    }
    
    // Everything else bypasses proxy
    return "DIRECT";
}
```

## Developer Workflow

### The Magic Experience

```bash
# 1. Start the proxy (one terminal)
./auth-proxy --domains saas.cmddev.stefando.me

# 2. Login normally (any browser tab)
# Visit https://saas.cmddev.stefando.me/login
# Complete OAuth flow
# ✨ Proxy captures session automatically

# 3. Develop as if same-origin (your app)
fetch('/api/v1/uploads/drive', {
    method: 'POST',
    body: formData,
    // No auth headers needed! Cookies injected automatically
});

# 4. API receives authenticated request
# Cookie: session_id=abc123
```

### What Developers See

**Before Proxy:**
```javascript
// Complex auth management
const token = await getAuthToken();
fetch('/api/v1/uploads/drive', {
    headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    },
    body: data
});
```

**With Proxy:**
```javascript  
// Just works™
fetch('/api/v1/uploads/drive', {
    method: 'POST', 
    body: data
});
```

## Technical Implementation

### HTTP Proxy Library Choice

**Design Priorities for Library Selection:**
- **Expressiveness over performance** - Code readability crucial for weekend hack
- **Minimal dependencies** - Balance simplicity with functionality
- **Time-to-value** - Fast development iteration over architectural purity

#### Option 1: `github.com/elazarl/goproxy` (Recommended)

**Code Example:**
```go
// Very expressive for our use case
proxy := goproxy.NewProxyHttpServer()

// Cookie theft - clean and readable
proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
    for _, cookie := range r.Header["Set-Cookie"] {
        if strings.Contains(cookie, "session_id=") {
            storedCookie = extractSessionId(cookie)
        }
    }
    return r
})

// Cookie injection - equally clean
proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
    if r.URL.Host == "saas.cmddev.stefando.me" && storedCookie != "" {
        r.Header.Set("Cookie", "session_id=" + storedCookie)
    }
    return r, nil
})
```

**Pros:**
- ✅ **Expressiveness: 9/10** - Purpose-built for HTTP proxy manipulation
- ✅ **Mature library** - 8+ years old, battle-tested
- ✅ **Zero transitive dependencies**
- ✅ **Perfect for proxy-specific operations**
- ✅ **30-line implementation possible**

**Cons:**
- ❌ **External dependency** (though very stable)
- ❌ **Adds ~100KB to binary**
- ❌ **Dependencies: 3/10**

#### Option 2: Go Standard Library (`net/http/httputil.ReverseProxy`)

**Code Example:**
```go
// Zero external dependencies
proxy := &httputil.ReverseProxy{
    Director: func(req *http.Request) {
        req.URL.Scheme = "https"
        req.URL.Host = "saas.cmddev.stefando.me"
        
        // Cookie injection
        if storedCookie != "" {
            req.Header.Set("Cookie", "session_id=" + storedCookie)
        }
    },
    ModifyResponse: func(resp *http.Response) error {
        // Cookie theft
        for _, cookie := range resp.Header["Set-Cookie"] {
            if strings.Contains(cookie, "session_id=") {
                storedCookie = extractSessionId(cookie)
            }
        }
        return nil
    },
}
```

**Pros:**
- ✅ **Dependencies: 10/10** - Zero external dependencies
- ✅ **Part of Go standard library**
- ✅ **No version conflicts possible**

**Cons:**
- ❌ **Expressiveness: 6/10** - More verbose, less proxy-specific
- ❌ **ReverseProxy designed for single backend**, not selective proxying
- ❌ **Need separate PAC server implementation**
- ❌ **More boilerplate code required**

#### Option 3: Raw `net/http` (Pure stdlib)

**Code Example:**
```go
http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    if r.Method == "CONNECT" {
        // Handle CONNECT tunneling manually (~50 lines)
        handleConnect(w, r)
        return
    }
    
    // Regular HTTP proxy (~100 lines)
    client := &http.Client{}
    proxyReq, _ := http.NewRequest(r.Method, "https://" + r.URL.Host + r.URL.Path, r.Body)
    
    // Cookie injection
    if storedCookie != "" {
        proxyReq.Header.Set("Cookie", "session_id=" + storedCookie)
    }
    
    resp, _ := client.Do(proxyReq)
    // ... extensive response copying logic
})
```

**Pros:**
- ✅ **Dependencies: 10/10** - Pure stdlib
- ✅ **Complete control over implementation**

**Cons:**
- ❌ **Expressiveness: 3/10** - Massive boilerplate (200+ lines)
- ❌ **Need to implement CONNECT tunneling manually**
- ❌ **Error-prone** - easy to get HTTP proxy protocol wrong
- ❌ **Destroys "30-line" weekend hack story**

#### Decision: `goproxy` for Weekend MVP

**Reasoning:**
```go
// This is the entire core logic with goproxy
var storedCookie string

proxy := goproxy.NewProxyHttpServer()
proxy.OnResponse().DoFunc(stealCookie)
proxy.OnRequest().DoFunc(injectCookie) 
http.ListenAndServe(":8080", proxy)
```

**vs stdlib equivalent:**
```go
// Would need ~200+ lines of HTTP proxy protocol handling
// CONNECT tunneling implementation  
// Header copying logic
// Response streaming
// Error handling
// ... much more complexity
```

**Trade-off Analysis:**
- **Expressiveness**: `goproxy` wins massively (30 lines vs 200+)
- **Maintainability**: Clear, readable code matters more than zero deps
- **Time-to-value**: Weekend hack needs fast iteration
- **Reliability**: `goproxy` handles edge cases we'd miss
- **Dependency cost**: One stable library, ~100KB (negligible for dev tool)

**The "30 lines that replace 1000" story only works if those 30 lines are actually 30 lines!**

### Core Dependencies
```go
// Minimal dependencies for maximum expressiveness
github.com/elazarl/goproxy    // HTTP proxy framework (chosen for simplicity)
github.com/spf13/cobra        // CLI interface  
github.com/sirupsen/logrus    // Structured logging
```

### Key Components

1. **PAC Server** - Serves proxy auto-configuration
2. **Cookie Thief** - Intercepts and stores session cookies
3. **Request Enhancer** - Injects cookies into outbound requests
4. **Domain Manager** - Handles multi-domain routing
5. **Session Store** - In-memory cookie storage

### Session Management

**Storage:**
- In-memory only (no persistence)
- Automatic cleanup on proxy restart
- Session isolation per proxy instance

**Security:**
- Localhost-only binding by default
- Development environment only
- Session data never exposed externally

## Success Criteria

### Primary Goals (Must Have)
1. **Zero-config auth** - Login once, API calls work forever
2. **Transparent operation** - Invisible to application code
3. **Selective proxying** - Zero interference with other websites
4. **30-line implementation** - Prove simplicity beats complexity

### Secondary Goals (Nice to Have)  
1. **Automatic logout detection** - Session cleanup on logout
2. **Multi-domain support** - Handle multiple APIs simultaneously
3. **Rich logging** - Debug authentication flows easily
4. **Graceful degradation** - Fail safely when proxy unavailable

## Limitations & Trade-offs

### What We're NOT Building
- ❌ Production-ready proxy infrastructure
- ❌ Advanced security features  
- ❌ High-performance request routing
- ❌ Complex authentication protocols

### Known Limitations
- **HTTP-only proxy**: Browser security warnings possible
- **In-memory storage**: Sessions lost on restart
- **Development only**: Not suitable for production
- **Single session**: One user session per domain

### Why These Are Acceptable
- **Fast development iteration** over production features
- **Simplicity** over comprehensive functionality
- **Time-to-value** over architectural perfection
- **Weekend hack** over enterprise solution

## The Weekend Satori Story

**Problem:** AWS API Gateway forces ugly dual authentication architecture

**AWS Solution:** 
- Duplicate every endpoint
- VTL magic strings
- Identity source wrestling  
- 1000+ lines of YAML

**Our Solution:**
```go
// The entire authentication proxy
var storedCookie string

proxy.OnResponse().DoFunc(stealCookie)
proxy.OnRequest().DoFunc(injectCookie) 
http.ListenAndServe(":8080", proxy)
```

**Result:** Delete 1000 lines, add 30 lines, infinite developer happiness.

*"The best code is the code you delete."*