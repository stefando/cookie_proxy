package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type CookieStore struct {
	cookies map[string]map[string]*http.Cookie // domain -> cookie_name -> cookie
	mu      sync.RWMutex
}

func NewCookieStore() *CookieStore {
	return &CookieStore{
		cookies: make(map[string]map[string]*http.Cookie),
	}
}

func (cs *CookieStore) Store(domain string, cookie *http.Cookie) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	
	if cs.cookies[domain] == nil {
		cs.cookies[domain] = make(map[string]*http.Cookie)
	}
	
	// Create a copy and set proper expiration time
	cookieCopy := *cookie // Copy the cookie
	var expiresAt time.Time
	if !cookie.Expires.IsZero() {
		expiresAt = cookie.Expires
	} else if cookie.MaxAge > 0 {
		expiresAt = time.Now().Add(time.Duration(cookie.MaxAge) * time.Second)
		cookieCopy.Expires = expiresAt // Set the calculated expiration
	} else if cookie.MaxAge < 0 {
		// Negative MaxAge means delete immediately (set expiration in the past)
		expiresAt = time.Now().Add(-time.Hour)
		cookieCopy.Expires = expiresAt // Set expired time
	} else {
		// MaxAge == 0 or not set, use default 1 hour
		expiresAt = time.Now().Add(time.Hour) // Default 1 hour
		cookieCopy.Expires = expiresAt // Set the default expiration
	}
	
	cs.cookies[domain][cookie.Name] = &cookieCopy
	
	logrus.WithFields(logrus.Fields{
		"action":     "cookie_captured",
		"domain":     domain,
		"name":       cookie.Name,
		"value":      cookie.Value,
		"expires_at": expiresAt.Format(time.RFC3339),
	}).Info("Cookie captured")
}


func (cs *CookieStore) Get(domain string) map[string]string {
	cs.mu.Lock() // Use write lock for lazy cleanup
	defer cs.mu.Unlock()
	
	if cs.cookies[domain] == nil {
		return make(map[string]string)
	}
	
	now := time.Now()
	result := make(map[string]string)
	
	// Lazy cleanup: remove expired cookies and return valid ones
	for name, cookie := range cs.cookies[domain] {
		// Calculate expiration time - we use the Expires field which was set during storage
		// (either from original Expires or calculated from MaxAge at storage time)
		var expiresAt time.Time
		if !cookie.Expires.IsZero() {
			expiresAt = cookie.Expires
		} else {
			// No expiration set, treat as session cookie - valid for 1 hour from now
			expiresAt = time.Now().Add(time.Hour)
		}
		
		if now.Before(expiresAt) {
			// Cookie is still valid
			result[name] = cookie.Value
		} else {
			// Cookie expired, remove it (lazy cleanup)
			delete(cs.cookies[domain], name)
			logrus.WithFields(logrus.Fields{
				"action": "cookie_expired",
				"domain": domain,
				"name":   name,
			}).Info("Cookie expired and removed")
		}
	}
	
	// Clean up empty domain map
	if len(cs.cookies[domain]) == 0 {
		delete(cs.cookies, domain)
	}
	
	return result
}

func (cs *CookieStore) Clear(domain string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	
	delete(cs.cookies, domain)
	logrus.WithField("domain", domain).Info("Cookies cleared for domain")
}

type ProxyConfig struct {
	domains     []string
	cookieNames []string
	port        int
	bindAddress string
}

type ProxyServer struct {
	store       *CookieStore
	domains     []string
	cookieNames []string
	port        int
	bindAddress string
}

func NewProxyServer(configFn func(*ProxyConfig)) *ProxyServer {
	config := &ProxyConfig{
		cookieNames: []string{"session_id"},
		port:        8080,
		bindAddress: "127.0.0.1",
	}
	
	if configFn != nil {
		configFn(config)
	}
	
	return &ProxyServer{
		store:       NewCookieStore(),
		domains:     config.domains,
		cookieNames: config.cookieNames,
		port:        config.port,
		bindAddress: config.bindAddress,
	}
}

func (ps *ProxyServer) isTargetDomain(host string) bool {
	for _, domain := range ps.domains {
		if host == domain {
			return true
		}
	}
	return false
}

func (ps *ProxyServer) parseSetCookieWithURL(setCookieHeader, cookieName string, requestURL *url.URL) *http.Cookie {
	// Parse using stdlib directly - handles all edge cases, proper case, encoding, etc.
	cookie, err := http.ParseSetCookie(setCookieHeader)
	if err != nil {
		// Malformed cookie header, skip it
		return nil
	}
	
	if cookie.Name != cookieName {
		return nil
	}
	
	// Check security attributes
	if cookie.SameSite == http.SameSiteStrictMode {
		logrus.WithFields(logrus.Fields{
			"action": "cookie_skipped",
			"domain": requestURL.Host,
			"name":   cookie.Name,
			"reason": "SameSite=Strict not suitable for cross-origin use",
		}).Warn("Skipping SameSite=Strict cookie")
		return nil
	}
	
	if cookie.Secure && requestURL.Scheme != "https" {
		logrus.WithFields(logrus.Fields{
			"action": "cookie_skipped",
			"domain": requestURL.Host,
			"name":   cookie.Name,
			"reason": "Secure cookie not suitable for non-HTTPS requests",
			"scheme": requestURL.Scheme,
		}).Warn("Skipping Secure cookie for non-HTTPS request")
		return nil
	}
	
	return cookie
}


func (ps *ProxyServer) servePAC(w http.ResponseWriter, r *http.Request) {
	pac := fmt.Sprintf(`function FindProxyForURL(url, host) {
    // Only proxy managed domains
    %s
    
    // Everything else bypasses proxy
    return "DIRECT";
}`, ps.generatePACConditions())

	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(pac))
}

func (ps *ProxyServer) generatePACConditions() string {
	conditions := make([]string, len(ps.domains))
	for i, domain := range ps.domains {
		conditions[i] = fmt.Sprintf(`if (host === "%s") {
        return "PROXY localhost:%d";
    }`, domain, ps.port)
	}
	return strings.Join(conditions, "\n    ")
}

func (ps *ProxyServer) Start() error {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	// Cookie theft - intercept Set-Cookie headers
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil || ctx.Req == nil {
			return resp
		}

		host := ctx.Req.URL.Host
		if !ps.isTargetDomain(host) {
			return resp
		}

		// Look for Set-Cookie headers
		setCookieHeaders := resp.Header["Set-Cookie"]
		for _, setCookieHeader := range setCookieHeaders {
			for _, cookieName := range ps.cookieNames {
				if cookie := ps.parseSetCookieWithURL(setCookieHeader, cookieName, ctx.Req.URL); cookie != nil {
					ps.store.Store(host, cookie)
				}
			}
		}

		return resp
	})

	// Cookie injection - add stored cookies to requests
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if req == nil {
			return req, nil
		}

		host := req.URL.Host
		if !ps.isTargetDomain(host) {
			return req, nil
		}

		// Get stored cookies for this domain
		cookies := ps.store.Get(host)
		if len(cookies) == 0 {
			return req, nil
		}

		// Build cookie header
		var cookieParts []string
		for name, value := range cookies {
			cookieParts = append(cookieParts, fmt.Sprintf("%s=%s", name, value))
		}

		if len(cookieParts) > 0 {
			existingCookies := req.Header.Get("Cookie")
			if existingCookies != "" {
				req.Header.Set("Cookie", existingCookies+"; "+strings.Join(cookieParts, "; "))
			} else {
				req.Header.Set("Cookie", strings.Join(cookieParts, "; "))
			}

			logrus.WithFields(logrus.Fields{
				"action": "cookie_injected",
				"domain": host,
				"path":   req.URL.Path,
				"cookies": strings.Join(cookieParts, "; "),
			}).Info("Cookies injected into request")
		}

		return req, nil
	})

	// Handle logout detection - clear cookies on 401/403
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil || ctx.Req == nil {
			return resp
		}

		host := ctx.Req.URL.Host
		if !ps.isTargetDomain(host) {
			return resp
		}

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			ps.store.Clear(host)
		}

		return resp
	})

	// Serve PAC file
	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/proxy.pac" {
			ps.servePAC(w, r)
			return
		}
		http.Error(w, "Not found", http.StatusNotFound)
	})

	logrus.WithFields(logrus.Fields{
		"bind_address": ps.bindAddress,
		"port":         ps.port,
		"domains":      strings.Join(ps.domains, ", "),
		"cookies":      strings.Join(ps.cookieNames, ", "),
		"pac_url":      fmt.Sprintf("http://%s:%d/proxy.pac", ps.bindAddress, ps.port),
	}).Info("Starting cookie proxy server")

	return http.ListenAndServe(fmt.Sprintf("%s:%d", ps.bindAddress, ps.port), proxy)
}

func main() {
	var domains []string
	var cookieNames []string
	var port int
	var logLevel string
	var bindAddress string

	rootCmd := &cobra.Command{
		Use:   "cookie-proxy",
		Short: "HTTP proxy for local development authentication",
		Long: `HTTP proxy that captures session cookies from browser login flows and injects them into API requests.
Manages authentication for local frontend development against cookie-authenticated APIs.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(domains) == 0 {
				return fmt.Errorf("at least one domain must be specified with --domains")
			}

			// Set log level
			level, err := logrus.ParseLevel(logLevel)
			if err != nil {
				return fmt.Errorf("invalid log level: %s", logLevel)
			}
			logrus.SetLevel(level)

			// Default cookie names if not specified
			if len(cookieNames) == 0 {
				cookieNames = []string{"session_id"}
			}

			server := NewProxyServer(func(c *ProxyConfig) {
				c.domains = domains
				c.cookieNames = cookieNames
				c.port = port
				c.bindAddress = bindAddress
			})
			return server.Start()
		},
	}

	rootCmd.Flags().StringSliceVarP(&domains, "domains", "d", nil, "Domains to manage (required)")
	rootCmd.Flags().StringSliceVarP(&cookieNames, "cookies", "c", []string{"session_id"}, "Cookie names to intercept (comma-separated)")
	rootCmd.Flags().IntVarP(&port, "port", "p", 8080, "Proxy port")
	rootCmd.Flags().StringVar(&bindAddress, "bind-address", "127.0.0.1", "IP address to bind to (127.0.0.1 for localhost only, 0.0.0.0 for all interfaces)")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Logging level (debug, info, warn, error)")

	rootCmd.MarkFlagRequired("domains")

	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}