package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type CookieStore struct {
	cookies map[string]map[string]string // domain -> cookie_name -> cookie_value
	mu      sync.RWMutex
}

func NewCookieStore() *CookieStore {
	return &CookieStore{
		cookies: make(map[string]map[string]string),
	}
}

func (cs *CookieStore) StoreCookie(domain, name, value string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	
	if cs.cookies[domain] == nil {
		cs.cookies[domain] = make(map[string]string)
	}
	cs.cookies[domain][name] = value
	
	logrus.WithFields(logrus.Fields{
		"action": "cookie_captured",
		"domain": domain,
		"name":   name,
		"value":  value,
	}).Info("Cookie captured")
}

func (cs *CookieStore) GetCookies(domain string) map[string]string {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	
	if cs.cookies[domain] == nil {
		return make(map[string]string)
	}
	
	// Return a copy to avoid race conditions
	result := make(map[string]string)
	for k, v := range cs.cookies[domain] {
		result[k] = v
	}
	return result
}

func (cs *CookieStore) ClearCookies(domain string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	
	delete(cs.cookies, domain)
	logrus.WithField("domain", domain).Info("Cookies cleared for domain")
}

type ProxyServer struct {
	store       *CookieStore
	domains     []string
	cookieNames []string
	port        int
	logger      *logrus.Logger
}

func NewProxyServer(domains, cookieNames []string, port int) *ProxyServer {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	
	return &ProxyServer{
		store:       NewCookieStore(),
		domains:     domains,
		cookieNames: cookieNames,
		port:        port,
		logger:      logger,
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

func (ps *ProxyServer) extractCookieValue(setCookieHeader, cookieName string) string {
	// Parse Set-Cookie header: "session_id=abc123; Path=/; HttpOnly"
	parts := strings.Split(setCookieHeader, ";")
	if len(parts) == 0 {
		return ""
	}
	
	keyValue := strings.TrimSpace(parts[0])
	cookieParts := strings.SplitN(keyValue, "=", 2)
	if len(cookieParts) != 2 {
		return ""
	}
	
	if strings.TrimSpace(cookieParts[0]) == cookieName {
		return strings.TrimSpace(cookieParts[1])
	}
	return ""
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
				if cookieValue := ps.extractCookieValue(setCookieHeader, cookieName); cookieValue != "" {
					ps.store.StoreCookie(host, cookieName, cookieValue)
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
		cookies := ps.store.GetCookies(host)
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

			ps.logger.WithFields(logrus.Fields{
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
			ps.store.ClearCookies(host)
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

	ps.logger.WithFields(logrus.Fields{
		"port":    ps.port,
		"domains": strings.Join(ps.domains, ", "),
		"cookies": strings.Join(ps.cookieNames, ", "),
		"pac_url": fmt.Sprintf("http://localhost:%d/proxy.pac", ps.port),
	}).Info("Starting cookie proxy server")

	return http.ListenAndServe(fmt.Sprintf(":%d", ps.port), proxy)
}

func main() {
	var domains []string
	var cookieNames []string
	var port int
	var logLevel string

	rootCmd := &cobra.Command{
		Use:   "cookie-proxy",
		Short: "Development authentication proxy that captures and injects session cookies",
		Long: `A Go-based HTTP proxy that eliminates cross-origin authentication pain for local development.
The proxy automatically captures session cookies from browser login flows and injects them into API requests.`,
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

			server := NewProxyServer(domains, cookieNames, port)
			return server.Start()
		},
	}

	rootCmd.Flags().StringSliceVarP(&domains, "domains", "d", nil, "Domains to manage (required)")
	rootCmd.Flags().StringSliceVarP(&cookieNames, "cookies", "c", []string{"session_id"}, "Cookie names to intercept (comma-separated)")
	rootCmd.Flags().IntVarP(&port, "port", "p", 8080, "Proxy port")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Logging level (debug, info, warn, error)")

	rootCmd.MarkFlagRequired("domains")

	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}