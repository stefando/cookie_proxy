package main

import (
	"crypto/tls"
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
	
	// Skip cookies with negative MaxAge (means delete immediately)
	if cookie.MaxAge < 0 {
		logrus.WithFields(logrus.Fields{
			"domain": domain,
			"name":   cookie.Name,
		}).Debug("Skipping cookie with negative MaxAge")
		return
	}
	
	cookieCopy := *cookie
	if cookie.MaxAge > 0 {
		cookieCopy.Expires = time.Now().Add(time.Duration(cookie.MaxAge) * time.Second)
	} else if cookie.Expires.IsZero() {
		cookieCopy.Expires = time.Now().Add(time.Hour) // Default 1 hour
	}
	
	cs.cookies[domain][cookie.Name] = &cookieCopy
	
	logrus.WithFields(logrus.Fields{
		"domain": domain,
		"name":   cookie.Name,
		"value":  cookie.Value,
	}).Info("Cookie captured")
}

func (cs *CookieStore) Get(domain string) map[string]string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	
	if cs.cookies[domain] == nil {
		return make(map[string]string)
	}
	
	now := time.Now()
	result := make(map[string]string)
	
	for name, cookie := range cs.cookies[domain] {
		if now.Before(cookie.Expires) {
			result[name] = cookie.Value
		} else {
			delete(cs.cookies[domain], name)
		}
	}
	
	return result
}

func (cs *CookieStore) Clear(domain string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	
	delete(cs.cookies, domain)
	logrus.WithField("domain", domain).Info("Cookies cleared for domain")
}

type ProxyServer struct {
	store     *CookieStore
	domains   []string
	cookieNames []string
	port      int
	certManager *CertificateManager
}

func (ps *ProxyServer) isTargetDomain(host string) bool {
	for _, domain := range ps.domains {
		if host == domain {
			return true
		}
	}
	return false
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

func (ps *ProxyServer) parseSetCookieWithURL(setCookieHeader, cookieName string, requestURL *url.URL) *http.Cookie {
	cookie, err := http.ParseSetCookie(setCookieHeader)
	if err != nil {
		return nil
	}
	
	if cookie.Name != cookieName {
		return nil
	}
	
	// Skip problematic cookies
	if cookie.SameSite == http.SameSiteStrictMode {
		logrus.WithField("cookie", cookie.Name).Warn("Skipping SameSite=Strict cookie")
		return nil
	}
	
	if cookie.Secure && requestURL.Scheme != "https" {
		logrus.WithFields(logrus.Fields{
			"cookie": cookie.Name,
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

func (ps *ProxyServer) Start() error {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false // Silence verbose goproxy logs
	
	// Enable HTTPS MITM with dynamic certificate generation
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	
	// Create TLS config function for dynamic certificate generation
	tlsConfigFunc := func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
		return &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				domain := hello.ServerName
				return ps.certManager.GetCertificate(domain)
			},
		}, nil
	}
	
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: tlsConfigFunc}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsConfigFunc}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: tlsConfigFunc}
	
	logrus.Info("HTTPS MITM enabled with dynamic certificate generation")
	
	// Cookie injection
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if req == nil || !ps.isTargetDomain(req.Host) {
			return req, nil
		}
		
		logrus.WithField("url", req.URL.String()).Debug("Processing HTTPS request")
		
		cookies := ps.store.Get(req.Host)
		if len(cookies) > 0 {
			var cookieParts []string
			for name, value := range cookies {
				cookieParts = append(cookieParts, fmt.Sprintf("%s=%s", name, value))
			}
			
			existingCookies := req.Header.Get("Cookie")
			if existingCookies != "" {
				req.Header.Set("Cookie", existingCookies+"; "+strings.Join(cookieParts, "; "))
			} else {
				req.Header.Set("Cookie", strings.Join(cookieParts, "; "))
			}
			
			logrus.WithFields(logrus.Fields{
				"domain": req.Host,
				"cookies": strings.Join(cookieParts, "; "),
			}).Info("Cookies injected")
		}
		
		return req, nil
	})
	
	// Cookie capture
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil || ctx.Req == nil || !ps.isTargetDomain(ctx.Req.Host) {
			return resp
		}
		
		logrus.WithFields(logrus.Fields{
			"url": ctx.Req.URL.String(),
			"status": resp.StatusCode,
		}).Debug("Processing HTTPS response")
		
		setCookieHeaders := resp.Header["Set-Cookie"]
		for _, setCookieHeader := range setCookieHeaders {
			cookie, err := http.ParseSetCookie(setCookieHeader)
			if err != nil {
				continue
			}
			
			for _, cookieName := range ps.cookieNames {
				if cookie.Name == cookieName {
					// Skip problematic cookies
					if cookie.SameSite == http.SameSiteStrictMode {
						logrus.WithField("cookie", cookie.Name).Warn("Skipping SameSite=Strict cookie")
						continue
					}
					
					ps.store.Store(ctx.Req.Host, cookie)
				}
			}
		}
		
		return resp
	})
	
	// Serve PAC file
	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/proxy.pac" {
			pac := fmt.Sprintf(`function FindProxyForURL(url, host) {
    // Only proxy managed domains
    %s
    
    // Everything else bypasses proxy
    return "DIRECT";
}`, ps.generatePACConditions())

			w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(pac))
			logrus.Debug("Served PAC file")
			return
		}
		http.Error(w, "Not found", http.StatusNotFound)
	})

	logrus.WithFields(logrus.Fields{
		"port":    ps.port,
		"domains": strings.Join(ps.domains, ", "),
		"cookies": strings.Join(ps.cookieNames, ", "),
		"pac_url": fmt.Sprintf("http://127.0.0.1:%d/proxy.pac", ps.port),
	}).Info("Starting HTTPS cookie proxy")
	
	return http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", ps.port), proxy)
}

func main() {
	var domains []string
	var cookieNames []string
	var port int
	var logLevel string
	var caCertFile string
	var caKeyFile string

	rootCmd := &cobra.Command{
		Use:   "cookie-proxy",
		Short: "HTTPS cookie proxy for development authentication",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(domains) == 0 {
				return fmt.Errorf("at least one domain must be specified with --domains")
			}

			level, err := logrus.ParseLevel(logLevel)
			if err != nil {
				return fmt.Errorf("invalid log level: %s", logLevel)
			}
			logrus.SetLevel(level)

			if len(cookieNames) == 0 {
				cookieNames = []string{"session_id"}
			}

			// Create certificate manager (uses mkcert CA by default)
			certManager, err := NewCertificateManager(caCertFile, caKeyFile)
			if err != nil {
				return fmt.Errorf("failed to create certificate manager: %v", err)
			}

			server := &ProxyServer{
				store:       NewCookieStore(),
				domains:     domains,
				cookieNames: cookieNames,
				port:        port,
				certManager: certManager,
			}
			return server.Start()
		},
	}

	rootCmd.Flags().StringSliceVarP(&domains, "domains", "d", nil, "Domains to manage (required)")
	rootCmd.Flags().StringSliceVarP(&cookieNames, "cookies", "c", []string{"session_id"}, "Cookie names to intercept")
	rootCmd.Flags().IntVarP(&port, "port", "p", 8080, "Proxy port")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Logging level (debug, info, warn, error)")
	rootCmd.Flags().StringVar(&caCertFile, "ca-cert", "", "CA certificate file path (uses mkcert CA by default)")
	rootCmd.Flags().StringVar(&caKeyFile, "ca-key", "", "CA private key file path (uses mkcert CA by default)")

	rootCmd.MarkFlagRequired("domains")

	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}