package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCookieStore_Store(t *testing.T) {
	store := NewCookieStore()
	
	cookie := &http.Cookie{
		Name:  "session_id",
		Value: "abc123",
	}
	store.Store("example.com", cookie)
	
	cookies := store.Get("example.com")
	if cookies["session_id"] != "abc123" {
		t.Errorf("Expected session_id=abc123, got %s", cookies["session_id"])
	}
}

func TestCookieStore_Get_EmptyDomain(t *testing.T) {
	store := NewCookieStore()
	
	cookies := store.Get("nonexistent.com")
	
	if len(cookies) != 0 {
		t.Errorf("Expected empty cookies for nonexistent domain, got %v", cookies)
	}
}

func TestCookieStore_MultipleCookies(t *testing.T) {
	store := NewCookieStore()
	
	sessionCookie := &http.Cookie{
		Name:  "session_id",
		Value: "abc123",
	}
	authCookie := &http.Cookie{
		Name:  "auth_token",
		Value: "xyz789",
	}
	store.Store("example.com", sessionCookie)
	store.Store("example.com", authCookie)
	
	cookies := store.Get("example.com")
	if len(cookies) != 2 {
		t.Errorf("Expected 2 cookies, got %d", len(cookies))
	}
	if cookies["session_id"] != "abc123" {
		t.Errorf("Expected session_id=abc123, got %s", cookies["session_id"])
	}
	if cookies["auth_token"] != "xyz789" {
		t.Errorf("Expected auth_token=xyz789, got %s", cookies["auth_token"])
	}
}

func TestCookieStore_DomainIsolation(t *testing.T) {
	store := NewCookieStore()
	
	exampleCookie := &http.Cookie{
		Name:  "session_id",
		Value: "abc123",
	}
	otherCookie := &http.Cookie{
		Name:  "session_id",
		Value: "xyz789",
	}
	store.Store("example.com", exampleCookie)
	store.Store("other.com", otherCookie)
	
	exampleCookies := store.Get("example.com")
	otherCookies := store.Get("other.com")
	
	if exampleCookies["session_id"] != "abc123" {
		t.Errorf("Expected example.com session_id=abc123, got %s", exampleCookies["session_id"])
	}
	if otherCookies["session_id"] != "xyz789" {
		t.Errorf("Expected other.com session_id=xyz789, got %s", otherCookies["session_id"])
	}
}

func TestCookieStore_Clear(t *testing.T) {
	store := NewCookieStore()
	
	sessionCookie := &http.Cookie{
		Name:  "session_id",
		Value: "abc123",
	}
	authCookie := &http.Cookie{
		Name:  "auth_token",
		Value: "xyz789",
	}
	store.Store("example.com", sessionCookie)
	store.Store("example.com", authCookie)
	
	store.Clear("example.com")
	
	cookies := store.Get("example.com")
	if len(cookies) != 0 {
		t.Errorf("Expected no cookies after clear, got %v", cookies)
	}
}

func TestCookieStore_ConcurrentAccess(t *testing.T) {
	store := NewCookieStore()
	wg := sync.WaitGroup{}
	
	// Test concurrent writes
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cookie := &http.Cookie{
				Name:  "session_id",
				Value: "value",
			}
			store.Store("example.com", cookie)
			store.Get("example.com")
		}(i)
	}
	
	wg.Wait()
	
	cookies := store.Get("example.com")
	if cookies["session_id"] != "value" {
		t.Errorf("Expected session_id=value after concurrent access, got %s", cookies["session_id"])
	}
}

func TestCookieStore_ExplicitExpires(t *testing.T) {
	store := NewCookieStore()
	
	// Create cookie that expires in 1 hour
	futureTime := time.Now().Add(time.Hour)
	cookie := &http.Cookie{
		Name:    "session_id",
		Value:   "abc123",
		Expires: futureTime,
	}
	store.Store("example.com", cookie)
	
	// Should be available now
	cookies := store.Get("example.com")
	if cookies["session_id"] != "abc123" {
		t.Errorf("Expected session_id=abc123, got %s", cookies["session_id"])
	}
	
	// Create cookie that already expired
	pastTime := time.Now().Add(-time.Hour)
	expiredCookie := &http.Cookie{
		Name:    "expired_cookie",
		Value:   "should_not_appear",
		Expires: pastTime,
	}
	store.Store("example.com", expiredCookie)
	
	// Should only get the non-expired cookie
	cookies = store.Get("example.com")
	if len(cookies) != 1 {
		t.Errorf("Expected 1 cookie after storing expired cookie, got %d", len(cookies))
	}
	if cookies["session_id"] != "abc123" {
		t.Errorf("Expected session_id=abc123, got %s", cookies["session_id"])
	}
	if _, exists := cookies["expired_cookie"]; exists {
		t.Error("Expected expired cookie to be cleaned up, but it still exists")
	}
}

func TestCookieStore_MaxAge(t *testing.T) {
	store := NewCookieStore()
	
	// Create cookie with MaxAge
	cookie := &http.Cookie{
		Name:   "session_id",
		Value:  "abc123",
		MaxAge: 3600, // 1 hour
	}
	store.Store("example.com", cookie)
	
	// Should be available now
	cookies := store.Get("example.com")
	if cookies["session_id"] != "abc123" {
		t.Errorf("Expected session_id=abc123, got %s", cookies["session_id"])
	}
	
	// Create cookie with negative MaxAge (should be treated as expired)
	expiredCookie := &http.Cookie{
		Name:   "expired_cookie",
		Value:  "should_not_appear",
		MaxAge: -1,
	}
	store.Store("example.com", expiredCookie)
	
	// Should only get the non-expired cookie
	cookies = store.Get("example.com")
	if len(cookies) != 1 {
		t.Errorf("Expected 1 cookie after storing expired cookie, got %d", len(cookies))
	}
	if cookies["session_id"] != "abc123" {
		t.Errorf("Expected session_id=abc123, got %s", cookies["session_id"])
	}
}

func TestCookieStore_DefaultExpiry(t *testing.T) {
	store := NewCookieStore()
	
	// Create cookie without expiration (should get default 1 hour)
	cookie := &http.Cookie{
		Name:  "session_id",
		Value: "abc123",
	}
	store.Store("example.com", cookie)
	
	// Should be available now
	cookies := store.Get("example.com")
	if cookies["session_id"] != "abc123" {
		t.Errorf("Expected session_id=abc123, got %s", cookies["session_id"])
	}
	
	// Verify the cookie got an expiration time set (should be ~1 hour from now)
	storedCookies := store.cookies["example.com"]
	if storedCookies == nil || storedCookies["session_id"] == nil {
		t.Fatal("Expected stored cookie to exist")
	}
	
	storedCookie := storedCookies["session_id"]
	if storedCookie.Expires.IsZero() {
		t.Error("Expected default expiration to be set, but Expires is zero")
	}
	
	// Should expire roughly 1 hour from now (give or take a few seconds for test execution)
	expectedExpiry := time.Now().Add(time.Hour)
	if storedCookie.Expires.Before(expectedExpiry.Add(-10*time.Second)) || 
	   storedCookie.Expires.After(expectedExpiry.Add(10*time.Second)) {
		t.Errorf("Expected expiry around %v, got %v", expectedExpiry, storedCookie.Expires)
	}
}

func TestCookieStore_LazyCleanup(t *testing.T) {
	store := NewCookieStore()
	
	// Store a valid cookie
	validCookie := &http.Cookie{
		Name:    "valid_cookie",
		Value:   "should_remain",
		Expires: time.Now().Add(time.Hour),
	}
	store.Store("example.com", validCookie)
	
	// Manually insert an expired cookie (simulate time passing)
	expiredCookie := &http.Cookie{
		Name:    "expired_cookie",
		Value:   "should_be_removed",
		Expires: time.Now().Add(-time.Hour),
	}
	store.mu.Lock()
	if store.cookies["example.com"] == nil {
		store.cookies["example.com"] = make(map[string]*http.Cookie)
	}
	store.cookies["example.com"]["expired_cookie"] = expiredCookie
	store.mu.Unlock()
	
	// Verify both cookies exist in storage before cleanup
	store.mu.RLock()
	storedCount := len(store.cookies["example.com"])
	store.mu.RUnlock()
	if storedCount != 2 {
		t.Fatalf("Expected 2 cookies in storage before cleanup, got %d", storedCount)
	}
	
	// Get should trigger lazy cleanup
	cookies := store.Get("example.com")
	
	// Should only return the valid cookie
	if len(cookies) != 1 {
		t.Errorf("Expected 1 cookie after lazy cleanup, got %d", len(cookies))
	}
	if cookies["valid_cookie"] != "should_remain" {
		t.Errorf("Expected valid_cookie=should_remain, got %s", cookies["valid_cookie"])
	}
	if _, exists := cookies["expired_cookie"]; exists {
		t.Error("Expected expired cookie to be removed by lazy cleanup")
	}
	
	// Verify expired cookie was actually removed from storage
	store.mu.RLock()
	storedCount = len(store.cookies["example.com"])
	store.mu.RUnlock()
	if storedCount != 1 {
		t.Errorf("Expected 1 cookie in storage after cleanup, got %d", storedCount)
	}
}

func TestCookieStore_ExpiredNotReturned(t *testing.T) {
	store := NewCookieStore()
	
	// Store cookie that will expire very soon
	almostExpiredCookie := &http.Cookie{
		Name:    "session_id",
		Value:   "abc123",
		Expires: time.Now().Add(50 * time.Millisecond),
	}
	store.Store("example.com", almostExpiredCookie)
	
	// Should be available immediately
	cookies := store.Get("example.com")
	if len(cookies) != 1 {
		t.Errorf("Expected 1 cookie initially, got %d", len(cookies))
	}
	
	// Wait for expiration
	time.Sleep(100 * time.Millisecond)
	
	// Should be gone after expiration
	cookies = store.Get("example.com")
	if len(cookies) != 0 {
		t.Errorf("Expected 0 cookies after expiration, got %d", len(cookies))
	}
}

// Removed redundant tests that primarily test Go's stdlib cookie parsing
// Our value-add is in security filtering and expiration handling, not basic parsing

func TestParseSetCookie_SameSiteStrictSkipped(t *testing.T) {
	ps := &ProxyServer{}
	
	setCookieHeader := "session_id=abc123; SameSite=Strict; Path=/"
	cookie := ps.parseSetCookieWithURL(setCookieHeader, "session_id", &url.URL{Scheme: "https", Host: "example.com"})
	
	if cookie != nil {
		t.Errorf("Expected nil for SameSite=Strict cookie, got %+v", cookie)
	}
}

func TestParseSetCookie_SameSiteLaxAllowed(t *testing.T) {
	ps := &ProxyServer{}
	
	setCookieHeader := "session_id=abc123; SameSite=Lax; Path=/"
	cookie := ps.parseSetCookieWithURL(setCookieHeader, "session_id", &url.URL{Scheme: "https", Host: "example.com"})
	
	if cookie == nil {
		t.Fatal("Expected cookie to be parsed, got nil")
	}
	if cookie.Value != "abc123" {
		t.Errorf("Expected value abc123 for SameSite=Lax cookie, got %s", cookie.Value)
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("Expected SameSite=Lax, got %v", cookie.SameSite)
	}
}

func TestParseSetCookie_SameSiteNoneAllowed(t *testing.T) {
	ps := &ProxyServer{}
	
	setCookieHeader := "session_id=abc123; SameSite=None; Secure; Path=/"
	cookie := ps.parseSetCookieWithURL(setCookieHeader, "session_id", &url.URL{Scheme: "https", Host: "example.com"})
	
	if cookie == nil {
		t.Fatal("Expected cookie to be parsed, got nil")
	}
	if cookie.Value != "abc123" {
		t.Errorf("Expected value abc123 for SameSite=None cookie, got %s", cookie.Value)
	}
	if cookie.SameSite != http.SameSiteNoneMode {
		t.Errorf("Expected SameSite=None, got %v", cookie.SameSite)
	}
	if !cookie.Secure {
		t.Error("Expected Secure flag to be true")
	}
}

func TestParseSetCookieWithURL_SecureCookieHTTPS(t *testing.T) {
	ps := &ProxyServer{}
	httpsURL := &url.URL{Scheme: "https", Host: "example.com"}
	
	setCookieHeader := "session_id=abc123; Secure; Path=/"
	cookie := ps.parseSetCookieWithURL(setCookieHeader, "session_id", httpsURL)
	
	if cookie == nil {
		t.Fatal("Expected cookie to be parsed, got nil")
	}
	if cookie.Value != "abc123" {
		t.Errorf("Expected value abc123 for Secure cookie over HTTPS, got %s", cookie.Value)
	}
	if !cookie.Secure {
		t.Error("Expected Secure flag to be true")
	}
}

func TestParseSetCookieWithURL_SecureCookieHTTPSkipped(t *testing.T) {
	ps := &ProxyServer{}
	httpURL := &url.URL{Scheme: "http", Host: "example.com"}
	
	setCookieHeader := "session_id=abc123; Secure; Path=/"
	cookie := ps.parseSetCookieWithURL(setCookieHeader, "session_id", httpURL)
	
	if cookie != nil {
		t.Errorf("Expected nil for Secure cookie over HTTP, got %+v", cookie)
	}
}

func TestParseSetCookieWithURL_NonSecureCookieHTTP(t *testing.T) {
	ps := &ProxyServer{}
	httpURL := &url.URL{Scheme: "http", Host: "example.com"}
	
	setCookieHeader := "session_id=abc123; Path=/"
	cookie := ps.parseSetCookieWithURL(setCookieHeader, "session_id", httpURL)
	
	if cookie == nil {
		t.Fatal("Expected cookie to be parsed, got nil")
	}
	if cookie.Value != "abc123" {
		t.Errorf("Expected value abc123 for non-Secure cookie over HTTP, got %s", cookie.Value)
	}
	if cookie.Secure {
		t.Error("Expected Secure flag to be false")
	}
}

func TestIsTargetDomain(t *testing.T) {
	domains := []string{"api.example.com", "auth.example.com"}
	ps := &ProxyServer{domains: domains}
	
	testCases := []struct {
		host     string
		expected bool
	}{
		{"api.example.com", true},
		{"auth.example.com", true},
		{"other.example.com", false},
		{"example.com", false},
		{"", false},
	}
	
	for _, tc := range testCases {
		result := ps.isTargetDomain(tc.host)
		if result != tc.expected {
			t.Errorf("isTargetDomain(%s): expected %v, got %v", tc.host, tc.expected, result)
		}
	}
}

func TestGeneratePACConditions(t *testing.T) {
	domains := []string{"api.example.com", "auth.example.com"}
	ps := &ProxyServer{domains: domains, port: 8080}
	
	conditions := ps.generatePACConditions()
	
	expectedParts := []string{
		`if (host === "api.example.com")`,
		`return "PROXY localhost:8080"`,
		`if (host === "auth.example.com")`,
	}
	
	for _, part := range expectedParts {
		if !strings.Contains(conditions, part) {
			t.Errorf("Expected PAC conditions to contain '%s', got: %s", part, conditions)
		}
	}
}

func TestServePAC(t *testing.T) {
	domains := []string{"api.example.com"}
	ps := &ProxyServer{domains: domains, port: 8080}
	
	req := httptest.NewRequest("GET", "/proxy.pac", nil)
	w := httptest.NewRecorder()
	
	ps.servePAC(w, req)
	
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
	
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/x-ns-proxy-autoconfig" {
		t.Errorf("Expected Content-Type application/x-ns-proxy-autoconfig, got %s", contentType)
	}
	
	body := w.Body.String()
	expectedParts := []string{
		"function FindProxyForURL(url, host)",
		`if (host === "api.example.com")`,
		`return "PROXY localhost:8080"`,
		`return "DIRECT"`,
	}
	
	for _, part := range expectedParts {
		if !strings.Contains(body, part) {
			t.Errorf("Expected PAC file to contain '%s', got: %s", part, body)
		}
	}
}

func TestServePAC_MultipleDomains(t *testing.T) {
	domains := []string{"api.example.com", "auth.example.com"}
	ps := &ProxyServer{domains: domains, port: 9090}
	
	req := httptest.NewRequest("GET", "/proxy.pac", nil)
	w := httptest.NewRecorder()
	
	ps.servePAC(w, req)
	
	body := w.Body.String()
	
	if !strings.Contains(body, "api.example.com") {
		t.Error("Expected PAC file to contain api.example.com")
	}
	if !strings.Contains(body, "auth.example.com") {
		t.Error("Expected PAC file to contain auth.example.com")
	}
	if !strings.Contains(body, "localhost:9090") {
		t.Error("Expected PAC file to contain custom port 9090")
	}
}