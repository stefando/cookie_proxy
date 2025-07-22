package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestCookieStore_StoreCookie(t *testing.T) {
	store := NewCookieStore()
	
	store.StoreCookie("example.com", "session_id", "abc123")
	
	cookies := store.GetCookies("example.com")
	if cookies["session_id"] != "abc123" {
		t.Errorf("Expected session_id=abc123, got %s", cookies["session_id"])
	}
}

func TestCookieStore_GetCookies_EmptyDomain(t *testing.T) {
	store := NewCookieStore()
	
	cookies := store.GetCookies("nonexistent.com")
	
	if len(cookies) != 0 {
		t.Errorf("Expected empty cookies for nonexistent domain, got %v", cookies)
	}
}

func TestCookieStore_MultipleCookies(t *testing.T) {
	store := NewCookieStore()
	
	store.StoreCookie("example.com", "session_id", "abc123")
	store.StoreCookie("example.com", "auth_token", "xyz789")
	
	cookies := store.GetCookies("example.com")
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
	
	store.StoreCookie("example.com", "session_id", "abc123")
	store.StoreCookie("other.com", "session_id", "xyz789")
	
	exampleCookies := store.GetCookies("example.com")
	otherCookies := store.GetCookies("other.com")
	
	if exampleCookies["session_id"] != "abc123" {
		t.Errorf("Expected example.com session_id=abc123, got %s", exampleCookies["session_id"])
	}
	if otherCookies["session_id"] != "xyz789" {
		t.Errorf("Expected other.com session_id=xyz789, got %s", otherCookies["session_id"])
	}
}

func TestCookieStore_ClearCookies(t *testing.T) {
	store := NewCookieStore()
	
	store.StoreCookie("example.com", "session_id", "abc123")
	store.StoreCookie("example.com", "auth_token", "xyz789")
	
	store.ClearCookies("example.com")
	
	cookies := store.GetCookies("example.com")
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
			store.StoreCookie("example.com", "session_id", "value")
			store.GetCookies("example.com")
		}(i)
	}
	
	wg.Wait()
	
	cookies := store.GetCookies("example.com")
	if cookies["session_id"] != "value" {
		t.Errorf("Expected session_id=value after concurrent access, got %s", cookies["session_id"])
	}
}

func TestExtractCookieValue_ValidCookie(t *testing.T) {
	ps := &ProxyServer{}
	
	setCookieHeader := "session_id=abc123; Path=/; HttpOnly"
	value := ps.extractCookieValue(setCookieHeader, "session_id")
	
	if value != "abc123" {
		t.Errorf("Expected abc123, got %s", value)
	}
}

func TestExtractCookieValue_CookieWithSpaces(t *testing.T) {
	ps := &ProxyServer{}
	
	setCookieHeader := " session_id = abc123 ; Path=/; HttpOnly"
	value := ps.extractCookieValue(setCookieHeader, "session_id")
	
	if value != "abc123" {
		t.Errorf("Expected abc123, got %s", value)
	}
}

func TestExtractCookieValue_WrongCookieName(t *testing.T) {
	ps := &ProxyServer{}
	
	setCookieHeader := "other_cookie=abc123; Path=/; HttpOnly"
	value := ps.extractCookieValue(setCookieHeader, "session_id")
	
	if value != "" {
		t.Errorf("Expected empty string for wrong cookie name, got %s", value)
	}
}

func TestExtractCookieValue_MalformedHeader(t *testing.T) {
	ps := &ProxyServer{}
	
	testCases := []string{
		"",
		"session_id",
		"=abc123",
		"session_id=",
	}
	
	for _, header := range testCases {
		value := ps.extractCookieValue(header, "session_id")
		if header == "session_id=" && value != "" {
			t.Errorf("Expected empty string for malformed header '%s', got %s", header, value)
		}
		if header == "session_id" && value != "" {
			t.Errorf("Expected empty string for malformed header '%s', got %s", header, value)
		}
	}
}

func TestExtractCookieValue_ComplexValue(t *testing.T) {
	ps := &ProxyServer{}
	
	setCookieHeader := "session_id=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0; Path=/; Secure"
	value := ps.extractCookieValue(setCookieHeader, "session_id")
	
	expected := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0"
	if value != expected {
		t.Errorf("Expected %s, got %s", expected, value)
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