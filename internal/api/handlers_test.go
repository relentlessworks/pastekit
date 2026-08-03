package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/relentlessworks/pastekit/internal/auth"
	"github.com/relentlessworks/pastekit/internal/config"
	"github.com/relentlessworks/pastekit/internal/model"
	"github.com/relentlessworks/pastekit/internal/store"
)

// testSetup creates a handler with an in-memory store for testing.
func testSetup(t *testing.T) (*Handler, *store.Store) {
	t.Helper()
	s, err := store.New(fmt.Sprintf("/tmp/pastekit_test_%d.json", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	cfg := &config.Config{
		Addr:      ":0",
		DBPath:    "test.json",
		Secret:    "test-secret",
		SMTPHost:  "", // OTP will be logged to stderr
		FromEmail: "test@pastekit.local",
	}
	a := auth.New(cfg, s)
	h := New(cfg, s, a)
	return h, s
}

// cleanup removes the test database file.
func cleanup(s *store.Store) {
	// The store doesn't expose the file path, but the test files are in /tmp
}

// getTestToken creates a token for testing by going through the OTP flow.
func getTestToken(t *testing.T, h *Handler, email string) string {
	t.Helper()
	// Request OTP
	form := url.Values{"email": {email}}
	req := httptest.NewRequest("POST", "/auth/request", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.requestOTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("OTP request failed: %d %s", w.Code, w.Body.String())
	}

	// Get the OTP from the store
	s := h.store
	otpReq, err := s.GetOTP(email)
	if err != nil {
		t.Fatalf("Failed to get OTP: %v", err)
	}

	// Verify OTP
	form = url.Values{"email": {email}, "code": {otpReq.Code}}
	req = httptest.NewRequest("POST", "/auth/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.verifyOTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("OTP verify failed: %d %s", w.Code, w.Body.String())
	}

	// Extract token from response
	body := w.Body.String()
	// Parse "token=xxx" from plain text response
	parts := strings.Fields(body)
	for _, p := range parts {
		if strings.HasPrefix(p, "token=") {
			return strings.TrimPrefix(p, "token=")
		}
	}
	t.Fatalf("Failed to extract token from response: %s", body)
	return ""
}

func TestHealth(t *testing.T) {
	h, _ := testSetup(t)
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	h.health(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "ok\n" {
		t.Errorf("expected 'ok', got '%s'", w.Body.String())
	}
}

func TestHelp(t *testing.T) {
	h, _ := testSetup(t)
	req := httptest.NewRequest("GET", "/help", nil)
	w := httptest.NewRecorder()
	h.help(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "pastekit") {
		t.Errorf("help should mention pastekit")
	}
	if !strings.Contains(body, "POST /pastes") {
		t.Errorf("help should mention POST /pastes")
	}
	if !strings.Contains(body, "AUTH") {
		t.Errorf("help should mention AUTH")
	}
}

func TestAuthRequestOTP(t *testing.T) {
	h, _ := testSetup(t)
	form := url.Values{"email": {"test@example.com"}}
	req := httptest.NewRequest("POST", "/auth/request", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.requestOTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "otp sent") {
		t.Errorf("expected 'otp sent' in response, got: %s", w.Body.String())
	}
}

func TestAuthRequestOTPMissingEmail(t *testing.T) {
	h, _ := testSetup(t)
	req := httptest.NewRequest("POST", "/auth/request", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.requestOTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAuthVerifyOTP(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")
	if token == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestAuthVerifyOTPInvalidCode(t *testing.T) {
	h, _ := testSetup(t)
	// First request OTP
	form := url.Values{"email": {"test@example.com"}}
	req := httptest.NewRequest("POST", "/auth/request", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.requestOTP(w, req)

	// Try to verify with wrong code
	form = url.Values{"email": {"test@example.com"}, "code": {"000000"}}
	req = httptest.NewRequest("POST", "/auth/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.verifyOTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuthVerifyOTPNoRequest(t *testing.T) {
	h, _ := testSetup(t)
	form := url.Values{"email": {"new@example.com"}, "code": {"123456"}}
	req := httptest.NewRequest("POST", "/auth/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.verifyOTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCreatePaste(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	form := url.Values{
		"content":    {"Hello, world!"},
		"title":      {"Test Paste"},
		"language":   {"text"},
		"visibility": {"public"},
	}
	req := httptest.NewRequest("POST", "/pastes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.pastes(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "handle=paste_") {
		t.Errorf("expected handle in response, got: %s", body)
	}
}

func TestCreatePasteMissingContent(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	form := url.Values{"title": {"No Content"}}
	req := httptest.NewRequest("POST", "/pastes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.pastes(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCreatePasteNoAuth(t *testing.T) {
	h, _ := testSetup(t)
	form := url.Values{"content": {"test"}}
	req := httptest.NewRequest("POST", "/pastes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.pastes(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCreatePasteInvalidVisibility(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	form := url.Values{
		"content":    {"test"},
		"visibility": {"invalid"},
	}
	req := httptest.NewRequest("POST", "/pastes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.pastes(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCreatePasteWithTTL(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	form := url.Values{
		"content": {"temporary"},
		"ttl":     {"1h"},
	}
	req := httptest.NewRequest("POST", "/pastes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.pastes(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreatePasteInvalidTTL(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	form := url.Values{
		"content": {"test"},
		"ttl":     {"invalid"},
	}
	req := httptest.NewRequest("POST", "/pastes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.pastes(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestListPastes(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	// Create a paste first
	form := url.Values{"content": {"test content"}, "title": {"Test"}}
	req := httptest.NewRequest("POST", "/pastes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.pastes(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	// List pastes
	req = httptest.NewRequest("GET", "/pastes", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.pastes(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "handle=paste_") {
		t.Errorf("expected paste handle in list, got: %s", body)
	}
}

func TestListPastesEmpty(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	req := httptest.NewRequest("GET", "/pastes", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.pastes(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "no pastes") {
		t.Errorf("expected 'no pastes' message, got: %s", body)
	}
}

func TestGetPaste(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	// Create a paste
	form := url.Values{"content": {"Hello, paste!"}, "visibility": {"public"}}
	req := httptest.NewRequest("POST", "/pastes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.pastes(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	// Extract handle
	body := w.Body.String()
	handle := ""
	for _, p := range strings.Fields(body) {
		if strings.HasPrefix(p, "handle=") {
			handle = strings.TrimPrefix(p, "handle=")
			break
		}
	}
	if handle == "" {
		t.Fatalf("failed to extract handle from: %s", body)
	}

	// Get the paste (public, no auth needed)
	req = httptest.NewRequest("GET", "/pastes/"+handle, nil)
	w = httptest.NewRecorder()
	h.pasteByHandle(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "Hello, paste!" {
		t.Errorf("expected 'Hello, paste!', got: '%s'", w.Body.String())
	}
}

func TestGetPasteJSON(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	// Create a paste
	form := url.Values{"content": {"JSON test"}, "visibility": {"public"}}
	req := httptest.NewRequest("POST", "/pastes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.pastes(w, req)
	body := w.Body.String()
	handle := ""
	for _, p := range strings.Fields(body) {
		if strings.HasPrefix(p, "handle=") {
			handle = strings.TrimPrefix(p, "handle=")
			break
		}
	}

	// Get as JSON
	req = httptest.NewRequest("GET", "/pastes/"+handle, nil)
	req.Header.Set("Accept", "application/json")
	w = httptest.NewRecorder()
	h.pasteByHandle(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var p model.Paste
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Errorf("failed to parse JSON: %v", err)
	}
	if p.Content != "JSON test" {
		t.Errorf("expected 'JSON test', got '%s'", p.Content)
	}
}

func TestGetPasteNotFound(t *testing.T) {
	h, _ := testSetup(t)
	req := httptest.NewRequest("GET", "/pastes/paste_nonexist", nil)
	w := httptest.NewRecorder()
	h.pasteByHandle(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestUpdatePaste(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	// Create a paste
	form := url.Values{"content": {"original"}, "visibility": {"public"}}
	req := httptest.NewRequest("POST", "/pastes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.pastes(w, req)
	body := w.Body.String()
	handle := ""
	for _, p := range strings.Fields(body) {
		if strings.HasPrefix(p, "handle=") {
			handle = strings.TrimPrefix(p, "handle=")
			break
		}
	}

	// Update the paste
	form = url.Values{"content": {"updated content"}, "title": {"New Title"}}
	req = httptest.NewRequest("PATCH", "/pastes/"+handle, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.pasteByHandle(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify content was updated
	req = httptest.NewRequest("GET", "/pastes/"+handle, nil)
	w = httptest.NewRecorder()
	h.pasteByHandle(w, req)
	if w.Body.String() != "updated content" {
		t.Errorf("expected 'updated content', got: '%s'", w.Body.String())
	}
}

func TestDeletePaste(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	// Create a paste
	form := url.Values{"content": {"to be deleted"}, "visibility": {"public"}}
	req := httptest.NewRequest("POST", "/pastes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.pastes(w, req)
	body := w.Body.String()
	handle := ""
	for _, p := range strings.Fields(body) {
		if strings.HasPrefix(p, "handle=") {
			handle = strings.TrimPrefix(p, "handle=")
			break
		}
	}

	// Delete the paste
	req = httptest.NewRequest("DELETE", "/pastes/"+handle, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.pasteByHandle(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Verify it's gone
	req = httptest.NewRequest("GET", "/pastes/"+handle, nil)
	w = httptest.NewRecorder()
	h.pasteByHandle(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 after delete, got %d", w.Code)
	}
}

func TestGetWorkspace(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	// Create a paste first to auto-create workspace
	form := url.Values{"content": {"test"}}
	req := httptest.NewRequest("POST", "/pastes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.pastes(w, req)

	// Get workspace
	req = httptest.NewRequest("GET", "/workspace", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.workspace(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "handle=ws_") {
		t.Errorf("expected workspace handle, got: %s", body)
	}
}

func TestAuditLog(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	// Create a paste to generate audit entry
	form := url.Values{"content": {"test"}}
	req := httptest.NewRequest("POST", "/pastes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.pastes(w, req)

	// Get audit log
	req = httptest.NewRequest("GET", "/audit", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.audit(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "paste.create") {
		t.Errorf("expected 'paste.create' in audit, got: %s", body)
	}
}

func TestMCPInitialize(t *testing.T) {
	h, _ := testSetup(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.mcp(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Errorf("failed to parse JSON: %v", err)
	}
	if resp["jsonrpc"] != "2.0" {
		t.Errorf("expected jsonrpc 2.0")
	}
}

func TestMCPToolsList(t *testing.T) {
	h, _ := testSetup(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.mcp(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Errorf("failed to parse JSON: %v", err)
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatal("expected result in response")
	}
	tools, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatal("expected tools array")
	}
	if len(tools) < 4 {
		t.Errorf("expected at least 4 tools, got %d", len(tools))
	}
}

func TestMCPCreatePaste(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_paste","arguments":{"content":"MCP test"}}}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.mcp(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Errorf("failed to parse JSON: %v", err)
	}
	if _, ok := resp["result"]; !ok {
		t.Errorf("expected result in response, got: %v", resp)
	}
}

func TestMCPGetPaste(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	// Create a paste via MCP
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_paste","arguments":{"content":"MCP get test"}}}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.mcp(w, req)

	// Extract handle from response
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	result := resp["result"].(map[string]interface{})
	content := result["content"].([]interface{})[0].(map[string]interface{})
	text := content["text"].(string)
	handle := ""
	for _, p := range strings.Fields(text) {
		if strings.HasPrefix(p, "handle=") {
			handle = strings.TrimPrefix(p, "handle=")
			break
		}
	}
	if handle == "" {
		t.Fatalf("failed to extract handle from: %s", text)
	}

	// Get the paste via MCP
	body = fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_paste","arguments":{"handle":"%s"}}}`, handle)
	req = httptest.NewRequest("POST", "/mcp", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.mcp(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	result = resp["result"].(map[string]interface{})
	content = result["content"].([]interface{})[0].(map[string]interface{})
	text = content["text"].(string)
	if text != "MCP get test" {
		t.Errorf("expected 'MCP get test', got '%s'", text)
	}
}

func TestMCPListPastes(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	// Create a paste first
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_paste","arguments":{"content":"list test"}}}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.mcp(w, req)

	// List pastes
	body = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_pastes","arguments":{}}}`
	req = httptest.NewRequest("POST", "/mcp", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.mcp(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	result := resp["result"].(map[string]interface{})
	content := result["content"].([]interface{})[0].(map[string]interface{})
	text := content["text"].(string)
	if !strings.Contains(text, "handle=paste_") {
		t.Errorf("expected paste handle in list, got: %s", text)
	}
}

func TestMCPDeletePaste(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	// Create a paste
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_paste","arguments":{"content":"delete me"}}}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.mcp(w, req)

	// Extract handle
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	result := resp["result"].(map[string]interface{})
	content := result["content"].([]interface{})[0].(map[string]interface{})
	text := content["text"].(string)
	handle := ""
	for _, p := range strings.Fields(text) {
		if strings.HasPrefix(p, "handle=") {
			handle = strings.TrimPrefix(p, "handle=")
			break
		}
	}

	// Delete via MCP
	body = fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_paste","arguments":{"handle":"%s"}}}`, handle)
	req = httptest.NewRequest("POST", "/mcp", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.mcp(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	result = resp["result"].(map[string]interface{})
	content = result["content"].([]interface{})[0].(map[string]interface{})
	text = content["text"].(string)
	if !strings.Contains(text, "Deleted") {
		t.Errorf("expected 'Deleted' in response, got: %s", text)
	}
}

func TestPrivatePasteRequiresAuth(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	// Create a private paste
	form := url.Values{"content": {"secret"}, "visibility": {"private"}}
	req := httptest.NewRequest("POST", "/pastes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.pastes(w, req)
	body := w.Body.String()
	handle := ""
	for _, p := range strings.Fields(body) {
		if strings.HasPrefix(p, "handle=") {
			handle = strings.TrimPrefix(p, "handle=")
			break
		}
	}

	// Try to get without auth
	req = httptest.NewRequest("GET", "/pastes/"+handle, nil)
	w = httptest.NewRecorder()
	h.pasteByHandle(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for private paste without auth, got %d", w.Code)
	}
}

func TestPrivatePasteWithAuth(t *testing.T) {
	h, _ := testSetup(t)
	token := getTestToken(t, h, "test@example.com")

	// Create a private paste
	form := url.Values{"content": {"my secret"}, "visibility": {"private"}}
	req := httptest.NewRequest("POST", "/pastes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.pastes(w, req)
	body := w.Body.String()
	handle := ""
	for _, p := range strings.Fields(body) {
		if strings.HasPrefix(p, "handle=") {
			handle = strings.TrimPrefix(p, "handle=")
			break
		}
	}

	// Get with auth
	req = httptest.NewRequest("GET", "/pastes/"+handle, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.pasteByHandle(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "my secret" {
		t.Errorf("expected 'my secret', got: '%s'", w.Body.String())
	}
}

func TestInvalidToken(t *testing.T) {
	h, _ := testSetup(t)
	req := httptest.NewRequest("GET", "/pastes", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken123")
	w := httptest.NewRecorder()
	h.pastes(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestErrorFormat(t *testing.T) {
	h, _ := testSetup(t)
	req := httptest.NewRequest("GET", "/pastes", nil)
	w := httptest.NewRecorder()
	h.pastes(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "error:") {
		t.Errorf("expected 'error:' in response, got: %s", body)
	}
	if !strings.Contains(body, "hint:") {
		t.Errorf("expected 'hint:' in response, got: %s", body)
	}
}

func TestErrorFormatJSON(t *testing.T) {
	h, _ := testSetup(t)
	req := httptest.NewRequest("GET", "/pastes", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	h.pastes(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Errorf("failed to parse JSON: %v", err)
	}
	if _, ok := resp["error"]; !ok {
		t.Errorf("expected 'error' key in JSON")
	}
	if _, ok := resp["hint"]; !ok {
		t.Errorf("expected 'hint' key in JSON")
	}
}

func TestParseTTL(t *testing.T) {
	tests := []struct {
		ttl   string
		valid bool
	}{
		{"1h", true},
		{"24h", true},
		{"7d", true},
		{"30d", true},
		{"", true}, // empty = no expiry
		{"invalid", false},
		{"5x", false},
	}

	for _, tt := range tests {
		expiry, err := model.ParseTTL(tt.ttl)
		if tt.valid {
			if err != nil {
				t.Errorf("ParseTTL(%q) unexpected error: %v", tt.ttl, err)
			}
			if tt.ttl != "" && expiry == nil {
				t.Errorf("ParseTTL(%q) expected non-nil expiry", tt.ttl)
			}
			if tt.ttl == "" && expiry != nil {
				t.Errorf("ParseTTL(%q) expected nil expiry", tt.ttl)
			}
		} else {
			if err == nil {
				t.Errorf("ParseTTL(%q) expected error, got nil", tt.ttl)
			}
		}
	}
}

func TestHandleGeneration(t *testing.T) {
	h1 := model.NewPasteHandle()
	h2 := model.NewPasteHandle()
	if h1 == h2 {
		t.Error("expected different handles")
	}
	if !strings.HasPrefix(h1, "paste_") {
		t.Errorf("expected 'paste_' prefix, got: %s", h1)
	}
	if len(h1) != len("paste_") + 5 {
		t.Errorf("expected handle length %d, got %d", len("paste_")+5, len(h1))
	}

	ws1 := model.NewWorkspaceHandle()
	if !strings.HasPrefix(ws1, "ws_") {
		t.Errorf("expected 'ws_' prefix, got: %s", ws1)
	}
}

func TestPasteExpiry(t *testing.T) {
	// Create an expired paste
	past := time.Now().Add(-1 * time.Hour)
	p := &model.Paste{
		ExpiresAt: &past,
	}
	if !p.IsExpired() {
		t.Error("expected paste to be expired")
	}

	// Non-expired paste
	future := time.Now().Add(1 * time.Hour)
	p2 := &model.Paste{
		ExpiresAt: &future,
	}
	if p2.IsExpired() {
		t.Error("expected paste to not be expired")
	}

	// No expiry
	p3 := &model.Paste{}
	if p3.IsExpired() {
		t.Error("expected paste with no expiry to not be expired")
	}
}
