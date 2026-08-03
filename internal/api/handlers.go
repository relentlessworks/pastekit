package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/relentlessworks/pastekit/internal/auth"
	"github.com/relentlessworks/pastekit/internal/config"
	"github.com/relentlessworks/pastekit/internal/model"
	"github.com/relentlessworks/pastekit/internal/store"
)

// Handler holds dependencies for HTTP handlers.
type Handler struct {
	cfg   *config.Config
	store *store.Store
	auth  *auth.Auth
}

// New creates a new Handler.
func New(cfg *config.Config, s *store.Store, a *auth.Auth) *Handler {
	return &Handler{cfg: cfg, store: s, auth: a}
}

// Routes returns the HTTP mux with all routes registered.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/health", h.health)

	// Help / agent documentation
	mux.HandleFunc("/help", h.help)
	mux.HandleFunc("/.well-known/agent.md", h.help)

	// Auth routes
	mux.HandleFunc("/auth/request", h.requestOTP)
	mux.HandleFunc("/auth/verify", h.verifyOTP)

	// Paste routes (auth required)
	mux.HandleFunc("/pastes", h.pastes)
	mux.HandleFunc("/pastes/", h.pasteByHandle)

	// Workspace routes
	mux.HandleFunc("/workspace", h.workspace)

	// Audit log
	mux.HandleFunc("/audit", h.audit)

	// MCP endpoint
	mux.HandleFunc("/mcp", h.mcp)

	return corsMiddleware(loggingMiddleware(mux))
}

// health returns a simple health check.
func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	writeText(w, http.StatusOK, "ok")
}

// help returns the operating manual for agents.
func (h *Handler) help(w http.ResponseWriter, r *http.Request) {
	manual := `pastekit — agentic-first pastebin service

Share text snippets, code, logs, and configs. Get a short handle back.

AUTH:
  1. POST /auth/request  body: email=user@example.com
     → sends 6-digit OTP to email (or logs to stderr if no SMTP)
  2. POST /auth/verify   body: email=user@example.com code=123456
     → returns: token=<long-lived-bearer-token>
  3. Use Authorization: Bearer <token> for all other endpoints

PASTES:
  POST /pastes          Create a paste
    body: content=<text>  title=<optional>  language=<optional>  visibility=<public|unlisted|private>  ttl=<1h|24h|7d|30d>
    → returns: handle=paste_abc12 created=2026-01-01T00:00:00Z
  GET  /pastes           List pastes in your workspace
    → one line per paste: handle=paste_abc12 title=... language=... visibility=... created=...
  GET  /pastes/<handle>   Get a paste
    → returns content as text/plain (or JSON with Accept: application/json)
  PATCH /pastes/<handle>  Update a paste (title, content, language, visibility)
  DELETE /pastes/<handle> Delete a paste

WORKSPACE:
  GET /workspace         Get your workspace info
  PATCH /workspace        Update workspace (name, plan)

AUDIT:
  GET /audit              List recent audit entries (query: ?limit=20)

MCP:
  POST /mcp               Model Context Protocol endpoint

FORMATS:
  Plain text by default (one record per line, key=value pairs)
  JSON: send Accept: application/json or ?format=json

ERRORS:
  error: <message> | hint: <what to do next>

VISIBILITY:
  public    — anyone with the handle can view (no auth needed)
  unlisted  — anyone with the handle can view (no auth, not listed)
  private   — only the workspace owner can view (auth required)

TTL:
  1h, 24h, 7d, 30d — paste auto-deletes after this duration
  empty — no expiry (permanent until deleted)
`
	writeText(w, http.StatusOK, manual)
}

// requestOTP handles POST /auth/request.
func (h *Handler) requestOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use POST")
		return
	}
	email, err := parseFormValue(r, "email")
	if err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error(), "provide email field in form body, e.g. email=user@example.com")
		return
	}
	if err := h.auth.RequestOTP(email); err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to send OTP", "check SMTP config or try again")
		return
	}
	writeText(w, http.StatusOK, fmt.Sprintf("otp sent to %s | hint: check your email for a 6-digit code, then call POST /auth/verify with email and code", email))
}

// verifyOTP handles POST /auth/verify.
func (h *Handler) verifyOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use POST")
		return
	}
	email, err := parseFormValue(r, "email")
	if err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error(), "provide email field in form body")
		return
	}
	code, err := parseFormValue(r, "code")
	if err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error(), "provide code field in form body (6-digit OTP code)")
		return
	}
	tok, err := h.auth.VerifyOTP(email, code)
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, err.Error(), "request a new OTP via POST /auth/request")
		return
	}
	writeRecord(w, r, http.StatusOK,
		fmt.Sprintf("token=%s workspace=auto email=%s expires=%s", tok.Token, tok.Email, tok.ExpiresAt.Format(time.RFC3339)),
		map[string]interface{}{
			"token":     tok.Token,
			"email":     tok.Email,
			"expires_at": tok.ExpiresAt.Format(time.RFC3339),
		},
	)
}

// pastes handles POST /pastes (create) and GET /pastes (list).
func (h *Handler) pastes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.createPaste(w, r)
	case http.MethodGet:
		h.listPastes(w, r)
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use POST to create or GET to list")
	}
}

// createPaste handles POST /pastes.
func (h *Handler) createPaste(w http.ResponseWriter, r *http.Request) {
	h.withWorkspace(func(w http.ResponseWriter, r *http.Request, tok *model.Token, ws *model.Workspace) {
		content, err := parseFormValue(r, "content")
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "missing content", "provide content field in form body with the text to paste")
			return
		}

		title := r.FormValue("title")
		language := r.FormValue("language")
		visibility := r.FormValue("visibility")
		if visibility == "" {
			visibility = "unlisted"
		}
		if visibility != "public" && visibility != "unlisted" && visibility != "private" {
			writeError(w, r, http.StatusBadRequest, "invalid visibility", "use one of: public, unlisted, private")
			return
		}

		ttl := r.FormValue("ttl")
		var expiresAt *time.Time
		if ttl != "" {
			expiresAt, err = model.ParseTTL(ttl)
			if err != nil {
				writeError(w, r, http.StatusBadRequest, err.Error(), "use formats like 1h, 24h, 7d, 30d")
				return
			}
		}

		p := &model.Paste{
			Handle:     model.NewPasteHandle(),
			Workspace:  ws.Handle,
			Title:      title,
			Content:    content,
			Language:   language,
			Visibility: visibility,
			TTL:        ttl,
			ExpiresAt:  expiresAt,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}

		if err := h.store.CreatePaste(p); err != nil {
			writeError(w, r, http.StatusInternalServerError, "failed to create paste", "try again")
			return
		}

		_ = h.store.AddAudit(&model.AuditEntry{
			Workspace: ws.Handle,
			Action:    "paste.create",
			Detail:     fmt.Sprintf("handle=%s title=%s", p.Handle, p.Title),
			Actor:      tok.Email,
		})

		writeRecord(w, r, http.StatusCreated,
			fmt.Sprintf("handle=%s title=%s language=%s visibility=%s created=%s", p.Handle, p.Title, p.Language, p.Visibility, p.CreatedAt.Format(time.RFC3339)),
			p,
		)
	})(w, r)
}

// listPastes handles GET /pastes.
func (h *Handler) listPastes(w http.ResponseWriter, r *http.Request) {
	h.withWorkspace(func(w http.ResponseWriter, r *http.Request, tok *model.Token, ws *model.Workspace) {
		pastes := h.store.ListPastes(ws.Handle)
		var records []string
		for _, p := range pastes {
			records = append(records, fmt.Sprintf("handle=%s title=%s language=%s visibility=%s created=%s",
				p.Handle, p.Title, p.Language, p.Visibility, p.CreatedAt.Format(time.RFC3339)))
		}
		if len(records) == 0 {
			records = []string{"(no pastes found) | hint: create one with POST /pastes"}
		}
		writeList(w, r, records, pastes)
	})(w, r)
}

// pasteByHandle handles GET/PATCH/DELETE /pastes/<handle>.
func (h *Handler) pasteByHandle(w http.ResponseWriter, r *http.Request) {
	handle := strings.TrimPrefix(r.URL.Path, "/pastes/")
	if handle == "" {
		writeError(w, r, http.StatusBadRequest, "missing paste handle", "provide a handle like /pastes/paste_abc12")
		return
	}

	p, err := h.store.GetPaste(handle)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "paste not found", "check the handle or list your pastes with GET /pastes")
		return
	}

	// Check if expired
	if p.IsExpired() {
		_ = h.store.DeletePaste(handle)
		writeError(w, r, http.StatusNotFound, "paste has expired", "this paste has been automatically deleted")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getPaste(w, r, p)
	case http.MethodPatch:
		h.updatePaste(w, r, p)
	case http.MethodDelete:
		h.deletePaste(w, r, p)
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use GET, PATCH, or DELETE")
	}
}

// getPaste returns a paste's content.
func (h *Handler) getPaste(w http.ResponseWriter, r *http.Request, p *model.Paste) {
	// Public and unlisted pastes can be viewed without auth
	if p.Visibility == "private" {
		h.withWorkspace(func(w http.ResponseWriter, r *http.Request, tok *model.Token, ws *model.Workspace) {
			if p.Workspace != ws.Handle {
				writeError(w, r, http.StatusForbidden, "access denied", "this paste is private and belongs to another workspace")
				return
			}
			h.writePaste(w, r, p)
		})(w, r)
		return
	}
	h.writePaste(w, r, p)
}

// writePaste writes a paste in the appropriate format.
func (h *Handler) writePaste(w http.ResponseWriter, r *http.Request, p *model.Paste) {
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, p)
		return
	}
	// For plain text, return the content directly
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, p.Content)
}

// updatePaste handles PATCH /pastes/<handle>.
func (h *Handler) updatePaste(w http.ResponseWriter, r *http.Request, p *model.Paste) {
	h.withWorkspace(func(w http.ResponseWriter, r *http.Request, tok *model.Token, ws *model.Workspace) {
		if p.Workspace != ws.Handle {
			writeError(w, r, http.StatusForbidden, "access denied", "you can only modify pastes in your own workspace")
			return
		}

		if title := r.FormValue("title"); title != "" {
			p.Title = title
		}
		if content := r.FormValue("content"); content != "" {
			p.Content = content
		}
		if language := r.FormValue("language"); language != "" {
			p.Language = language
		}
		if visibility := r.FormValue("visibility"); visibility != "" {
			if visibility != "public" && visibility != "unlisted" && visibility != "private" {
				writeError(w, r, http.StatusBadRequest, "invalid visibility", "use one of: public, unlisted, private")
				return
			}
			p.Visibility = visibility
		}
		p.UpdatedAt = time.Now()

		if err := h.store.UpdatePaste(p); err != nil {
			writeError(w, r, http.StatusInternalServerError, "failed to update paste", "try again")
			return
		}

		_ = h.store.AddAudit(&model.AuditEntry{
			Workspace: ws.Handle,
			Action:    "paste.update",
			Detail:    fmt.Sprintf("handle=%s", p.Handle),
			Actor:     tok.Email,
		})

		writeRecord(w, r, http.StatusOK,
			fmt.Sprintf("handle=%s title=%s language=%s visibility=%s updated=%s", p.Handle, p.Title, p.Language, p.Visibility, p.UpdatedAt.Format(time.RFC3339)),
			p,
		)
	})(w, r)
}

// deletePaste handles DELETE /pastes/<handle>.
func (h *Handler) deletePaste(w http.ResponseWriter, r *http.Request, p *model.Paste) {
	h.withWorkspace(func(w http.ResponseWriter, r *http.Request, tok *model.Token, ws *model.Workspace) {
		if p.Workspace != ws.Handle {
			writeError(w, r, http.StatusForbidden, "access denied", "you can only delete pastes in your own workspace")
			return
		}

		if err := h.store.DeletePaste(p.Handle); err != nil {
			writeError(w, r, http.StatusInternalServerError, "failed to delete paste", "try again")
			return
		}

		_ = h.store.AddAudit(&model.AuditEntry{
			Workspace: ws.Handle,
			Action:    "paste.delete",
			Detail:    fmt.Sprintf("handle=%s", p.Handle),
			Actor:      tok.Email,
		})

		writeText(w, http.StatusOK, fmt.Sprintf("deleted handle=%s", p.Handle))
	})(w, r)
}

// workspace handles GET/PATCH /workspace.
func (h *Handler) workspace(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getWorkspace(w, r)
	case http.MethodPatch:
		h.updateWorkspace(w, r)
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use GET or PATCH")
	}
}

func (h *Handler) getWorkspace(w http.ResponseWriter, r *http.Request) {
	h.withWorkspace(func(w http.ResponseWriter, r *http.Request, tok *model.Token, ws *model.Workspace) {
		writeRecord(w, r, http.StatusOK,
			fmt.Sprintf("handle=%s name=%s plan=%s created=%s", ws.Handle, ws.Name, ws.Plan, ws.CreatedAt.Format(time.RFC3339)),
			ws,
		)
	})(w, r)
}

func (h *Handler) updateWorkspace(w http.ResponseWriter, r *http.Request) {
	h.withWorkspace(func(w http.ResponseWriter, r *http.Request, tok *model.Token, ws *model.Workspace) {
		if name := r.FormValue("name"); name != "" {
			ws.Name = name
		}
		if plan := r.FormValue("plan"); plan != "" {
			if plan != "free" && plan != "pro" {
				writeError(w, r, http.StatusBadRequest, "invalid plan", "use one of: free, pro")
				return
			}
			ws.Plan = plan
		}
		if err := h.store.CreateWorkspace(ws); err != nil {
			writeError(w, r, http.StatusInternalServerError, "failed to update workspace", "try again")
			return
		}
		writeRecord(w, r, http.StatusOK,
			fmt.Sprintf("handle=%s name=%s plan=%s", ws.Handle, ws.Name, ws.Plan),
			ws,
		)
	})(w, r)
}

// audit handles GET /audit.
func (h *Handler) audit(w http.ResponseWriter, r *http.Request) {
	h.withWorkspace(func(w http.ResponseWriter, r *http.Request, tok *model.Token, ws *model.Workspace) {
		limit := 20
		if l := r.URL.Query().Get("limit"); l != "" {
			var n int
			if _, err := fmt.Sscanf(l, "%d", &n); err == nil && n > 0 {
				limit = n
			}
		}
		entries := h.store.ListAudit(ws.Handle, limit)
		var records []string
		for _, e := range entries {
			records = append(records, fmt.Sprintf("id=%d action=%s detail=%s actor=%s time=%s",
				e.ID, e.Action, e.Detail, e.Actor, e.Timestamp.Format(time.RFC3339)))
		}
		if len(records) == 0 {
			records = []string{"(no audit entries)"}
		}
		writeList(w, r, records, entries)
	})(w, r)
}

// mcp handles POST /mcp — Model Context Protocol endpoint.
func (h *Handler) mcp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use POST with MCP JSON-RPC payload")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "failed to read body", "send a valid JSON-RPC request")
		return
	}
	defer r.Body.Close()

	var req map[string]interface{}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid JSON", "send a valid JSON-RPC 2.0 request")
		return
	}

	method, _ := req["method"].(string)

	switch method {
	case "initialize":
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req["id"],
			"result": map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{},
				},
				"serverInfo": map[string]interface{}{
					"name":    "pastekit",
					"version": "0.1.0",
				},
			},
		})

	case "tools/list":
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req["id"],
			"result": map[string]interface{}{
				"tools": []map[string]interface{}{
					{
						"name":        "create_paste",
						"description": "Create a text paste/snippet",
						"inputSchema": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"content":    map[string]interface{}{"type": "string", "description": "The text content to paste"},
								"title":      map[string]interface{}{"type": "string", "description": "Optional title"},
								"language":   map[string]interface{}{"type": "string", "description": "Optional language hint (e.g. go, python, json)"},
								"visibility": map[string]interface{}{"type": "string", "enum": []string{"public", "unlisted", "private"}},
								"ttl":        map[string]interface{}{"type": "string", "description": "Time-to-live: 1h, 24h, 7d, 30d"},
							},
							"required": []string{"content"},
						},
					},
					{
						"name":        "get_paste",
						"description": "Get a paste by its handle",
						"inputSchema": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"handle": map[string]interface{}{"type": "string", "description": "The paste handle (e.g. paste_abc12)"},
							},
							"required": []string{"handle"},
						},
					},
					{
						"name":        "list_pastes",
						"description": "List all pastes in your workspace",
						"inputSchema": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{},
						},
					},
					{
						"name":        "delete_paste",
						"description": "Delete a paste by its handle",
						"inputSchema": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"handle": map[string]interface{}{"type": "string", "description": "The paste handle to delete"},
							},
							"required": []string{"handle"},
						},
					},
				},
			},
		})

	case "tools/call":
		params, _ := req["params"].(map[string]interface{})
		toolName, _ := params["name"].(string)
		args, _ := params["arguments"].(map[string]interface{})

		switch toolName {
		case "create_paste":
			content, _ := args["content"].(string)
			if content == "" {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      req["id"],
					"error": map[string]interface{}{
						"code":    -32602,
						"message": "content is required",
					},
				})
				return
			}
			// For MCP, we need auth — check the Authorization header
			authHeader := r.Header.Get("Authorization")
			tokenStr := auth.ExtractBearer(authHeader)
			if tokenStr == "" {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      req["id"],
					"error": map[string]interface{}{
						"code":    -32603,
						"message": "authentication required: provide Bearer token in Authorization header",
					},
				})
				return
			}
			tok, err := h.auth.ValidateToken(tokenStr)
			if err != nil {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      req["id"],
					"error": map[string]interface{}{
						"code":    -32603,
						"message": "invalid token: " + err.Error(),
					},
				})
				return
			}
			ws, err := h.store.GetWorkspaceByName(tok.Email)
			if err != nil {
				ws = &model.Workspace{
					Handle: model.NewWorkspaceHandle(),
					Name:   tok.Email,
					Plan:   "free",
				}
				_ = h.store.CreateWorkspace(ws)
			}
			visibility, _ := args["visibility"].(string)
			if visibility == "" {
				visibility = "unlisted"
			}
			ttl, _ := args["ttl"].(string)
			var expiresAt *time.Time
			if ttl != "" {
				expiresAt, _ = model.ParseTTL(ttl)
			}
			title, _ := args["title"].(string)
			language, _ := args["language"].(string)
			p := &model.Paste{
				Handle:     model.NewPasteHandle(),
				Workspace:  ws.Handle,
				Title:      title,
				Content:    content,
				Language:   language,
				Visibility: visibility,
				TTL:        ttl,
				ExpiresAt:  expiresAt,
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			}
			_ = h.store.CreatePaste(p)
			_ = h.store.AddAudit(&model.AuditEntry{
				Workspace: ws.Handle,
				Action:    "paste.create",
				Detail:     fmt.Sprintf("handle=%s", p.Handle),
				Actor:      tok.Email,
			})
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"result": map[string]interface{}{
					"content": []map[string]interface{}{
						{
							"type": "text",
							"text": fmt.Sprintf("Created paste: handle=%s", p.Handle),
						},
					},
				},
			})

		case "get_paste":
			handle, _ := args["handle"].(string)
			p, err := h.store.GetPaste(handle)
			if err != nil {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      req["id"],
					"error": map[string]interface{}{
						"code":    -32602,
						"message": "paste not found: " + handle,
					},
				})
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"result": map[string]interface{}{
					"content": []map[string]interface{}{
						{
							"type": "text",
							"text": p.Content,
						},
					},
				},
			})

		case "list_pastes":
			authHeader := r.Header.Get("Authorization")
			tokenStr := auth.ExtractBearer(authHeader)
			if tokenStr == "" {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      req["id"],
					"error": map[string]interface{}{
						"code":    -32603,
						"message": "authentication required",
					},
				})
				return
			}
			tok, err := h.auth.ValidateToken(tokenStr)
			if err != nil {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      req["id"],
					"error": map[string]interface{}{
						"code":    -32603,
						"message": "invalid token",
					},
				})
				return
			}
			ws, err := h.store.GetWorkspaceByName(tok.Email)
			if err != nil {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      req["id"],
					"result": map[string]interface{}{
						"content": []map[string]interface{}{
							{
								"type": "text",
								"text": "(no pastes found)",
							},
						},
					},
				})
				return
			}
			pastes := h.store.ListPastes(ws.Handle)
			var lines []string
			for _, p := range pastes {
				lines = append(lines, fmt.Sprintf("handle=%s title=%s language=%s", p.Handle, p.Title, p.Language))
			}
			if len(lines) == 0 {
				lines = []string{"(no pastes found)"}
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"result": map[string]interface{}{
					"content": []map[string]interface{}{
						{
							"type": "text",
							"text": strings.Join(lines, "\n"),
						},
					},
				},
			})

		case "delete_paste":
			handle, _ := args["handle"].(string)
			authHeader := r.Header.Get("Authorization")
			tokenStr := auth.ExtractBearer(authHeader)
			if tokenStr == "" {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      req["id"],
					"error": map[string]interface{}{
						"code":    -32603,
						"message": "authentication required",
					},
				})
				return
			}
			tok, err := h.auth.ValidateToken(tokenStr)
			if err != nil {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      req["id"],
					"error": map[string]interface{}{
						"code":    -32603,
						"message": "invalid token",
					},
				})
				return
			}
			ws, err := h.store.GetWorkspaceByName(tok.Email)
			if err != nil {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      req["id"],
					"error": map[string]interface{}{
						"code":    -32602,
						"message": "paste not found or access denied",
					},
				})
				return
			}
			p, err := h.store.GetPaste(handle)
			if err != nil || p.Workspace != ws.Handle {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      req["id"],
					"error": map[string]interface{}{
						"code":    -32602,
						"message": "paste not found or access denied",
					},
				})
				return
			}
			_ = h.store.DeletePaste(handle)
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"result": map[string]interface{}{
					"content": []map[string]interface{}{
						{
							"type": "text",
							"text": fmt.Sprintf("Deleted paste: handle=%s", handle),
						},
					},
				},
			})

		default:
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"error": map[string]interface{}{
					"code":    -32601,
					"message": "unknown tool: " + toolName,
				},
			})
		}

	default:
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req["id"],
			"error": map[string]interface{}{
				"code":    -32601,
				"message": "method not found: " + method,
			},
		})
	}
}

// parseFormValue reads a form value and returns an error if it's empty.
func parseFormValue(r *http.Request, key string) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", fmt.Errorf("failed to parse form data")
	}
	val := r.FormValue(key)
	if val == "" {
		return "", fmt.Errorf("missing required field: %s", key)
	}
	return val, nil
}
