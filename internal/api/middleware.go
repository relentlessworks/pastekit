package api

import (
	"net/http"
	"strings"

	"github.com/relentlessworks/pastekit/internal/auth"
	"github.com/relentlessworks/pastekit/internal/model"
)

// Middleware provides HTTP middleware functions.

// withAuth wraps a handler requiring authentication.
func (h *Handler) withAuth(next func(w http.ResponseWriter, r *http.Request, tok *model.Token)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		tokenStr := auth.ExtractBearer(authHeader)
		if tokenStr == "" {
			writeError(w, r, http.StatusUnauthorized, "missing auth token", "call POST /auth/request with email to get an OTP, then POST /auth/verify to get a bearer token")
			return
		}
		tok, err := h.auth.ValidateToken(tokenStr)
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, err.Error(), "request a new token via POST /auth/request then POST /auth/verify")
			return
		}
		next(w, r, tok)
	}
}

// withWorkspace wraps a handler that needs a workspace context.
// The workspace is resolved from the token's email. If the user doesn't have
// a workspace yet, one is auto-created.
func (h *Handler) withWorkspace(next func(w http.ResponseWriter, r *http.Request, tok *model.Token, ws *model.Workspace)) http.HandlerFunc {
	return h.withAuth(func(w http.ResponseWriter, r *http.Request, tok *model.Token) {
		// Try to find workspace by name (email)
		ws, err := h.store.GetWorkspaceByName(tok.Email)
		if err != nil {
			// Auto-create workspace
			ws = &model.Workspace{
				Handle: model.NewWorkspaceHandle(),
				Name:   tok.Email,
				Plan:   "free",
			}
			if err := h.store.CreateWorkspace(ws); err != nil {
				writeError(w, r, http.StatusInternalServerError, "failed to create workspace", "try again later or contact support")
				return
			}
			_ = h.store.AddAudit(&model.AuditEntry{
				Workspace: ws.Handle,
				Action:    "workspace.create",
				Detail:    "auto-created on first auth",
				Actor:     tok.Email,
			})
		}
		next(w, r, tok, ws)
	})
}

// corsMiddleware adds CORS headers.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs requests.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip health checks
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// trimPath removes trailing slashes from the path.
func trimPath(p string) string {
	return strings.TrimRight(p, "/")
}
