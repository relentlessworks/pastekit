package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// wantsJSON checks if the client wants JSON response.
func wantsJSON(r *http.Request) bool {
	if r.URL.Query().Get("format") == "json" {
		return true
	}
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json")
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeText writes a plain text response.
func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintln(w, body)
}

// writeError writes an error response in the appropriate format.
func writeError(w http.ResponseWriter, r *http.Request, status int, msg, hint string) {
	if wantsJSON(r) {
		writeJSON(w, status, map[string]string{
			"error": msg,
			"hint":  hint,
		})
		return
	}
	writeText(w, status, fmt.Sprintf("error: %s | hint: %s", msg, hint))
}

// writeRecord writes a single record in the appropriate format.
func writeRecord(w http.ResponseWriter, r *http.Request, status int, record string, jsonv interface{}) {
	if wantsJSON(r) {
		writeJSON(w, status, jsonv)
		return
	}
	writeText(w, status, record)
}

// writeList writes a list of records in the appropriate format.
func writeList(w http.ResponseWriter, r *http.Request, records []string, jsonv interface{}) {
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, jsonv)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	for _, rec := range records {
		fmt.Fprintln(w, rec)
	}
}
