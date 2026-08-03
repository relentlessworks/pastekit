package store

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/relentlessworks/pastekit/internal/model"
)

// Store is a JSON file-backed data store.
type Store struct {
	mu       sync.RWMutex
	filePath string
	data     *storeData
}

type storeData struct {
	Workspaces map[string]*model.Workspace `json:"workspaces"`
	Pastes     map[string]*model.Paste     `json:"pastes"`
	Tokens     map[string]*model.Token     `json:"tokens"`
	OTPs       map[string]*model.OTPRequest `json:"otps"`
	Audit      []model.AuditEntry          `json:"audit"`
	AuditSeq   int                          `json:"audit_seq"`
}

// New creates a new Store backed by the given file path.
func New(filePath string) (*Store, error) {
	s := &Store{
		filePath: filePath,
		data: &storeData{
			Workspaces: make(map[string]*model.Workspace),
			Pastes:     make(map[string]*model.Paste),
			Tokens:     make(map[string]*model.Token),
			OTPs:       make(map[string]*model.OTPRequest),
		},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// load reads the JSON file into memory. If the file doesn't exist, it starts empty.
func (s *Store) load() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, s.data)
}

// save writes the in-memory data to the JSON file.
func (s *Store) save() error {
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.filePath, data, 0644)
}

// --- Workspace operations ---

func (s *Store) CreateWorkspace(ws *model.Workspace) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Workspaces[ws.Handle] = ws
	return s.save()
}

func (s *Store) GetWorkspace(handle string) (*model.Workspace, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ws, ok := s.data.Workspaces[handle]
	if !ok {
		return nil, fmt.Errorf("workspace not found: %s", handle)
	}
	return ws, nil
}

func (s *Store) GetWorkspaceByName(name string) (*model.Workspace, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, ws := range s.data.Workspaces {
		if ws.Name == name {
			return ws, nil
		}
	}
	return nil, fmt.Errorf("workspace not found with name: %s", name)
}

// --- Paste operations ---

func (s *Store) CreatePaste(p *model.Paste) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Pastes[p.Handle] = p
	return s.save()
}

func (s *Store) GetPaste(handle string) (*model.Paste, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.data.Pastes[handle]
	if !ok {
		return nil, fmt.Errorf("paste not found: %s", handle)
	}
	return p, nil
}

func (s *Store) UpdatePaste(p *model.Paste) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Pastes[p.Handle] = p
	return s.save()
}

func (s *Store) DeletePaste(handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data.Pastes, handle)
	return s.save()
}

func (s *Store) ListPastes(workspace string) []*model.Paste {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var pastes []*model.Paste
	for _, p := range s.data.Pastes {
		if p.Workspace == workspace {
			pastes = append(pastes, p)
		}
	}
	// Sort by created_at descending
	sort.Slice(pastes, func(i, j int) bool {
		return pastes[i].CreatedAt.After(pastes[j].CreatedAt)
	})
	return pastes
}

// CleanupExpired removes all expired pastes and returns the count.
func (s *Store) CleanupExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for handle, p := range s.data.Pastes {
		if p.IsExpired() {
			delete(s.data.Pastes, handle)
			count++
		}
	}
	if count > 0 {
		_ = s.save()
	}
	return count
}

// --- Token operations ---

func (s *Store) SaveToken(t *model.Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Tokens[t.Token] = t
	return s.save()
}

func (s *Store) GetToken(token string) (*model.Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.data.Tokens[token]
	if !ok {
		return nil, fmt.Errorf("token not found")
	}
	return t, nil
}

func (s *Store) DeleteToken(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data.Tokens, token)
	return s.save()
}

// --- OTP operations ---

func (s *Store) SaveOTP(req *model.OTPRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.OTPs[req.Email] = req
	return s.save()
}

func (s *Store) GetOTP(email string) (*model.OTPRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.data.OTPs[email]
	if !ok {
		return nil, fmt.Errorf("no OTP request found for %s", email)
	}
	return req, nil
}

func (s *Store) DeleteOTP(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data.OTPs, email)
	_ = s.save()
}

// --- Audit operations ---

func (s *Store) AddAudit(entry *model.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.AuditSeq++
	entry.ID = s.data.AuditSeq
	entry.Timestamp = time.Now()
	s.data.Audit = append(s.data.Audit, *entry)
	return s.save()
}

func (s *Store) ListAudit(workspace string, limit int) []model.AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var entries []model.AuditEntry
	for _, e := range s.data.Audit {
		if e.Workspace == workspace {
			entries = append(entries, e)
		}
	}
	// Reverse order (newest first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	return entries
}
