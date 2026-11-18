package controlplane

// Control-plane account store.
//
// Accounts live in a config-managed JSON file (default
// control-accounts.json) holding usernames and bcrypt password
// hashes only — never plaintext passwords. There are no
// default credentials: the first owner account is created
// through the one-time setup-token bootstrap (`sonushield
// control-setup`), and the control plane refuses password
// logins until an account exists.
//
// Roles form the platform model, reusing the Batch 5 tenant
// model (domains carry a `tenant` field; see
// domains.NormalizeTenant):
//
//   - owner: sees and manages everything on every node.
//   - reseller: manages only the tenants listed on the
//     account, on every node.
//   - tenant: read-only, only the account's own tenant.
//
// Authorization always reads the live store: deleting or
// disabling an account immediately invalidates its sessions,
// and role changes apply without re-login. The store file is
// written atomically (temp file + rename) with 0600
// permissions.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"sonushield/core/domains"

	"golang.org/x/crypto/bcrypt"
)

const (
	// RoleOwner sees and manages everything.
	RoleOwner = "owner"
	// RoleReseller manages only its listed tenants.
	RoleReseller = "reseller"
	// RoleTenant is read-only for its own tenant.
	RoleTenant = "tenant"
)

const (
	minPasswordLength = 12
	accountsFileMode  = 0600
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}$`)

// Account is one control-plane login.
type Account struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"passwordHash"`
	Role         string    `json:"role"`
	Tenant       string    `json:"tenant,omitempty"`
	Tenants      []string  `json:"tenants,omitempty"`
	Disabled     bool      `json:"disabled,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// TenantSet returns the tenants this account may access, or
// nil for the owner (all tenants). Names are normalized with
// domains.NormalizeTenant so "" and "default" agree.
func (a *Account) TenantSet() map[string]bool {
	if a == nil || a.Role == RoleOwner {
		return nil
	}
	set := map[string]bool{}
	if a.Role == RoleTenant {
		set[domains.NormalizeTenant(a.Tenant)] = true
		return set
	}
	for _, tenant := range a.Tenants {
		set[domains.NormalizeTenant(tenant)] = true
	}
	return set
}

// NodeRole maps the account role to the proxy API role level
// it may exercise through the control plane. The node remains
// the source of truth for what each level may do (see
// api.MinRoleFor); the control plane only decides which level
// an account gets.
func (a *Account) NodeRole() string {
	switch a.Role {
	case RoleOwner:
		return "admin"
	case RoleReseller:
		return "operator"
	default:
		return "viewer"
	}
}

// accountFile is the on-disk store shape.
type accountFile struct {
	Version  int        `json:"version"`
	Accounts []*Account `json:"accounts"`
}

// Store is the loaded account file with serialized writes.
type Store struct {
	mu       sync.RWMutex
	path     string
	accounts map[string]*Account
}

// LoadStore reads the accounts file. A missing file means an
// empty store (no accounts yet); a corrupt file is a startup
// error, never silently ignored.
func LoadStore(path string) (*Store, error) {
	store := &Store{path: path, accounts: map[string]*Account{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, err
	}
	var file accountFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("accounts file %s is not valid JSON: %w", path, err)
	}
	for _, account := range file.Accounts {
		if account == nil || account.Username == "" {
			continue
		}
		store.accounts[account.Username] = account
	}
	return store, nil
}

// save writes the store atomically. The caller holds the write
// lock.
func (s *Store) save() error {
	file := accountFile{Version: 1}
	names := make([]string, 0, len(s.accounts))
	for name := range s.accounts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		file.Accounts = append(file.Accounts, s.accounts[name])
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".accounts-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(accountsFileMode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}

// Get returns a copy of the account, or nil.
func (s *Store) Get(username string) *Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	account, ok := s.accounts[username]
	if !ok {
		return nil
	}
	copy := *account
	return &copy
}

// HasOwner reports whether any enabled owner account exists.
func (s *Store) HasOwner() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, account := range s.accounts {
		if account.Role == RoleOwner && !account.Disabled {
			return true
		}
	}
	return false
}

// List returns copies of all accounts, sorted by username.
func (s *Store) List() []*Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.accounts))
	for name := range s.accounts {
		names = append(names, name)
	}
	sort.Strings(names)
	list := make([]*Account, 0, len(names))
	for _, name := range names {
		copy := *s.accounts[name]
		list = append(list, &copy)
	}
	return list
}

// validateAccountFields checks a new or updated account's
// fields. It never sees a password hash, only the plaintext
// password at creation/change time (which is hashed by the
// caller and never stored).
func validateAccountFields(username, password, role, tenant string, tenants []string) error {
	if !usernamePattern.MatchString(username) {
		return errors.New("username must be 3-32 characters: lowercase letters, digits, dots, hyphens, underscores")
	}
	if len(password) < minPasswordLength {
		return fmt.Errorf("password must be at least %d characters", minPasswordLength)
	}
	switch role {
	case RoleOwner, RoleReseller, RoleTenant:
	default:
		return errors.New("role must be owner, reseller, or tenant")
	}
	if role == RoleTenant && strings.TrimSpace(tenant) == "" {
		return errors.New("a tenant account needs a tenant")
	}
	if role == RoleReseller && len(tenants) == 0 {
		return errors.New("a reseller account needs at least one tenant")
	}
	return nil
}

// Create adds an account, hashing the password with bcrypt.
// It reports an error when the username already exists.
func (s *Store) Create(username, password, role, tenant string, tenants []string) (*Account, error) {
	if err := validateAccountFields(username, password, role, tenant, tenants); err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	account := &Account{
		Username:     username,
		PasswordHash: string(hash),
		Role:         role,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	switch role {
	case RoleTenant:
		account.Tenant = domains.NormalizeTenant(tenant)
	case RoleReseller:
		normalized := make([]string, 0, len(tenants))
		seen := map[string]bool{}
		for _, name := range tenants {
			name = domains.NormalizeTenant(name)
			if !seen[name] {
				seen[name] = true
				normalized = append(normalized, name)
			}
		}
		sort.Strings(normalized)
		account.Tenants = normalized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.accounts[username]; exists {
		return nil, errors.New("username already exists")
	}
	s.accounts[username] = account
	if err := s.save(); err != nil {
		delete(s.accounts, username)
		return nil, err
	}
	copy := *account
	return &copy, nil
}

// Delete removes an account. Deleting the last enabled owner
// is refused: the platform must always have an owner.
func (s *Store) Delete(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	account, ok := s.accounts[username]
	if !ok {
		return errors.New("no such account")
	}
	if account.Role == RoleOwner && !account.Disabled {
		owners := 0
		for _, other := range s.accounts {
			if other.Role == RoleOwner && !other.Disabled {
				owners++
			}
		}
		if owners <= 1 {
			return errors.New("cannot delete the last enabled owner")
		}
	}
	delete(s.accounts, username)
	return s.save()
}

// SetPassword replaces an account's password hash.
func (s *Store) SetPassword(username, password string) error {
	if len(password) < minPasswordLength {
		return fmt.Errorf("password must be at least %d characters", minPasswordLength)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	account, ok := s.accounts[username]
	if !ok {
		return errors.New("no such account")
	}
	account.PasswordHash = string(hash)
	account.UpdatedAt = time.Now().UTC()
	return s.save()
}

// SetDisabled toggles an account. Disabling the last enabled
// owner is refused, like deleting it.
func (s *Store) SetDisabled(username string, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	account, ok := s.accounts[username]
	if !ok {
		return errors.New("no such account")
	}
	if disabled && account.Role == RoleOwner && !account.Disabled {
		owners := 0
		for _, other := range s.accounts {
			if other.Role == RoleOwner && !other.Disabled {
				owners++
			}
		}
		if owners <= 1 {
			return errors.New("cannot disable the last enabled owner")
		}
	}
	account.Disabled = disabled
	account.UpdatedAt = time.Now().UTC()
	return s.save()
}

// dummyHash is a bcrypt hash of a random value, used to check
// passwords for unknown usernames so the timing (and the
// generic failure) does not reveal whether a username exists.
var dummyHash = func() string {
	hash, _ := bcrypt.GenerateFromPassword([]byte("sonushield-control-plane-dummy"), bcrypt.DefaultCost)
	return string(hash)
}()

// CheckPassword verifies a password for a username. It
// reports false for unknown users, disabled accounts, and
// wrong passwords alike: callers must not distinguish them.
func (s *Store) CheckPassword(username, password string) bool {
	account := s.Get(username)
	hash := dummyHash
	if account != nil {
		hash = account.PasswordHash
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil || account == nil || account.Disabled {
		return false
	}
	return true
}

// setupState is the one-time bootstrap token record. Only the
// hash is stored; the token itself is shown once by the CLI.
type setupState struct {
	TokenHash string    `json:"tokenHash"`
	ExpiresAt time.Time `json:"expiresAt"`
}

const setupTokenTTL = time.Hour

// setupStatePath derives the setup-token file path from the
// accounts file path.
func setupStatePath(accountsPath string) string {
	return accountsPath + ".setup.json"
}

// GenerateSetupToken creates a one-time bootstrap token,
// stores only its hash, and returns the token for the CLI to
// print once. Any previous token is invalidated. It refuses
// when an owner account already exists.
func GenerateSetupToken(accountsPath string) (string, error) {
	store, err := LoadStore(accountsPath)
	if err != nil {
		return "", err
	}
	if store.HasOwner() {
		return "", errors.New("an owner account already exists; bootstrap is disabled")
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(token))
	state := setupState{
		TokenHash: hex.EncodeToString(sum[:]),
		ExpiresAt: time.Now().Add(setupTokenTTL),
	}
	data, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	path := setupStatePath(accountsPath)
	if err := os.WriteFile(path, data, accountsFileMode); err != nil {
		return "", err
	}
	return token, nil
}

// verifySetupToken checks a presented token against the stored
// hash and expiry, consuming the token on success. Failures
// never reveal whether a token exists, has expired, or
// mismatches.
func verifySetupToken(accountsPath, token string) bool {
	path := setupStatePath(accountsPath)
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var state setupState
	if err := json.Unmarshal(data, &state); err != nil {
		return false
	}
	if time.Now().After(state.ExpiresAt) {
		os.Remove(path)
		return false
	}
	sum := sha256.Sum256([]byte(token))
	presented := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(presented), []byte(state.TokenHash)) != 1 {
		return false
	}
	// Single-use: remove the token before creating the
	// account so a replayed request cannot create a second
	// owner even if it races the first.
	os.Remove(path)
	return true
}

// SetupPending reports whether bootstrap is available: no
// owner exists and a live setup token is on file.
func SetupPending(accountsPath string) bool {
	store, err := LoadStore(accountsPath)
	if err != nil || store.HasOwner() {
		return false
	}
	data, err := os.ReadFile(setupStatePath(accountsPath))
	if err != nil {
		return false
	}
	var state setupState
	if err := json.Unmarshal(data, &state); err != nil {
		return false
	}
	return time.Now().Before(state.ExpiresAt)
}
