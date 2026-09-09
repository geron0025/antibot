package admin

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Iterations is how many times PBKDF2 is run. The number comes from the
// OWASP recommendations for PBKDF2-HMAC-SHA256: guessing a password has
// to be expensive, while a human logs in once a day and will survive an
// extra half a second.
const Iterations = 600_000

// iterations is the same number, but replaceable by tests: half a second
// per password check turns this package's test run into a minute and a
// half, and then people stop running it. Verifying an existing hash
// always uses the number written inside the hash itself, so the
// substitution breaks nothing.
var iterations = Iterations

// User is a name and a password hash.
type User struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
}

// Users are the admin UI's accounts, a file on disk.
//
// A separate file rather than the configuration: the configuration is
// often mounted read-only, while a password is changed without restarting
// the node.
type Users struct {
	path string

	mu    sync.RWMutex
	users []User
}

type usersFile struct {
	Version int    `json:"version"`
	Users   []User `json:"users"`
}

// UsersFormatVersion is the format version of the accounts file.
const UsersFormatVersion = 1

// OpenUsers reads the accounts file. A missing file is not an error:
// before the first `antibot admin passwd` there are no accounts, and the
// admin UI then simply does not come up.
func OpenUsers(path string) (*Users, error) {
	u := &Users{path: path}

	contents, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return u, nil
	}
	if err != nil {
		return nil, fmt.Errorf("admin UI users %s: %w", path, err)
	}

	var f usersFile
	if err := json.Unmarshal(contents, &f); err != nil {
		return nil, fmt.Errorf("admin UI users %s: %w", path, err)
	}
	if f.Version != UsersFormatVersion {
		return nil, fmt.Errorf("admin UI users %s: version %d, and the node understands %d",
			path, f.Version, UsersFormatVersion)
	}
	u.users = f.Users
	return u, nil
}

// Any answers whether there is at least one account. Without one the
// admin UI must not come up: a login is mandatory from the very first
// version, and "without a password for now" is exactly the case where
// "for now" lasts years.
func (u *Users) Any() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return len(u.users) > 0
}

// Names lists the accounts.
func (u *Users) Names() []string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	names := make([]string, 0, len(u.users))
	for _, user := range u.users {
		names = append(names, user.Name)
	}
	return names
}

// Set creates an account or changes the password of an existing one.
func (u *Users) Set(name, password string) error {
	if name == "" {
		return fmt.Errorf("an empty name")
	}
	if len([]rune(password)) < 12 {
		// Twelve rather than eight: one day the admin UI will be exposed
		// to the outside, whatever the documentation says.
		return fmt.Errorf("the password is shorter than twelve characters")
	}

	hash, err := hashPassword(password)
	if err != nil {
		return err
	}

	u.mu.Lock()
	found := false
	for i := range u.users {
		if u.users[i].Name == name {
			u.users[i].Hash = hash
			found = true
		}
	}
	if !found {
		u.users = append(u.users, User{Name: name, Hash: hash})
	}
	list := make([]User, len(u.users))
	copy(list, u.users)
	u.mu.Unlock()

	return u.write(list)
}

// Remove deletes an account.
func (u *Users) Remove(name string) error {
	u.mu.Lock()
	left := make([]User, 0, len(u.users))
	for _, user := range u.users {
		if user.Name != name {
			left = append(left, user)
		}
	}
	if len(left) == len(u.users) {
		u.mu.Unlock()
		return fmt.Errorf("there is no account %q", name)
	}
	u.users = left
	list := make([]User, len(left))
	copy(list, left)
	u.mu.Unlock()

	return u.write(list)
}

// write puts the file down atomically and with mode 0600: it holds
// password hashes, and there is nobody else to read it.
func (u *Users) write(list []User) error {
	contents, err := json.MarshalIndent(
		usersFile{Version: UsersFormatVersion, Users: list}, "", "  ")
	if err != nil {
		return err
	}
	contents = append(contents, '\n')

	dir := filepath.Dir(u.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".admin-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)

	if _, err := tmp.Write(contents); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	return os.Rename(name, u.path)
}

// Check verifies a name and a password.
//
// A non-existent name costs as much time as an existing one: otherwise
// names are enumerated by the speed of the answer, without knowing a
// single password.
func (u *Users) Check(name, password string) bool {
	u.mu.RLock()
	var hash string
	for _, user := range u.users {
		if subtle.ConstantTimeCompare([]byte(user.Name), []byte(name)) == 1 {
			hash = user.Hash
		}
	}
	u.mu.RUnlock()

	if hash == "" {
		// Work for nothing, for the sake of an equal response time.
		hashWithSalt(password, make([]byte, 16))
		return false
	}
	return verify(hash, password)
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return hashWithSalt(password, salt), nil
}

func hashWithSalt(password string, salt []byte) string {
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		// An error is only possible with invalid parameters, and here
		// they are set by constants.
		panic(err)
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

func verify(hash, password string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	rounds, err := strconv.Atoi(parts[1])
	if err != nil || rounds <= 0 || rounds > 10_000_000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}

	key, err := pbkdf2.Key(sha256.New, password, salt, rounds, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(key, want) == 1
}

// Sessions holds those who are logged in, in the process's memory.
//
// In memory precisely: a restart of the node logs everybody out, and that
// is more correct than keeping on disk something that can be logged in
// with.
type Sessions struct {
	ttl time.Duration

	mu   sync.Mutex
	live map[string]session
}

type session struct {
	name  string
	until time.Time
}

func NewSessions(ttl time.Duration) *Sessions {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &Sessions{ttl: ttl, live: map[string]session{}}
}

// Start creates a session and returns its key.
func (s *Sessions) Start(name string, now time.Time) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	key := base64.RawURLEncoding.EncodeToString(raw)
	until := now.Add(s.ttl)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	s.live[key] = session{name: name, until: until}
	return key, until, nil
}

// Whose returns the name of the logged-in user.
func (s *Sessions) Whose(key string, now time.Time) (string, bool) {
	if key == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	live, ok := s.live[key]
	if !ok {
		return "", false
	}
	if !now.Before(live.until) {
		delete(s.live, key)
		return "", false
	}
	return live.name, true
}

// End closes a session.
func (s *Sessions) End(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.live, key)
}

// Live is how many sessions are open right now.
func (s *Sessions) Live() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live)
}

func (s *Sessions) sweep(now time.Time) {
	for key, live := range s.live {
		if !now.Before(live.until) {
			delete(s.live, key)
		}
	}
}
