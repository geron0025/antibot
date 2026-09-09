package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The tests make passwords cheap: the production number of iterations
// costs half a second per check, and with it the package run takes a
// minute and a half. A separate test below guards that the production
// number has not slipped.
func TestMain(m *testing.M) {
	iterations = 1000
	os.Exit(m.Run())
}

// The number of iterations is not the place to economize: guessing a
// password has to be expensive.
func TestProductionIterationCount(t *testing.T) {
	if Iterations < 600_000 {
		t.Errorf("%d iterations — fewer than the six hundred thousand OWASP recommends", Iterations)
	}
}

// A hash written with a different number of iterations must be verified
// by the number inside the hash itself: otherwise changing the default
// would log everybody out at once.
func TestVerificationUsesTheCountFromTheHash(t *testing.T) {
	old := iterations
	iterations = 5000
	hash, err := hashPassword("a very long password")
	if err != nil {
		t.Fatal(err)
	}
	iterations = old

	if !verify(hash, "a very long password") {
		t.Error("a hash computed with a different iteration count did not verify")
	}
}

func tempPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "admin.json")
}

// Before the first `antibot admin passwd` there are no accounts — and
// that is not a read error but the ordinary state of a node that has just
// been installed.
func TestAMissingFileIsNotAnError(t *testing.T) {
	u, err := OpenUsers(tempPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if u.Any() {
		t.Error("accounts were found out of nowhere")
	}
}

func TestSetAndCheck(t *testing.T) {
	path := tempPath(t)
	u, err := OpenUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Set("owner", "a very long password"); err != nil {
		t.Fatal(err)
	}

	if !u.Check("owner", "a very long password") {
		t.Error("the correct password did not match")
	}
	if u.Check("owner", "another password") {
		t.Error("a wrong password matched")
	}
	if u.Check("no such user", "a very long password") {
		t.Error("a non-existent name logged in")
	}

	// The accounts survive a restart.
	again, err := OpenUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Check("owner", "a very long password") {
		t.Error("after the file was reread the password did not match")
	}
}

// The file holds password hashes and nothing else: there is nobody to
// read it.
func TestFilePermissions(t *testing.T) {
	path := tempPath(t)
	u, _ := OpenUsers(path)
	if err := u.Set("owner", "a very long password"); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("permissions %o, want 600", mode)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "a very long password") {
		t.Error("the password lies in the file in clear text")
	}
	if !strings.Contains(string(contents), "pbkdf2-sha256$") {
		t.Errorf("the hash is not in the expected form: %s", contents)
	}
}

// One day the admin UI will be exposed to the outside, whatever the
// documentation says — a short password is not accepted.
func TestAShortPasswordIsNotAccepted(t *testing.T) {
	u, _ := OpenUsers(tempPath(t))
	if err := u.Set("owner", "tooshort"); err == nil {
		t.Error("an eight-character password was accepted")
	}
	if err := u.Set("", "a very long password"); err == nil {
		t.Error("an empty name was accepted")
	}
}

func TestChangingAPasswordAndRemoving(t *testing.T) {
	path := tempPath(t)
	u, _ := OpenUsers(path)
	if err := u.Set("owner", "the first long password"); err != nil {
		t.Fatal(err)
	}
	if err := u.Set("owner", "the second long password"); err != nil {
		t.Fatal(err)
	}
	if u.Check("owner", "the first long password") {
		t.Error("the old password works after the change")
	}
	if !u.Check("owner", "the second long password") {
		t.Error("the new password does not work")
	}
	if len(u.Names()) != 1 {
		t.Errorf("%d accounts, want 1: changing a password must not create a second one", len(u.Names()))
	}

	if err := u.Remove("owner"); err != nil {
		t.Fatal(err)
	}
	if u.Any() {
		t.Error("the account survived the removal")
	}
	if err := u.Remove("no such user"); err == nil {
		t.Error("removing a non-existent account passed silently")
	}
}

// A broken accounts file is a refusal, not "entry is free".
func TestABrokenFileIsARefusal(t *testing.T) {
	path := tempPath(t)
	if err := os.WriteFile(path, []byte(`{"version":1,"users":[`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenUsers(path); err == nil {
		t.Error("the broken accounts file was read without an error")
	}

	if err := os.WriteFile(path, []byte(`{"version":99,"users":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenUsers(path); err == nil {
		t.Error("a file of a foreign version was accepted")
	}
}

// Every password has its own salt: identical passwords must not produce
// identical hashes.
func TestTheSaltDiffers(t *testing.T) {
	first, err := hashPassword("the same long password")
	if err != nil {
		t.Fatal(err)
	}
	second, err := hashPassword("the same long password")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Error("two hashes of one password coincided — the salt does not work")
	}
	if !verify(first, "the same long password") || !verify(second, "the same long password") {
		t.Error("the hashes do not verify")
	}
}

func TestAnInvalidHashLetsNobodyIn(t *testing.T) {
	invalid := []string{
		"", "just a string", "pbkdf2-sha256$0$c29s$a2V5",
		"pbkdf2-sha256$600000$not-base64$a2V5",
		"md5$1$c29s$a2V5",
	}
	for _, h := range invalid {
		if verify(h, "any password") {
			t.Errorf("the hash %q let someone in", h)
		}
	}
}

func TestSessions(t *testing.T) {
	s := NewSessions(time.Hour)
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

	key, until, err := s.Start("owner", now)
	if err != nil {
		t.Fatal(err)
	}
	if !until.After(now) {
		t.Error("the session ends before it began")
	}

	if name, ok := s.Whose(key, now.Add(time.Minute)); !ok || name != "owner" {
		t.Errorf("the session was not found: %q, %v", name, ok)
	}
	if _, ok := s.Whose("a made-up key", now); ok {
		t.Error("a made-up key logged in")
	}
	if _, ok := s.Whose("", now); ok {
		t.Error("an empty key logged in")
	}

	// An expired session lets nobody in and is removed from memory.
	if _, ok := s.Whose(key, now.Add(2*time.Hour)); ok {
		t.Error("an expired session let someone in")
	}
	if s.Live() != 0 {
		t.Errorf("the expired session stayed in memory: %d", s.Live())
	}

	key, _, _ = s.Start("owner", now)
	s.End(key)
	if _, ok := s.Whose(key, now); ok {
		t.Error("the session works after logging out")
	}
}

// Session keys must not repeat.
func TestSessionKeysDiffer(t *testing.T) {
	s := NewSessions(time.Hour)
	now := time.Now()
	seen := map[string]struct{}{}
	for i := 0; i < 100; i++ {
		key, _, err := s.Start("owner", now)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := seen[key]; ok {
			t.Fatal("a session key repeated")
		}
		seen[key] = struct{}{}
		if len(key) < 32 {
			t.Fatalf("the key is short: %d characters", len(key))
		}
	}
}
