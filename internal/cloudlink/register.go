package cloudlink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultURL is where a node with nothing in its settings asks for a
// token. The settings file overrides it, and the stand does exactly
// that.
const DefaultURL = "https://updates.netbota.ru"

// registerFormat is the version of the exchange, as
// docs/*/protocol/registration.md fixes it.
const registerFormat = 1

// maxAnswer caps what is read back. The answer is seven short fields;
// anything larger is not the cloud answering.
const maxAnswer = 64 << 10

// Answer is what the cloud hands back. The token is in it once and
// never again: the cloud keeps a hash.
type Answer struct {
	Format    int    `json:"format"`
	Token     string `json:"token"`
	Scope     string `json:"scope"`
	Level     string `json:"level"`
	Tenant    string `json:"tenant"`
	FactsURL  string `json:"facts_url"`
	IngestURL string `json:"ingest_url"`
}

// ErrAlreadyRegistered means this installation has a token already —
// somewhere. The cloud cannot show it again, and the owner needs a human.
var ErrAlreadyRegistered = errors.New("this installation is already registered with the cloud")

// TooSoon means the address has had its share of registrations for now.
type TooSoon struct{ RetryAfter time.Duration }

func (t *TooSoon) Error() string {
	return fmt.Sprintf("the cloud asks to try again in %s", t.RetryAfter.Round(time.Minute))
}

// Refused carries what the cloud said about a body it would not take.
type Refused struct {
	Status int
	Text   string
}

func (r *Refused) Error() string {
	return fmt.Sprintf("the cloud refused the registration (%d): %s", r.Status, r.Text)
}

// Register asks the cloud for a token.
//
// It sends what the owner ticked, because the cloud has no other way of
// learning what people come for, and nothing else: no domains, no mail,
// no rules. What goes out here is the whole of the protocol's
// registration document.
func Register(ctx context.Context, baseURL, nodeID, version string,
	facts, aggregates bool, client *http.Client) (*Answer, error) {

	if nodeID == "" {
		return nil, errors.New("no node identifier to register with")
	}
	if baseURL == "" {
		baseURL = DefaultURL
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	body, err := json.Marshal(map[string]any{
		"format": registerFormat, "node": nodeID, "version": version,
		"facts": facts, "aggregates": aggregates,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(baseURL, "/")+"/register", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("registration address: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "antibot/"+version)

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("the cloud did not answer: %w", err)
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(res.Body, maxAnswer))
	if err != nil {
		return nil, fmt.Errorf("the cloud's answer was not read: %w", err)
	}

	switch res.StatusCode {
	case http.StatusCreated:
	case http.StatusConflict:
		return nil, ErrAlreadyRegistered
	case http.StatusTooManyRequests:
		return nil, &TooSoon{RetryAfter: retryAfter(res.Header.Get("Retry-After"))}
	default:
		return nil, &Refused{Status: res.StatusCode, Text: errorText(raw)}
	}

	var a Answer
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&a); err != nil {
		return nil, fmt.Errorf("the cloud's answer is not a registration: %w", err)
	}
	if a.Format != registerFormat {
		return nil, fmt.Errorf("the cloud answered in format %d", a.Format)
	}
	if a.Token == "" || a.FactsURL == "" || a.IngestURL == "" {
		return nil, errors.New("the cloud's answer has no token or no addresses in it")
	}
	return &a, nil
}

// errorText pulls the cloud's own words out of the refusal, and falls
// back to the body when there are none: whatever answered is then not
// the cloud, and the owner should see what it was.
func errorText(raw []byte) string {
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &body); err == nil && body.Error != "" {
		return body.Error
	}
	text := strings.TrimSpace(string(raw))
	if len(text) > 200 {
		text = text[:200] + "…"
	}
	if text == "" {
		text = "no answer"
	}
	return text
}

func retryAfter(header string) time.Duration {
	var seconds int
	if _, err := fmt.Sscanf(strings.TrimSpace(header), "%d", &seconds); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return 24 * time.Hour
}
