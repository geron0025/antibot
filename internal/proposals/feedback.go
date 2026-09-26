package proposals

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/geron0025/antibot/internal/rules"
)

// FeedbackFileName is where the node remembers what it last told the
// cloud about each proposal and advice, in cloud.state_dir next to the
// aggregate's own outbox — so that a later cycle sends only what
// changed since the cloud last accepted a report.
const FeedbackFileName = "proposals-feedback.json"

const feedbackStateFormat = 1

// Backoff for the feedback channel, mirroring the aggregate sender's:
// the protocol says the two answer alike.
const (
	retryFeedbackUnauthorized = time.Hour
	retryFeedbackFirstFailure = time.Minute
	retryFeedbackMax          = 30 * time.Minute
	maxFeedbackFailures       = 20
)

// FeedbackURL derives <cloud.url without /ingest>/proposals/feedback —
// decision Д3 of the cloud's spec says the node finds it the same way
// it finds the registration address.
func FeedbackURL(cloudURL string) string {
	return "" // not implemented
}

// Sender posts what became of each decided proposal and each advice to
// the cloud — only the changes since the last report the cloud
// accepted. It runs only while sending the aggregate is enabled: a node
// with no token to speak to the cloud does not speak to it about this
// either.
type Sender struct {
	URL     string
	Token   string
	NodeID  string
	Version string
	Client  *http.Client

	// Decisions and Rules are where the answer is computed from: the
	// owner's own accept and reject, and the rule set as it stands
	// right now — he may have promoted a rule to active, disabled it or
	// deleted it since he accepted it.
	Decisions *Store
	Rules     *rules.Store

	// StateDir is cloud.state_dir, the same directory the aggregate's
	// outbox lives in.
	StateDir string

	Log *slog.Logger

	// now is replaced in tests.
	now func() time.Time

	failures int
	hint     time.Duration
}

func (s *Sender) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Sender) client() *http.Client {
	if s.Client == nil {
		s.Client = &http.Client{
			Timeout: time.Minute,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return s.Client
}

// Run posts on a schedule until the context ends, with the same jitter
// idea as the aggregate sender.
func (s *Sender) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	if s.Log == nil {
		s.Log = slog.Default()
	}
	s.client()

	for {
		s.hint = 0
		err := s.Once(ctx)
		if err != nil {
			s.Log.Debug("the proposals feedback was not sent", "err", err)
		}
		delay := s.nextDelay(err, interval)
		delay += time.Duration(rand.Int63n(int64(delay)/10 + 1))
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// Once computes the current answer, works out what changed since the
// last accepted report, and posts it — nothing, if nothing changed.
func (s *Sender) Once(ctx context.Context) error {
	if s.Log == nil {
		s.Log = slog.Default()
	}

	sent, err := readFeedbackState(s.StateDir)
	if err != nil {
		return err
	}

	decisions, err := s.Decisions.Decisions()
	if err != nil {
		return err
	}
	advice, err := s.Decisions.Advice()
	if err != nil {
		return err
	}
	var current []rules.Rule
	if set := s.Rules.Set(); set != nil {
		current = set.All()
	}

	items := computeItems(s.clock(), decisions, current, advice)

	var diff []Item
	for _, it := range items {
		if prev, ok := sent.Sent[it.ID]; ok && prev.State == it.State && prev.Rule == it.Rule {
			continue
		}
		diff = append(diff, it)
	}
	if len(diff) == 0 {
		s.failures = 0
		return nil
	}
	sort.Slice(diff, func(i, j int) bool { return diff[i].ID < diff[j].ID })
	if len(diff) > maxItemsPerPost {
		diff = diff[:maxItemsPerPost]
	}

	body := Feedback{
		Format: FormatVersion,
		Node:   s.NodeID,
		SentAt: s.clock().UTC().Format(time.RFC3339),
		Items:  diff,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(buf.Bytes()))
	if err != nil {
		s.Log.Error("the proposals feedback address is invalid", "url", s.URL, "err", err)
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("X-Antibot-Node", s.NodeID)
	if s.Version != "" {
		req.Header.Set("X-Antibot-Version", s.Version)
	}

	resp, err := s.client().Do(req)
	if err != nil {
		s.Log.Warn("the proposals feedback was not sent, will retry", "err", err)
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 512))

	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
		s.failures, s.hint = 0, 0
		for _, it := range diff {
			sent.Sent[it.ID] = sentItem{State: it.State, Rule: it.Rule}
		}
		return writeFeedbackState(s.StateDir, sent)

	case code == http.StatusBadRequest || code == http.StatusRequestEntityTooLarge:
		// The format was refused. Sending the same bytes again would
		// get the same answer, and treating this as an ordinary failure
		// would retry it every minute forever; the state is not marked
		// sent, so the next ordinary cycle simply tries again with
		// whatever has changed by then.
		s.failures, s.hint = 0, 0
		s.Log.Error("the cloud refused the proposals feedback format; not retried as is", "status", code)
		return nil

	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		s.hint = retryFeedbackUnauthorized
		s.Log.Error("the cloud did not accept the token for proposals feedback; sending sleeps for an hour",
			"status", code)
		return fmt.Errorf("the cloud did not accept the token (%d)", code)

	default:
		s.Log.Warn("the cloud did not take the proposals feedback, will retry", "status", code)
		return fmt.Errorf("the cloud answered %d", code)
	}
}

// nextDelay mirrors catalog.Fetcher.nextDelay: a cycle with nothing to
// report or with its report accepted returns to the ordinary schedule;
// an answer that named its own reason (401, 403) waits what it said;
// everything else grows from a minute, so that a long outage does not
// turn into a request per minute from every installation at once.
func (s *Sender) nextDelay(err error, interval time.Duration) time.Duration {
	if err == nil {
		s.failures = 0
		return interval
	}
	if s.hint > 0 {
		return s.hint
	}
	if s.failures < maxFeedbackFailures {
		s.failures++
	}
	delay := retryFeedbackFirstFailure << (s.failures - 1)
	if delay > retryFeedbackMax || delay <= 0 {
		delay = retryFeedbackMax
	}
	return delay
}

// computeItems works out the current answer for every decided proposal
// and every piece of advice, from the owner's decisions and the rule
// set as it stands right now. It is pure and holds no state of its own:
// Once decides, by comparing this against what was last sent, which of
// these are worth a post.
func computeItems(now time.Time, decisions []Decision, current []rules.Rule, advice []Advice) []Item {
	return nil // not implemented
}

type feedbackState struct {
	Format int                 `json:"format"`
	Sent   map[string]sentItem `json:"sent"`
}

type sentItem struct {
	State string `json:"state"`
	Rule  string `json:"rule,omitempty"`
}

func readFeedbackState(dir string) (feedbackState, error) {
	var st feedbackState
	raw, err := os.ReadFile(filepath.Join(dir, FeedbackFileName))
	if errors.Is(err, fs.ErrNotExist) {
		st.Format, st.Sent = feedbackStateFormat, map[string]sentItem{}
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return st, fmt.Errorf("%s: %w", FeedbackFileName, err)
	}
	if st.Sent == nil {
		st.Sent = map[string]sentItem{}
	}
	return st, nil
}

func writeFeedbackState(dir string, st feedbackState) error {
	st.Format = feedbackStateFormat
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeAtomic(filepath.Join(dir, FeedbackFileName), raw, 0o640)
}
