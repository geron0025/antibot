package aggregate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// Backoff after each kind of answer, from the protocol.
const (
	// The token is no good. It may be reissued, so it is worth trying
	// again, but not every minute.
	retryAfterUnauthorized = time.Hour

	// The cloud is out of shape: 1, 2, 4… minutes up to half an hour.
	retryAfterFirstFailure = time.Minute
	retryAfterMax          = 30 * time.Minute

	// maxFailures keeps the shift from overflowing on a node that has
	// been cut off for a year; the delay hits its ceiling long before.
	maxFailures = 20
)

type outcome int

const (
	accepted outcome = iota
	rejected
	unauthorized
	retry
)

// sender takes batches out of the outbox and posts them.
//
// It lives in its own goroutine, and nothing on the hot path waits for
// it: an unreachable cloud costs the node a line in the log and nothing
// else.
type sender struct {
	url     string
	token   string
	node    string
	version string
	client  *http.Client
	outbox  *outbox
	log     *slog.Logger

	// failures counts consecutive failed attempts, for the backoff.
	failures int

	// wake is poked when a new batch lands in the outbox.
	wake chan struct{}
}

func newClient() *http.Client {
	return &http.Client{
		Timeout: time.Minute,
		// Redirects are not followed: the address is configuration, and
		// a redirect to a foreign host would carry the subscription
		// token there.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (s *sender) run(ctx context.Context) {
	for {
		delay := s.drain(ctx)
		if delay == 0 {
			select {
			case <-ctx.Done():
				return
			case <-s.wake:
			}
			continue
		}

		// Jitter, so that installations cut off by the same outage do
		// not all come back at the same second.
		delay += time.Duration(rand.Int63n(int64(delay)/10 + 1))
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// drain posts what is in the outbox, oldest first, and returns how long
// to wait before the next attempt — zero when nothing is left.
//
// The oldest first and one at a time: the batch that failed is retried
// before anything newer, so the cloud receives the windows in order.
func (s *sender) drain(ctx context.Context) time.Duration {
	ids, err := s.outbox.list()
	if err != nil {
		s.log.Error("the outbox was not read", "err", err)
		return retryAfterMax
	}

	for _, id := range ids {
		if ctx.Err() != nil {
			return 0
		}

		body, err := s.outbox.read(id)
		if errors.Is(err, fs.ErrNotExist) {
			continue // trimmed while we were busy
		}
		if err != nil {
			// A batch that cannot be read would block the outbox forever
			// if it stayed at its head.
			s.log.Error("an unreadable batch is dropped from the outbox", "batch", id, "err", err)
			s.outbox.remove(id)
			continue
		}

		switch s.post(ctx, id, body) {
		case accepted:
			s.failures = 0
			s.outbox.remove(id)
		case rejected:
			s.failures = 0
			s.outbox.remove(id)
		case unauthorized:
			return retryAfterUnauthorized
		default:
			return s.backoff()
		}
	}
	return 0
}

func (s *sender) backoff() time.Duration {
	if s.failures < maxFailures {
		s.failures++
	}
	delay := retryAfterFirstFailure << (s.failures - 1)
	if delay > retryAfterMax || delay <= 0 {
		delay = retryAfterMax
	}
	return delay
}

// post sends one batch and turns the answer into what the protocol says
// to do next.
func (s *sender) post(ctx context.Context, id string, body []byte) outcome {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		s.log.Error("the aggregate address is invalid", "url", s.url, "err", err)
		return retry
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("X-Antibot-Node", s.node)
	if s.version != "" {
		req.Header.Set("X-Antibot-Version", s.version)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		s.log.Warn("the aggregate was not sent, will retry", "batch", id, "err", err)
		return retry
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
		s.log.Debug("the aggregate was accepted", "batch", id)
		return accepted

	case code == http.StatusBadRequest || code == http.StatusRequestEntityTooLarge:
		// The format was refused. Sending the same bytes again would get
		// the same answer, and a batch stuck at the head would hold back
		// everything behind it.
		s.log.Error("the cloud refused the aggregate format; the batch is dropped, not retried",
			"batch", id, "status", code, "answer", strings.TrimSpace(string(answer)))
		return rejected

	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		s.log.Error("the cloud did not accept the token; sending sleeps for an hour",
			"status", code)
		return unauthorized

	default:
		s.log.Warn("the cloud did not take the aggregate, will retry",
			"batch", id, "status", code)
		return retry
	}
}
