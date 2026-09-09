package catalog

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// maxSetSize caps what the node is willing to read into memory.
//
// Eighteen thousand networks in gzip are single-digit megabytes; sixty-
// four is room for growth and still not enough for a wrong answer to
// matter. Without a cap the node reads whatever the far side sends, and
// the far side is reachable by anyone who got hold of the address.
const maxSetSize = 64 << 20

// Backoff after each kind of refusal. The numbers come from the
// protocol, and the differences between them are the point.
const (
	// A revoked or unknown token: it may have been reissued, so it is
	// worth asking again soon.
	retryAfterUnauthorized = time.Hour

	// The subscription does not cover the bases. Nothing will change
	// before the end of the day, and the base has frozen — which is not
	// the same as the protection being lifted.
	retryAfterForbidden = 24 * time.Hour

	// The cloud is out of shape. Grows from a minute; six hours is
	// enough that a long outage does not turn into a request every
	// minute from every installation at once.
	retryAfterFirstFailure = time.Minute
	retryAfterMax          = 6 * time.Hour
)

// Fetcher downloads fact sets from the update service.
//
// It is the only place in the node that talks to the cloud about facts,
// and it can do exactly two things: ask for a manifest and ask for a
// set. It has no way to influence a decision — everything it downloads
// goes through Store.Install and the five checks there.
type Fetcher struct {
	Store   *Store
	BaseURL string
	Token   string
	NodeID  string
	Version string
	Client  *http.Client
	Log     *slog.Logger

	// failures counts consecutive unsuccessful cycles — one per cycle,
	// not per request. A cycle makes several requests, and counting each
	// of them would double the delay for one outage.
	failures int

	// hint is a delay the answer itself named: a refused token and an
	// expired subscription are not "the cloud is out of shape" and are
	// not retried on the same schedule.
	hint time.Duration
}

// maxFailures caps the shift in the backoff. The delay hits its ceiling
// long before this; the cap exists so the shift cannot overflow on a
// node that has been offline for a year.
const maxFailures = 20

// NewFetcher assembles a fetcher. A nil return means fetching is not
// configured, and that is a normal state: a node without a token has no
// addressee.
func NewFetcher(store *Store, baseURL, token, nodeID, version string, log *slog.Logger) *Fetcher {
	if store == nil || !store.Enabled() || baseURL == "" || token == "" {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}
	return &Fetcher{
		Store:   store,
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		Token:   token,
		NodeID:  nodeID,
		Version: version,
		Client: &http.Client{
			Timeout: 5 * time.Minute,
			// Redirects are not followed: the address of the update
			// service is configuration, not something the far side gets
			// to change mid-conversation. A redirect to a foreign host
			// would also carry the subscription token there.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Log: log,
	}
}

// Run fetches on a schedule until the context ends.
//
// The interval carries jitter of up to a tenth: without it every
// installation started from the same image asks at the same second, and
// the update service sees a daily spike of its own making.
func (f *Fetcher) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	for {
		f.hint = 0
		err := f.Once(ctx)
		if err != nil {
			f.Log.Error("the fact set was not fetched, the previous one stays in force", "err", err)
		}

		sleep := f.nextDelay(err, interval)
		sleep += time.Duration(rand.Int63n(int64(sleep)/10 + 1))

		select {
		case <-ctx.Done():
			return
		case <-time.After(sleep):
		}
	}
}

// Once makes one attempt: the keys, then the manifest, then the set.
func (f *Fetcher) Once(ctx context.Context) error {
	// The keys first: a set signed by a key that arrived today verifies
	// only if the key is already in the ring. Failures here are not
	// fatal — the built-in keys stay in force.
	if err := f.fetchKeys(ctx); err != nil {
		f.Log.Debug("the key list was not fetched", "err", err)
	}

	manifestRaw, manifest, fresh, err := f.fetchManifest(ctx)
	if err != nil || !fresh {
		return err
	}

	body, err := f.fetchSet(ctx, manifest.Version)
	if err != nil {
		return err
	}

	_, err = f.Store.Install(manifestRaw, body, false)
	if errors.Is(err, ErrShrunk) {
		// Not applied and not retried until a human looks: a shrunken
		// base is more dangerous than a stale one.
		f.Log.Error("the fact set shrank sharply and was not applied; check what is missing, "+
			"then `antibot facts apply -force`", "err", err)
		f.hint = retryAfterForbidden
		return nil
	}
	return err
}

// nextDelay decides how long to wait after an attempt.
//
// Three cases, and keeping them apart is the whole point: a successful
// cycle waits the ordinary interval; an answer that named its own reason
// waits what the protocol says for that reason; everything else grows
// from a minute, so that a long outage does not turn into a request per
// minute from every installation at once.
func (f *Fetcher) nextDelay(err error, interval time.Duration) time.Duration {
	if err == nil {
		f.failures = 0
		return interval
	}
	if f.hint > 0 {
		return f.hint
	}
	if f.failures < maxFailures {
		f.failures++
	}
	delay := retryAfterFirstFailure << (f.failures - 1)
	if delay > retryAfterMax || delay <= 0 {
		delay = retryAfterMax
	}
	return delay
}

func manifestHeaders(f *Fetcher) map[string]string {
	h := map[string]string{}
	if v := f.Store.Current().Version(); v > 0 {
		h["If-None-Match"] = `"` + strconv.Itoa(v) + `"`
	}
	return h
}

// fetchManifest returns the manifest bytes, the parsed manifest and
// whether it is worth downloading the set at all.
//
// The bytes are carried out rather than re-requested: Install verifies
// the signature over exactly what arrived, and asking twice would both
// waste a request and open a gap between what was checked and what was
// applied.
func (f *Fetcher) fetchManifest(ctx context.Context) ([]byte, *Manifest, bool, error) {
	raw, err := f.get(ctx, "/manifest?format="+strconv.Itoa(FormatVersion), manifestHeaders(f))
	if errors.Is(err, errNotModified) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, err
	}

	m, err := ParseManifest(raw)
	if err != nil {
		return nil, nil, false, err
	}
	if current := f.Store.Current().Version(); m.Version <= current {
		return nil, nil, false, nil
	}
	return raw, m, true, nil
}

func (f *Fetcher) fetchSet(ctx context.Context, version int) ([]byte, error) {
	return f.get(ctx, "/set/"+strconv.Itoa(version), nil)
}

func (f *Fetcher) fetchKeys(ctx context.Context) error {
	raw, err := f.get(ctx, "/keys", nil)
	if err != nil {
		return err
	}
	return f.Store.Keyring().LoadBytes(raw)
}

var errNotModified = errors.New("not modified")

// get performs one request and turns the answer into what the protocol
// says the node should do.
func (f *Fetcher) get(ctx context.Context, path string, extra map[string]string) ([]byte, error) {
	if _, err := url.Parse(f.BaseURL + path); err != nil {
		return nil, fmt.Errorf("fact set address: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+f.Token)
	req.Header.Set("Accept", "application/json")
	if f.NodeID != "" {
		req.Header.Set("X-Antibot-Node", f.NodeID)
	}
	if f.Version != "" {
		req.Header.Set("X-Antibot-Version", f.Version)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}

	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		f.failures, f.hint = 0, 0

	case http.StatusNotModified:
		f.failures, f.hint = 0, 0
		return nil, errNotModified

	case http.StatusUnauthorized:
		// The token is no good. The node keeps working on the last set:
		// a revoked token is a reason to stop updating, never a reason
		// to stop protecting.
		f.hint = retryAfterUnauthorized
		f.Log.Error("the update service did not accept the token; the node keeps working "+
			"on the fact set it already has", "status", resp.StatusCode)
		return nil, fmt.Errorf("the token was not accepted (%d)", resp.StatusCode)

	case http.StatusForbidden, http.StatusPaymentRequired:
		// The subscription does not cover the bases. The base freezes,
		// the protection stays: rules keep working, network classes stay
		// known, only their freshness goes stale.
		f.hint = retryAfterForbidden
		f.Log.Warn("the subscription does not cover the fact bases: the base has frozen at the "+
			"version already applied, the rules keep working",
			"status", resp.StatusCode, "version", f.Store.Current().Version())
		return nil, fmt.Errorf("the subscription does not cover the bases (%d)", resp.StatusCode)

	default:
		return nil, fmt.Errorf("the update service answered %d", resp.StatusCode)
	}

	body := io.Reader(io.LimitReader(resp.Body, maxSetSize+1))
	// Go decompresses transparently only when it asked for gzip itself.
	// The protocol says the set arrives gzipped, so an explicit
	// Content-Encoding has to be unwrapped by hand.
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(body)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer zr.Close()
		body = io.LimitReader(zr, maxSetSize+1)
	}

	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSetSize {
		return nil, fmt.Errorf("the answer is larger than the %d-byte limit", maxSetSize)
	}
	return raw, nil
}
