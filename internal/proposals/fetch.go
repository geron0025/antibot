package proposals

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/geron0025/antibot/internal/catalog"
	"github.com/geron0025/antibot/internal/schemacheck"
)

// FileName is where the verified list lives, next to rules.json.
const FileName = "proposals.json"

// Backoff after each kind of answer — the protocol's own error policy
// for this channel, kept apart from the fact set fetcher's: a tier
// without facts_and_analysis answers every request here with 403, and
// that must never slow down the fact sets sharing the same address and
// the same token.
const (
	retryAfterUnauthorized = time.Hour
	retryAfterForbidden    = 24 * time.Hour
	retryAfterFirstFailure = time.Minute
	retryAfterMax          = 6 * time.Hour
	maxFailures            = 20
)

// Fetcher downloads the cloud's proposals for this node, checks them,
// and keeps the verified list on disk.
//
// It shares Source's address, token and identity — the same facts.url
// and the same subscription cover proposals, docs/*/protocol/proposals.md
// says so explicitly — but keeps its own failure count and its own
// backoff hint, through GetSigned rather than through Source's Once.
type Fetcher struct {
	// Source is the fact set fetcher for this node. Only GetSigned is
	// called on it; nothing here reads or writes its fact-set state.
	Source *catalog.Fetcher

	// Keyring is what the node trusts — normally Source.Store.Keyring(),
	// the very ring the fact set signature is checked against, because
	// keys of both uses arrive together over /keys. A key of the wrong
	// use is refused by Keyring.Verify before the mathematics runs.
	Keyring *catalog.Keyring

	// Dir is the shared directory rules.json lives in; the verified
	// list is written to Dir/proposals.json, next to it.
	Dir string

	// Served reports whether this node serves a domain — the same
	// predicate the router uses, so a proposal cannot address a site
	// this node never claimed to protect.
	Served func(host string) bool

	Log *slog.Logger

	failures int
	hint     time.Duration
	lastETag string
}

// Run fetches on a schedule until the context ends, with the same
// jitter idea as the fact set fetcher: a burst of installations built
// from one image must not ask at the same second forever.
func (f *Fetcher) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	if f.Log == nil {
		f.Log = slog.Default()
	}

	for {
		f.hint = 0
		err := f.Once(ctx)
		if err != nil {
			f.Log.Debug("the proposals were not fetched", "err", err)
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

// Once makes one attempt: fetch, verify in the order the protocol
// lists, and only on success replace the file on disk. Any failed
// check leaves the previous list exactly as it was and writes a line to
// the log — the protocol's own words for it.
func (f *Fetcher) Once(ctx context.Context) error {
	if f.Log == nil {
		f.Log = slog.Default()
	}

	path := "/proposals?format=" + strconv.Itoa(FormatVersion)
	body, signature, etag, status, err := f.Source.GetSigned(ctx, path, f.lastETag)
	if err != nil {
		return err
	}

	switch status {
	case http.StatusNotModified:
		f.failures, f.hint = 0, 0
		return nil

	case http.StatusUnauthorized:
		f.hint = retryAfterUnauthorized
		f.Log.Error("proposals were not fetched: the token was not accepted; "+
			"the previous list stays in force", "status", status)
		return fmt.Errorf("the token was not accepted (%d)", status)

	case http.StatusForbidden, http.StatusPaymentRequired:
		f.hint = retryAfterForbidden
		f.Log.Warn("proposals were not fetched: the subscription does not cover them; "+
			"the previous list stays in force", "status", status)
		return fmt.Errorf("the subscription does not cover proposals (%d)", status)

	case http.StatusOK:
		// Falls through to verification below.

	default:
		return fmt.Errorf("the update service answered %d for /proposals", status)
	}

	f.failures, f.hint = 0, 0

	if err := f.verify(body, signature); err != nil {
		f.Log.Error("the proposals were not applied, the previous list stays in force", "err", err)
		return err
	}

	if err := writeAtomic(filepath.Join(f.Dir, FileName), body, 0o640); err != nil {
		return err
	}
	f.lastETag = etag
	return nil
}

// verify runs every check the protocol requires, in the order it lists
// them, over the bytes exactly as they arrived: the signature is over
// those bytes, and re-encoding the document before checking it would
// mean checking something that was never signed.
func (f *Fetcher) verify(body []byte, signature string) error {
	keyID, sigB64, ok := strings.Cut(signature, ":")
	if !ok || keyID == "" || sigB64 == "" {
		return fmt.Errorf("X-Antibot-Signature %q is not key_id:signature", signature)
	}
	digest := sha256.Sum256(body)
	if err := f.Keyring.Verify(keyID, catalog.UseProposals, digest[:], sigB64, time.Now()); err != nil {
		return fmt.Errorf("signature: %w", err)
	}

	var generic map[string]any
	if err := json.Unmarshal(body, &generic); err != nil {
		return fmt.Errorf("not a JSON document: %w", err)
	}
	if node, _ := generic["node"].(string); node != f.Source.NodeID {
		return fmt.Errorf("proposals addressed to node %q, this node is %q", node, f.Source.NodeID)
	}
	if errs := schemacheck.Validate(proposalsSchema, generic); len(errs) > 0 {
		return fmt.Errorf("schema: %s", strings.Join(errs, "; "))
	}

	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("document: %w", err)
	}

	served := func(host string) bool {
		if f.Served == nil {
			return false
		}
		return f.Served(host)
	}

	for i := range doc.Proposals {
		p := &doc.Proposals[i]
		if !strings.HasPrefix(p.ID, "cloud-") {
			return fmt.Errorf("proposal id %q does not start with cloud-", p.ID)
		}
		if !strings.HasPrefix(p.Rule.ID, "cloud-") {
			return fmt.Errorf("rule id %q does not start with cloud-", p.Rule.ID)
		}
		for _, scope := range p.Rule.Scope {
			if scope != "*" && !served(scope) {
				return fmt.Errorf("proposal %q scopes a domain this node does not serve: %q", p.ID, scope)
			}
		}
		built := p.asRule()
		if _, err := built.Compile(); err != nil {
			return fmt.Errorf("proposal %q does not compile as a rule: %w", p.ID, err)
		}
	}
	for i := range doc.Advice {
		a := &doc.Advice[i]
		if !strings.HasPrefix(a.ID, "cloud-") {
			return fmt.Errorf("advice id %q does not start with cloud-", a.ID)
		}
	}
	return nil
}

// nextDelay mirrors catalog.Fetcher.nextDelay: a success returns to the
// ordinary schedule, an answer that named its own reason waits what the
// protocol says for that reason, and everything else grows from a
// minute so that a long outage does not turn into a request per minute
// from every installation at once.
func (f *Fetcher) nextDelay(err error, interval time.Duration) time.Duration {
	return interval // not implemented
}
