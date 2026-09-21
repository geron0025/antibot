package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Client asks the core over its socket. It implements Core, so the admin
// UI cannot tell it from the core itself — apart from the errors: a core
// that is down answers every question with ErrUnreachable.
type Client struct {
	path string
	http *http.Client
}

// ErrUnreachable is a core that does not answer on its socket: stopped,
// restarting, or never started.
var ErrUnreachable = errors.New("the core does not answer")

// NewClient makes a client for the socket at path. Nothing is dialled
// until the first question: the admin UI starts whether or not the core
// is up, and says which on every page.
func NewClient(path string) *Client {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	return &Client{
		path: path,
		http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return dialer.DialContext(ctx, "unix", path)
				},
				MaxIdleConns:    4,
				IdleConnTimeout: 30 * time.Second,
			},
			// Registration with the cloud is the longest thing asked:
			// the core waits for the cloud itself.
			Timeout: 60 * time.Second,
		},
	}
}

func (c *Client) Health(ctx context.Context) (Health, error) {
	var h Health
	return h, c.call(ctx, "GET", "/health", nil, &h)
}

func (c *Client) Stop(ctx context.Context) error {
	return c.call(ctx, "POST", "/stop", nil, nil)
}

func (c *Client) Alerts(ctx context.Context) (Alerts, error) {
	var a Alerts
	return a, c.call(ctx, "GET", "/alerts", nil, &a)
}

func (c *Client) TestAlert(ctx context.Context) (string, error) {
	var r testResult
	err := c.call(ctx, "POST", "/alerts/test", nil, &r)
	return r.Result, err
}

func (c *Client) Cloud(ctx context.Context) (CloudState, error) {
	var s CloudState
	return s, c.call(ctx, "GET", "/cloud", nil, &s)
}

func (c *Client) CloudAnswer(ctx context.Context, facts, aggregates bool) error {
	return c.call(ctx, "POST", "/cloud/answer", cloudAnswer{facts, aggregates}, nil)
}

func (c *Client) CloudRegister(ctx context.Context, facts, aggregates bool) error {
	return c.call(ctx, "POST", "/cloud/register", cloudAnswer{facts, aggregates}, nil)
}

func (c *Client) CloudForget(ctx context.Context) error {
	return c.call(ctx, "POST", "/cloud/forget", nil, nil)
}

func (c *Client) Certificates(ctx context.Context) ([]Certificate, error) {
	var list []Certificate
	return list, c.call(ctx, "GET", "/certificates", nil, &list)
}

func (c *Client) Routes(ctx context.Context) (map[string]string, error) {
	var routes map[string]string
	return routes, c.call(ctx, "GET", "/routes", nil, &routes)
}

func (c *Client) Reload(ctx context.Context, what Reloadable) error {
	return c.call(ctx, "POST", "/reload", reloadRequest{What: what}, nil)
}

func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	// The host is a placeholder: the transport dials the socket whatever
	// the URL names.
	req, err := http.NewRequestWithContext(ctx, method, "http://core"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUnreachable, c.path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var p problem
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&p); err != nil || p.Error == "" {
			return fmt.Errorf("the core answered %s to %s", resp.Status, path)
		}
		if p.Refusal {
			return Refuse(p.Error)
		}
		return errors.New(p.Error)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("the core's answer to %s: %w", path, err)
	}
	return nil
}
