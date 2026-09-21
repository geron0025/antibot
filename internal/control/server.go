package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"
)

// Listen takes the socket. A socket left at the path by a core that died
// is removed first. A socket somebody answers on is another core, and a
// file that is not a socket is somebody else's: either stops the start
// rather than being taken over.
//
// The socket is 0660: the core's user and the group the admin UI is in.
// Nobody else on the machine may ask the core anything.
func Listen(path string) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("control.socket %s: the path is taken by something that is not a socket", path)
		}
		if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
			conn.Close()
			return nil, fmt.Errorf("control.socket %s: another core answers on it", path)
		}
		os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("control.socket %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, fmt.Errorf("control.socket %s: %w", path, err)
	}
	return ln, nil
}

// Serve answers on the socket until ctx is done.
func Serve(ctx context.Context, ln net.Listener, core Core, log *slog.Logger) error {
	srv := &http.Server{
		Handler:           Handler(core, log),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	log.Info("listening on the control socket", "path", ln.Addr().String())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("control socket: %w", err)
	}
	return nil
}

// cloudAnswer is the body of the two cloud requests that carry the
// checkboxes.
type cloudAnswer struct {
	Facts      bool `json:"facts"`
	Aggregates bool `json:"aggregates"`
}

type reloadRequest struct {
	What Reloadable `json:"what"`
}

type testResult struct {
	Result string `json:"result"`
}

// problem is an error on the wire. Refusal says the text is meant for a
// human as it is.
type problem struct {
	Error   string `json:"error"`
	Refusal bool   `json:"refusal,omitempty"`
}

// Handler is the socket's routes. Separate from Serve so that a test can
// exercise them without a socket.
func Handler(core Core, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	get := func(path string, f func(ctx context.Context) (any, error)) {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			v, err := f(r.Context())
			reply(w, v, err)
		})
	}
	// decode reads the request's body into v; each request gets its own.
	type decode func(v any) error
	post := func(path string, f func(ctx context.Context, body decode) (any, error)) {
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			body := func(v any) error {
				if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(v); err != nil {
					return fmt.Errorf("the request: %w", err)
				}
				return nil
			}
			v, err := f(r.Context(), body)
			if err != nil {
				log.Warn("a control request was not carried out", "path", path, "err", err)
			}
			reply(w, v, err)
		})
	}

	get("/health", func(ctx context.Context) (any, error) { return core.Health(ctx) })
	get("/alerts", func(ctx context.Context) (any, error) { return core.Alerts(ctx) })
	get("/cloud", func(ctx context.Context) (any, error) { return core.Cloud(ctx) })
	get("/certificates", func(ctx context.Context) (any, error) { return core.Certificates(ctx) })
	get("/routes", func(ctx context.Context) (any, error) { return core.Routes(ctx) })

	post("/stop", func(ctx context.Context, _ decode) (any, error) {
		log.Warn("the core was asked to stop over the control socket")
		return nil, core.Stop(ctx)
	})
	post("/alerts/test", func(ctx context.Context, _ decode) (any, error) {
		result, err := core.TestAlert(ctx)
		return testResult{Result: result}, err
	})
	post("/cloud/answer", func(ctx context.Context, body decode) (any, error) {
		var a cloudAnswer
		if err := body(&a); err != nil {
			return nil, err
		}
		return nil, core.CloudAnswer(ctx, a.Facts, a.Aggregates)
	})
	post("/cloud/register", func(ctx context.Context, body decode) (any, error) {
		var a cloudAnswer
		if err := body(&a); err != nil {
			return nil, err
		}
		return nil, core.CloudRegister(ctx, a.Facts, a.Aggregates)
	})
	post("/cloud/forget", func(ctx context.Context, _ decode) (any, error) {
		return nil, core.CloudForget(ctx)
	})
	post("/reload", func(ctx context.Context, body decode) (any, error) {
		var req reloadRequest
		if err := body(&req); err != nil {
			return nil, err
		}
		return nil, core.Reload(ctx, req.What)
	})

	return mux
}

func reply(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		p := problem{Error: err.Error()}
		var refusal *Refusal
		if errors.As(err, &refusal) {
			p.Refusal = true
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(p)
		return
	}
	if v == nil {
		v = struct{}{}
	}
	json.NewEncoder(w).Encode(v)
}
