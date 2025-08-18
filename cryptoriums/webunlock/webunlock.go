package webunlock

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cosmossdk.io/log"
)

// WaitForUnlock starts a tiny HTTP server to accept a GPG passphrase,
// decrypts one pass-store entry to warm gpg-agent cache, then shuts down.
// - Uses the app logger (required; must be non-nil).
// - Rate limiting: after 10 failed attempts, lock for 60s.
// - Returns raw stderr text from gpg on failure (no string matching).
func WaitForUnlock(logger log.Logger) error {
	addr := "0.0.0.0:8080"
	ctx := context.Background()
	store := os.ExpandEnv("$HOME/.password-store")

	entryPath, err := firstGPG(store)
	if err != nil {
		return fmt.Errorf("no entries to unlock: %w", err)
	}

	// If already unlocked (agent cache), skip UI.
	if err := tryDecrypt(ctx, entryPath, ""); err == nil {
		logger.Info("webunlock: already unlocked (agent cache OK)", "entry", entryPath)
		return nil
	}

	page := template.Must(template.New("p").Parse(`<!doctype html>
<title>Unlock pass store</title>
<style>
body{font-family:sans-serif;margin:2rem}
label{min-width:10em;display:inline-block;margin:.35rem 0}
.notice{color:#c00}
.ok{color:#060}
</style>
<body>
<p>Store: <code>{{.Store}}</code> · Entry: <code>{{.Entry}}</code></p>
{{if .Locked}}<p class="notice">Too many failures. Try again in {{.Wait}}.</p>{{end}}
{{if .Err}}<p class="notice">{{.Err}}</p>{{end}}
{{if .Ok}}<p class="ok">{{.Ok}}</p>{{end}}
<form method="post">
  <label for="decryptPass">GPG passphrase:</label>
  <input id="decryptPass" name="decryptPass" type="password" autofocus>
  <button>Unlock</button>
</form>
</body>`))

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Never let a panic kill the server; also log it.
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("webunlock: panic recovered", "remote", r.RemoteAddr, "panic", rec)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()

		// Rate-limit gate
		if d, locked := checkGate(); locked {
			logger.Warn("webunlock: rate limited", "remote", r.RemoteAddr, "wait", d.String())
			err := page.Execute(w, map[string]any{
				"Store": store, "Entry": entryPath, "Locked": true, "Wait": d.Truncate(time.Second),
			})
			if err != nil {
				logger.Error("webunlock: failed to render page", "remote", r.RemoteAddr, "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
			return
		}

		var errMsg, okMsg string

		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				logger.Error("webunlock: bad form data", "remote", r.RemoteAddr, "err", err)
				http.Error(w, "bad form data", http.StatusBadRequest)
				return
			}
			pw := r.FormValue("decryptPass")
			if pw == "" {
				// Treat empty as wrong input; don't send empty silently.
				noteFailure()
				errMsg = "Empty passphrase. Try again."
				logger.Warn("webunlock: empty passphrase", "remote", r.RemoteAddr)
			} else if err := tryDecrypt(r.Context(), entryPath, pw); err == nil {
				noteSuccess()
				okMsg = "Sucker! Try another day!"
				logger.Info("webunlock: unlocked", "remote", r.RemoteAddr, "entry", entryPath)
				fmt.Fprint(w, okMsg)
				go shutdown()
				return
			} else {
				noteFailure()
				// Return raw error text to user and log it.
				errMsg = "unlock failed"
				logger.Error("webunlock: unlock failed", "remote", r.RemoteAddr, "err", strings.TrimSpace(err.Error()))
			}
		}

		err := page.Execute(w, map[string]any{
			"Store": store, "Entry": entryPath, "Err": errMsg, "Ok": okMsg,
		})
		if err != nil {
			logger.Error("webunlock: failed to render page", "remote", r.RemoteAddr, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// If we reach here, the page was rendered successfully.
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	shutdown = func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := srv.Shutdown(ctx2)
		if err != nil {
			logger.Error("webunlock: shutdown error", "err", err)
		}
		logger.Info("webunlock: http server shut down")
	}

	logger.Info("webunlock: listening", "addr", "http://"+addr, "entry", entryPath)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		} else {
			errCh <- nil
		}
	}()

	select {
	case <-ctx.Done():
		_ = srv.Shutdown(context.Background())
		logger.Warn("webunlock: context canceled")
		return ctx.Err()
	case err := <-errCh:
		if err != nil {
			logger.Error("webunlock: server error", "err", err)
		}
		return err
	}
}

var shutdown = func() {}

// ---- Rate limiting: 10 fails → 60s lock ----

var (
	mu           sync.Mutex
	failCount    int
	lockUntil    time.Time
	maxFails     = 10
	lockDuration = time.Minute
)

func checkGate() (time.Duration, bool) {
	mu.Lock()
	defer mu.Unlock()
	if time.Now().Before(lockUntil) {
		return time.Until(lockUntil), true
	}
	return 0, false
}
func noteFailure() {
	mu.Lock()
	defer mu.Unlock()
	failCount++
	if failCount >= maxFails {
		lockUntil = time.Now().Add(lockDuration)
		failCount = 0
	}
}
func noteSuccess() {
	mu.Lock()
	defer mu.Unlock()
	failCount = 0
	lockUntil = time.Time{}
}

// ---- Helpers ----

func firstGPG(store string) (string, error) {
	var found string
	err := filepath.Walk(store, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".gpg") && found == "" {
			found = p
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("no *.gpg files in %s", store)
	}
	return found, nil
}

// tryDecrypt decrypts one entry to prime gpg-agent cache.
// On failure, returns raw stderr text from gpg (no matching/translation).
func tryDecrypt(ctx context.Context, file string, pass string) error {
	var stderr bytes.Buffer

	c := exec.CommandContext(ctx, "gpg",
		"--batch", "--yes",
		"--pinentry-mode", "loopback",
		"--passphrase-fd", "0",
		"-d", file,
	)

	if pass == "" {
		pass = "\n" // harmless if cached; required for fd 0
	}
	in, err := c.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe error: %w", err)
	}
	go func() {
		_, _ = io.WriteString(in, pass)
		_ = in.Close()
	}()

	c.Stdout = io.Discard
	c.Stderr = &stderr

	if err := c.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}
