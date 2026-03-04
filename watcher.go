package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

type watcher struct {
	fsw         *fsnotify.Watcher
	certsDir    string
	pathPrefix  string
	tlsYamlPath string
	defaultCert string
	debounce    time.Duration
}

func newWatcher(cfg config) (*watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return &watcher{
		fsw:         fsw,
		certsDir:    cfg.certsDir,
		pathPrefix:  cfg.certPathPrefix,
		tlsYamlPath: cfg.tlsYamlPath,
		defaultCert: cfg.defaultCert,
		debounce:    cfg.debounceDelay,
	}, nil
}

// run starts watching the certs directory and blocks until ctx is canceled.
func (w *watcher) run(ctx context.Context) error {
	defer w.fsw.Close()

	if err := w.fsw.Add(w.certsDir); err != nil {
		return err
	}
	slog.Info("watching directory", "dir", w.certsDir)

	w.addSubdirectories(w.certsDir)

	var debounceTimer *time.Timer

	for {
		// Build the timer channel — nil if no timer is active (select skips nil channels).
		var timerC <-chan time.Time
		if debounceTimer != nil {
			timerC = debounceTimer.C
		}

		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return ctx.Err()

		case event, ok := <-w.fsw.Events:
			if !ok {
				return nil
			}

			// Handle new subdirectories (use Lstat to avoid following symlinks).
			if event.Has(fsnotify.Create) {
				if info, err := os.Lstat(event.Name); err == nil && info.IsDir() {
					if err := w.fsw.Add(event.Name); err != nil {
						slog.Warn("failed to watch new subdirectory", "dir", event.Name, "error", err)
					} else {
						slog.Info("watching new subdirectory", "dir", event.Name)
					}
					if debounceTimer != nil {
						debounceTimer.Stop()
					}
					debounceTimer = time.NewTimer(w.debounce)
					continue
				}
			}

			if !isRelevantEvent(event, w.tlsYamlPath) {
				continue
			}

			slog.Debug("relevant filesystem event", "op", event.Op.String(), "file", event.Name)
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.NewTimer(w.debounce)

		case err, ok := <-w.fsw.Errors:
			if !ok {
				return nil
			}
			slog.Error("fsnotify error", "error", err)

		case <-timerC:
			debounceTimer = nil

			changed, err := reconcile(w.certsDir, w.pathPrefix, w.tlsYamlPath, w.defaultCert)
			if err != nil {
				slog.Error("reconcile failed", "error", err)
			} else if changed {
				slog.Info("tls.yaml reconciled successfully")
			}
		}
	}
}

// addSubdirectories adds all immediate subdirectories to the fsnotify watcher.
func (w *watcher) addSubdirectories(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.Warn("failed to read directory for subdirectory watching", "dir", dir, "error", err)
		return
	}

	for _, e := range entries {
		// Skip non-directories and symlinks.
		if !e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			continue
		}
		subdir := filepath.Join(dir, e.Name())
		if err := w.fsw.Add(subdir); err != nil {
			slog.Warn("failed to watch subdirectory", "dir", subdir, "error", err)
		} else {
			slog.Info("watching subdirectory", "dir", subdir)
		}
	}
}

// isRelevantEvent checks if a filesystem event should trigger reconciliation.
func isRelevantEvent(event fsnotify.Event, tlsYamlPath string) bool {
	if event.Name == tlsYamlPath {
		return false
	}

	if !event.Has(fsnotify.Create) && !event.Has(fsnotify.Write) &&
		!event.Has(fsnotify.Remove) && !event.Has(fsnotify.Rename) {
		return false
	}

	ext := filepath.Ext(event.Name)
	return isCertExt(ext) || ext == ".key" || ext == ".pem"
}
