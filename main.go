package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

type config struct {
	certsDir       string
	tlsYamlPath    string
	certPathPrefix string
	defaultCert    string
	debounceDelay  time.Duration
}

func loadConfig() config {
	certsDir := envOrDefault("CERTS_DIR", "/certs")
	tlsYamlPath := envOrDefault("TLS_YAML_PATH", filepath.Join(certsDir, "tls.yaml"))
	certPathPrefix := envOrDefault("CERT_PATH_PREFIX", certsDir)
	defaultCert := os.Getenv("DEFAULT_CERT")

	debounceMs, err := strconv.Atoi(envOrDefault("DEBOUNCE_MS", "2000"))
	if err != nil || debounceMs < 0 {
		debounceMs = 2000
	}

	return config{
		certsDir:       certsDir,
		tlsYamlPath:    tlsYamlPath,
		certPathPrefix: certPathPrefix,
		defaultCert:    defaultCert,
		debounceDelay:  time.Duration(debounceMs) * time.Millisecond,
	}
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg := loadConfig()
	slog.Info("starting traefik-cert-watcher",
		"certsDir", cfg.certsDir,
		"tlsYamlPath", cfg.tlsYamlPath,
		"certPathPrefix", cfg.certPathPrefix,
		"defaultCert", cfg.defaultCert,
		"debounceMs", cfg.debounceDelay.Milliseconds(),
	)

	if _, err := os.Stat(cfg.certsDir); err != nil {
		slog.Error("certs directory does not exist", "dir", cfg.certsDir, "error", err)
		os.Exit(1)
	}

	changed, err := reconcile(cfg.certsDir, cfg.certPathPrefix, cfg.tlsYamlPath, cfg.defaultCert)
	if err != nil {
		slog.Error("initial reconciliation failed", "error", err)
		os.Exit(1)
	}
	if changed {
		slog.Info("initial tls.yaml written")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	w, err := newWatcher(cfg)
	if err != nil {
		slog.Error("failed to create watcher", "error", err)
		os.Exit(1)
	}

	slog.Info("watching for certificate changes")
	if err := w.run(ctx); err != nil && err != context.Canceled {
		slog.Error("watcher exited with error", "error", err)
		os.Exit(1)
	}

	slog.Info("shutting down gracefully")
}
