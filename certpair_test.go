package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverFlatLayout(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "example.com.crt"), "cert")
	writeFile(t, filepath.Join(dir, "example.com.key"), "key")
	writeFile(t, filepath.Join(dir, "other.com.crt"), "cert")
	writeFile(t, filepath.Join(dir, "other.com.key"), "key")
	writeFile(t, filepath.Join(dir, "orphan.crt"), "cert") // no matching key

	pairs, err := discoverCertPairs(dir, "/certs", filepath.Join(dir, "tls.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(pairs))
	}
	if pairs[0].baseName != "example.com" {
		t.Errorf("expected first pair to be example.com, got %s", pairs[0].baseName)
	}
	if pairs[1].baseName != "other.com" {
		t.Errorf("expected second pair to be other.com, got %s", pairs[1].baseName)
	}
	if pairs[0].certFile != "/certs/example.com.crt" {
		t.Errorf("expected /certs/example.com.crt, got %s", pairs[0].certFile)
	}
	if pairs[0].keyFile != "/certs/example.com.key" {
		t.Errorf("expected /certs/example.com.key, got %s", pairs[0].keyFile)
	}
}

func TestDiscoverFlatCerLayout(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "example.com.cer"), "cert")
	writeFile(t, filepath.Join(dir, "example.com.key"), "key")

	pairs, err := discoverCertPairs(dir, "/certs", filepath.Join(dir, "tls.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0].certFile != "/certs/example.com.cer" {
		t.Errorf("expected /certs/example.com.cer, got %s", pairs[0].certFile)
	}
	if pairs[0].keyFile != "/certs/example.com.key" {
		t.Errorf("expected /certs/example.com.key, got %s", pairs[0].keyFile)
	}
}

func TestDiscoverSubdirLetsEncrypt(t *testing.T) {
	dir := t.TempDir()

	subdir := filepath.Join(dir, "example.com")
	os.Mkdir(subdir, 0o755)
	writeFile(t, filepath.Join(subdir, "fullchain.pem"), "cert")
	writeFile(t, filepath.Join(subdir, "privkey.pem"), "key")

	pairs, err := discoverCertPairs(dir, "/certs", filepath.Join(dir, "tls.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0].certFile != "/certs/example.com/fullchain.pem" {
		t.Errorf("expected /certs/example.com/fullchain.pem, got %s", pairs[0].certFile)
	}
	if pairs[0].keyFile != "/certs/example.com/privkey.pem" {
		t.Errorf("expected /certs/example.com/privkey.pem, got %s", pairs[0].keyFile)
	}
}

func TestDiscoverSubdirCertPem(t *testing.T) {
	dir := t.TempDir()

	subdir := filepath.Join(dir, "example.com")
	os.Mkdir(subdir, 0o755)
	writeFile(t, filepath.Join(subdir, "cert.pem"), "cert")
	writeFile(t, filepath.Join(subdir, "key.pem"), "key")

	pairs, err := discoverCertPairs(dir, "/certs", filepath.Join(dir, "tls.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0].certFile != "/certs/example.com/cert.pem" {
		t.Errorf("expected /certs/example.com/cert.pem, got %s", pairs[0].certFile)
	}
}

func TestDiscoverSubdirCrtKeyFallback(t *testing.T) {
	dir := t.TempDir()

	subdir := filepath.Join(dir, "example.com")
	os.Mkdir(subdir, 0o755)
	writeFile(t, filepath.Join(subdir, "server.crt"), "cert")
	writeFile(t, filepath.Join(subdir, "server.key"), "key")

	pairs, err := discoverCertPairs(dir, "/certs", filepath.Join(dir, "tls.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0].certFile != "/certs/example.com/server.crt" {
		t.Errorf("expected /certs/example.com/server.crt, got %s", pairs[0].certFile)
	}
}

func TestDiscoverSubdirCerFallback(t *testing.T) {
	dir := t.TempDir()

	subdir := filepath.Join(dir, "example.com")
	os.Mkdir(subdir, 0o755)
	writeFile(t, filepath.Join(subdir, "server.cer"), "cert")
	writeFile(t, filepath.Join(subdir, "server.key"), "key")

	pairs, err := discoverCertPairs(dir, "/certs", filepath.Join(dir, "tls.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0].certFile != "/certs/example.com/server.cer" {
		t.Errorf("expected /certs/example.com/server.cer, got %s", pairs[0].certFile)
	}
}

func TestDiscoverMixedLayout(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "flat.com.crt"), "cert")
	writeFile(t, filepath.Join(dir, "flat.com.key"), "key")

	subdir := filepath.Join(dir, "subdir.com")
	os.Mkdir(subdir, 0o755)
	writeFile(t, filepath.Join(subdir, "fullchain.pem"), "cert")
	writeFile(t, filepath.Join(subdir, "privkey.pem"), "key")

	pairs, err := discoverCertPairs(dir, "/certs", filepath.Join(dir, "tls.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(pairs))
	}
}

func TestDiscoverFlatPrecedence(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "example.com.crt"), "flat-cert")
	writeFile(t, filepath.Join(dir, "example.com.key"), "flat-key")

	subdir := filepath.Join(dir, "example.com")
	os.Mkdir(subdir, 0o755)
	writeFile(t, filepath.Join(subdir, "fullchain.pem"), "subdir-cert")
	writeFile(t, filepath.Join(subdir, "privkey.pem"), "subdir-key")

	pairs, err := discoverCertPairs(dir, "/certs", filepath.Join(dir, "tls.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0].certFile != "/certs/example.com.crt" {
		t.Errorf("expected flat layout path /certs/example.com.crt, got %s", pairs[0].certFile)
	}
}

func TestDiscoverIgnoresTLSYaml(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "tls.yaml"), "existing content")
	writeFile(t, filepath.Join(dir, "example.com.crt"), "cert")
	writeFile(t, filepath.Join(dir, "example.com.key"), "key")

	pairs, err := discoverCertPairs(dir, "/certs", filepath.Join(dir, "tls.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
}

func TestDiscoverEmptyDir(t *testing.T) {
	dir := t.TempDir()

	pairs, err := discoverCertPairs(dir, "/certs", filepath.Join(dir, "tls.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	if len(pairs) != 0 {
		t.Fatalf("expected 0 pairs, got %d", len(pairs))
	}
}

func TestDiscoverPathPrefix(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "example.com.crt"), "cert")
	writeFile(t, filepath.Join(dir, "example.com.key"), "key")

	pairs, err := discoverCertPairs(dir, "/custom/path", filepath.Join(dir, "tls.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	if pairs[0].certFile != "/custom/path/example.com.crt" {
		t.Errorf("expected /custom/path/example.com.crt, got %s", pairs[0].certFile)
	}
	if pairs[0].keyFile != "/custom/path/example.com.key" {
		t.Errorf("expected /custom/path/example.com.key, got %s", pairs[0].keyFile)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
