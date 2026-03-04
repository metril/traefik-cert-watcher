package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildNoCerts(t *testing.T) {
	cfg := buildTLSConfig(nil, "")
	if len(cfg.TLS.Certificates) != 0 {
		t.Errorf("expected 0 certificates, got %d", len(cfg.TLS.Certificates))
	}
	if cfg.TLS.Stores != nil {
		t.Error("expected no stores when no default cert")
	}
}

func TestBuildWithCerts(t *testing.T) {
	pairs := []certPair{
		{baseName: "example.com", certFile: "/certs/example.com.crt", keyFile: "/certs/example.com.key"},
		{baseName: "other.com", certFile: "/certs/other.com.crt", keyFile: "/certs/other.com.key"},
	}

	cfg := buildTLSConfig(pairs, "")
	if len(cfg.TLS.Certificates) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(cfg.TLS.Certificates))
	}
	if cfg.TLS.Certificates[0].CertFile != "/certs/example.com.crt" {
		t.Errorf("unexpected cert path: %s", cfg.TLS.Certificates[0].CertFile)
	}
}

func TestBuildWithDefaultCert(t *testing.T) {
	pairs := []certPair{
		{baseName: "example.com", certFile: "/certs/example.com.crt", keyFile: "/certs/example.com.key"},
		{baseName: "default.com", certFile: "/certs/default.com.crt", keyFile: "/certs/default.com.key"},
	}

	cfg := buildTLSConfig(pairs, "default.com")
	if cfg.TLS.Stores == nil {
		t.Fatal("expected stores to be set")
	}
	if cfg.TLS.Stores.Default.DefaultCertificate == nil {
		t.Fatal("expected default certificate to be set")
	}
	if cfg.TLS.Stores.Default.DefaultCertificate.CertFile != "/certs/default.com.crt" {
		t.Errorf("unexpected default cert: %s", cfg.TLS.Stores.Default.DefaultCertificate.CertFile)
	}
}

func TestBuildWithMissingDefaultCert(t *testing.T) {
	pairs := []certPair{
		{baseName: "example.com", certFile: "/certs/example.com.crt", keyFile: "/certs/example.com.key"},
	}

	cfg := buildTLSConfig(pairs, "nonexistent.com")
	if cfg.TLS.Stores != nil {
		t.Error("expected no stores when default cert doesn't match any pair")
	}
}

func TestEqualIdentical(t *testing.T) {
	a := tlsConfig{TLS: tlsSection{Certificates: []certificate{
		{CertFile: "/certs/a.crt", KeyFile: "/certs/a.key"},
		{CertFile: "/certs/b.crt", KeyFile: "/certs/b.key"},
	}}}
	b := tlsConfig{TLS: tlsSection{Certificates: []certificate{
		{CertFile: "/certs/a.crt", KeyFile: "/certs/a.key"},
		{CertFile: "/certs/b.crt", KeyFile: "/certs/b.key"},
	}}}
	if !tlsConfigsEqual(a, b) {
		t.Error("expected configs to be equal")
	}
}

func TestEqualDifferentOrder(t *testing.T) {
	a := tlsConfig{TLS: tlsSection{Certificates: []certificate{
		{CertFile: "/certs/a.crt", KeyFile: "/certs/a.key"},
		{CertFile: "/certs/b.crt", KeyFile: "/certs/b.key"},
	}}}
	b := tlsConfig{TLS: tlsSection{Certificates: []certificate{
		{CertFile: "/certs/b.crt", KeyFile: "/certs/b.key"},
		{CertFile: "/certs/a.crt", KeyFile: "/certs/a.key"},
	}}}
	if !tlsConfigsEqual(a, b) {
		t.Error("expected configs with different order to be equal")
	}
}

func TestEqualDifferentCerts(t *testing.T) {
	a := tlsConfig{TLS: tlsSection{Certificates: []certificate{
		{CertFile: "/certs/a.crt", KeyFile: "/certs/a.key"},
	}}}
	b := tlsConfig{TLS: tlsSection{Certificates: []certificate{
		{CertFile: "/certs/b.crt", KeyFile: "/certs/b.key"},
	}}}
	if tlsConfigsEqual(a, b) {
		t.Error("expected configs with different certs to not be equal")
	}
}

func TestEqualWithStores(t *testing.T) {
	a := tlsConfig{TLS: tlsSection{
		Certificates: []certificate{},
		Stores: &tlsStores{Default: defaultStore{
			DefaultCertificate: &certificate{CertFile: "/certs/default.crt", KeyFile: "/certs/default.key"},
		}},
	}}
	b := tlsConfig{TLS: tlsSection{Certificates: []certificate{}}}
	if tlsConfigsEqual(a, b) {
		t.Error("expected configs with different stores to not be equal")
	}
}

func TestWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tls.yaml")

	original := tlsConfig{TLS: tlsSection{
		Certificates: []certificate{
			{CertFile: "/certs/example.com.crt", KeyFile: "/certs/example.com.key"},
		},
		Stores: &tlsStores{Default: defaultStore{
			DefaultCertificate: &certificate{CertFile: "/certs/example.com.crt", KeyFile: "/certs/example.com.key"},
		}},
	}}

	if err := writeTLSConfig(path, original); err != nil {
		t.Fatal(err)
	}

	loaded, err := readTLSConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if !tlsConfigsEqual(original, loaded) {
		t.Error("written and read configs are not equal")
	}
}

func TestReadNonexistent(t *testing.T) {
	cfg, err := readTLSConfig("/nonexistent/tls.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TLS.Certificates) != 0 {
		t.Error("expected empty config for nonexistent file")
	}
}

func TestTouch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	os.WriteFile(path, []byte("test"), 0o644)

	past := time.Now().Add(-1 * time.Hour)
	os.Chtimes(path, past, past)
	before, _ := os.Stat(path)

	if err := touchFile(path); err != nil {
		t.Fatal(err)
	}

	after, _ := os.Stat(path)
	if !after.ModTime().After(before.ModTime()) {
		t.Error("expected mtime to be updated after touch")
	}
}

func TestReconcileCreatesFile(t *testing.T) {
	dir := t.TempDir()
	tlsPath := filepath.Join(dir, "tls.yaml")

	os.WriteFile(filepath.Join(dir, "example.com.crt"), []byte("cert"), 0o644)
	os.WriteFile(filepath.Join(dir, "example.com.key"), []byte("key"), 0o644)

	changed, err := reconcile(dir, "/certs", tlsPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("expected changed to be true")
	}
	if _, err := os.Stat(tlsPath); err != nil {
		t.Error("expected tls.yaml to be created")
	}

	cfg, err := readTLSConfig(tlsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TLS.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(cfg.TLS.Certificates))
	}
}

func TestReconcileTouchesUnchanged(t *testing.T) {
	dir := t.TempDir()
	tlsPath := filepath.Join(dir, "tls.yaml")

	os.WriteFile(filepath.Join(dir, "example.com.crt"), []byte("cert"), 0o644)
	os.WriteFile(filepath.Join(dir, "example.com.key"), []byte("key"), 0o644)

	reconcile(dir, "/certs", tlsPath, "")

	past := time.Now().Add(-1 * time.Hour)
	os.Chtimes(tlsPath, past, past)
	before, _ := os.Stat(tlsPath)

	changed, err := reconcile(dir, "/certs", tlsPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("expected changed to be true (touch)")
	}

	after, _ := os.Stat(tlsPath)
	if !after.ModTime().After(before.ModTime()) {
		t.Error("expected mtime to be updated")
	}
}

func TestReconcileUpdatesOnChange(t *testing.T) {
	dir := t.TempDir()
	tlsPath := filepath.Join(dir, "tls.yaml")

	os.WriteFile(filepath.Join(dir, "example.com.crt"), []byte("cert"), 0o644)
	os.WriteFile(filepath.Join(dir, "example.com.key"), []byte("key"), 0o644)

	reconcile(dir, "/certs", tlsPath, "")

	os.WriteFile(filepath.Join(dir, "new.com.crt"), []byte("cert"), 0o644)
	os.WriteFile(filepath.Join(dir, "new.com.key"), []byte("key"), 0o644)

	changed, err := reconcile(dir, "/certs", tlsPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("expected changed to be true")
	}

	cfg, err := readTLSConfig(tlsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TLS.Certificates) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(cfg.TLS.Certificates))
	}
}
