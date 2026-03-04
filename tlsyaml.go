package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

type tlsConfig struct {
	TLS tlsSection `yaml:"tls"`
}

type tlsSection struct {
	Certificates []certificate `yaml:"certificates"`
	Stores       *tlsStores    `yaml:"stores,omitempty"`
}

type certificate struct {
	CertFile string `yaml:"certFile"`
	KeyFile  string `yaml:"keyFile"`
}

type tlsStores struct {
	Default defaultStore `yaml:"default"`
}

type defaultStore struct {
	DefaultCertificate *certificate `yaml:"defaultCertificate,omitempty"`
}

// readTLSConfig parses an existing tls.yaml file. Returns zero-value if the file does not exist.
func readTLSConfig(path string) (tlsConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return tlsConfig{}, nil
		}
		return tlsConfig{}, fmt.Errorf("reading %q: %w", path, err)
	}

	var cfg tlsConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return tlsConfig{}, fmt.Errorf("parsing %q: %w", path, err)
	}
	return cfg, nil
}

// buildTLSConfig constructs a tlsConfig from discovered cert pairs and an optional default cert.
func buildTLSConfig(pairs []certPair, defaultCertBaseName string) tlsConfig {
	certs := make([]certificate, len(pairs))
	for i, p := range pairs {
		certs[i] = certificate{CertFile: p.certFile, KeyFile: p.keyFile}
	}

	cfg := tlsConfig{
		TLS: tlsSection{Certificates: certs},
	}

	if defaultCertBaseName != "" {
		for _, p := range pairs {
			if p.baseName == defaultCertBaseName {
				cfg.TLS.Stores = &tlsStores{
					Default: defaultStore{
						DefaultCertificate: &certificate{
							CertFile: p.certFile,
							KeyFile:  p.keyFile,
						},
					},
				}
				break
			}
		}
		if cfg.TLS.Stores == nil {
			slog.Warn("DEFAULT_CERT specified but no matching cert pair found", "defaultCert", defaultCertBaseName)
		}
	}

	return cfg
}

// writeTLSConfig serializes the config to the given path atomically (temp file + rename).
func writeTLSConfig(path string, cfg tlsConfig) error {
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("marshaling tls config: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tls-yaml-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}

	return os.Rename(tmpName, path)
}

// touchFile updates the mtime of the file without changing content.
func touchFile(path string) error {
	now := time.Now()
	return os.Chtimes(path, now, now)
}

// tlsConfigsEqual compares two configs for semantic equality (order-independent).
func tlsConfigsEqual(a, b tlsConfig) bool {
	if len(a.TLS.Certificates) != len(b.TLS.Certificates) {
		return false
	}

	aCerts := sortedCerts(a.TLS.Certificates)
	bCerts := sortedCerts(b.TLS.Certificates)
	for i := range aCerts {
		if aCerts[i] != bCerts[i] {
			return false
		}
	}

	aDefault := defaultCertFrom(a)
	bDefault := defaultCertFrom(b)
	return aDefault == bDefault
}

func defaultCertFrom(cfg tlsConfig) certificate {
	if cfg.TLS.Stores != nil && cfg.TLS.Stores.Default.DefaultCertificate != nil {
		return *cfg.TLS.Stores.Default.DefaultCertificate
	}
	return certificate{}
}

func sortedCerts(certs []certificate) []certificate {
	sorted := make([]certificate, len(certs))
	copy(sorted, certs)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CertFile < sorted[j].CertFile
	})
	return sorted
}

// reconcile discovers cert pairs, compares with existing tls.yaml, and updates as needed.
func reconcile(certsDir, pathPrefix, tlsYamlPath, defaultCert string) (bool, error) {
	pairs, err := discoverCertPairs(certsDir, pathPrefix, tlsYamlPath)
	if err != nil {
		return false, fmt.Errorf("discovering cert pairs: %w", err)
	}

	slog.Info("discovered certificate pairs", "count", len(pairs))

	desired := buildTLSConfig(pairs, defaultCert)

	existing, err := readTLSConfig(tlsYamlPath)
	if err != nil {
		return false, fmt.Errorf("reading existing config: %w", err)
	}

	if _, statErr := os.Stat(tlsYamlPath); statErr != nil {
		slog.Info("creating tls.yaml")
		return true, writeTLSConfig(tlsYamlPath, desired)
	}

	if tlsConfigsEqual(existing, desired) {
		slog.Info("cert set unchanged, touching tls.yaml to trigger reload")
		return true, touchFile(tlsYamlPath)
	}

	slog.Info("cert set changed, updating tls.yaml")
	return true, writeTLSConfig(tlsYamlPath, desired)
}
