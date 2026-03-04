package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type certPair struct {
	baseName string // domain name, e.g. "example.com"
	certFile string // path as written into tls.yaml
	keyFile  string // path as written into tls.yaml
}

// certExts is the set of recognized certificate file extensions.
var certExts = map[string]bool{".crt": true, ".cer": true}

func isCertExt(ext string) bool { return certExts[ext] }

// certKeyConvention defines a pair of filenames to look for inside a subdirectory.
type certKeyConvention struct {
	certName string
	keyName  string
}

// subdirConventions are tried in order; first match wins.
var subdirConventions = []certKeyConvention{
	{"fullchain.pem", "privkey.pem"},
	{"cert.pem", "key.pem"},
}

// discoverCertPairs scans dir for certificate/key pairs in both flat and subdirectory layouts.
// Paths in the returned pairs use pathPrefix instead of dir.
func discoverCertPairs(dir, pathPrefix, tlsYamlPath string) ([]certPair, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	pairs := make(map[string]certPair)

	// Pass 1: flat layout — .crt/.cer/.key files in root
	certFiles := make(map[string]string) // base name → extension
	keyFiles := make(map[string]bool)

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Join(dir, e.Name()) == tlsYamlPath {
			continue
		}
		ext := filepath.Ext(e.Name())
		base := strings.TrimSuffix(e.Name(), ext)
		switch {
		case isCertExt(ext):
			certFiles[base] = ext
		case ext == ".key":
			keyFiles[base] = true
		}
	}

	for base, ext := range certFiles {
		if keyFiles[base] {
			pairs[base] = certPair{
				baseName: base,
				certFile: filepath.Join(pathPrefix, base+ext),
				keyFile:  filepath.Join(pathPrefix, base+".key"),
			}
			delete(keyFiles, base)
		} else {
			slog.Warn("orphaned certificate file (no matching .key)", "file", base+ext)
		}
	}
	for base := range keyFiles {
		slog.Warn("orphaned key file (no matching cert)", "file", base+".key")
	}

	// Pass 2: subdirectory layout
	for _, e := range entries {
		if !e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			continue
		}
		domainName := e.Name()
		if _, exists := pairs[domainName]; exists {
			slog.Info("flat layout takes precedence over subdirectory", "domain", domainName)
			continue
		}

		subdir := filepath.Join(dir, domainName)
		if pair, ok := discoverSubdir(subdir, domainName, pathPrefix); ok {
			pairs[domainName] = pair
		}
	}

	result := make([]certPair, 0, len(pairs))
	for _, p := range pairs {
		result = append(result, p)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].baseName < result[j].baseName
	})
	return result, nil
}

// discoverSubdir tries known naming conventions, then falls back to first cert+key pair.
func discoverSubdir(subdir, domainName, pathPrefix string) (certPair, bool) {
	for _, conv := range subdirConventions {
		certPath := filepath.Join(subdir, conv.certName)
		keyPath := filepath.Join(subdir, conv.keyName)
		if fileExists(certPath) && fileExists(keyPath) {
			return certPair{
				baseName: domainName,
				certFile: filepath.Join(pathPrefix, domainName, conv.certName),
				keyFile:  filepath.Join(pathPrefix, domainName, conv.keyName),
			}, true
		}
	}

	// Fallback: first cert + first key found in the subdirectory
	entries, err := os.ReadDir(subdir)
	if err != nil {
		slog.Warn("cannot read subdirectory", "dir", subdir, "error", err)
		return certPair{}, false
	}

	var certFile, keyFile string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if isCertExt(ext) && certFile == "" {
			certFile = e.Name()
		}
		if ext == ".key" && keyFile == "" {
			keyFile = e.Name()
		}
	}

	if certFile != "" && keyFile != "" {
		return certPair{
			baseName: domainName,
			certFile: filepath.Join(pathPrefix, domainName, certFile),
			keyFile:  filepath.Join(pathPrefix, domainName, keyFile),
		}, true
	}

	if certFile != "" || keyFile != "" {
		slog.Warn("incomplete certificate pair in subdirectory", "dir", domainName)
	}
	return certPair{}, false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
