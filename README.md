# traefik-cert-watcher

Watches a certificates directory and automatically generates Traefik's `tls.yaml` dynamic configuration file.

## How it works

1. On startup, scans the certificate directory for cert/key pairs and writes `tls.yaml`
2. Watches the directory for filesystem changes using `fsnotify`
3. On change (debounced), re-scans and reconciles `tls.yaml` — updating it if the cert set changed, or touching it to trigger a Traefik reload if unchanged
4. Writes are atomic (temp file + rename) to avoid partial reads

## Certificate layouts

### Flat layout

Place certificate and key files directly in the certs directory:

```
/certs/
  example.com.crt
  example.com.key
  wildcard.example.com.cer
  wildcard.example.com.key
```

Supported certificate extensions: `.crt`, `.cer`. Keys must use `.key`.

### Subdirectory layout

Organize certificates into per-domain folders. The following naming conventions are tried in order:

1. `fullchain.pem` + `privkey.pem` (Let's Encrypt style)
2. `cert.pem` + `key.pem`
3. Fallback: first cert file + first key file found

```
/certs/
  example.com/
    fullchain.pem
    privkey.pem
  other.com/
    cert.pem
    key.pem
```

If a domain has both a flat-layout file and a subdirectory, the flat layout takes precedence.

## Usage

```yaml
# compose.yaml
services:
  traefik-cert-watcher:
    image: ghcr.io/metril/traefik-cert-watcher:latest
    restart: unless-stopped
    environment:
      PUID: "1000"
      PGID: "1000"
      CERTS_DIR: /certs
      TLS_YAML_PATH: /certs/tls.yaml
      # DEFAULT_CERT: example.com
      # DEBOUNCE_MS: "2000"
    volumes:
      - /opt/docker/certs:/certs
```

Mount the same `/certs` volume into your Traefik container and point a [file provider](https://doc.traefik.io/traefik/providers/file/) at `/certs/tls.yaml`.

## Configuration

All configuration is via environment variables.

| Variable | Default | Description |
|---|---|---|
| `PUID` | `1000` | UID the process runs as inside the container |
| `PGID` | `1000` | GID the process runs as inside the container |
| `CERTS_DIR` | `/certs` | Directory to watch for certificate files |
| `TLS_YAML_PATH` | `<CERTS_DIR>/tls.yaml` | Output path for the generated Traefik TLS config |
| `CERT_PATH_PREFIX` | `<CERTS_DIR>` | Path prefix used in generated cert/key paths (useful when the container mount differs from Traefik's view) |
| `DEFAULT_CERT` | *(none)* | Base name of the certificate pair to set as Traefik's default (e.g. `example.com`) |
| `DEBOUNCE_MS` | `2000` | Milliseconds to wait after a filesystem event before reconciling |

## Generated output

For a directory containing `example.com.crt`, `example.com.key`, and a `sub.example.com/` subdirectory with Let's Encrypt files, with `DEFAULT_CERT=example.com`:

```yaml
tls:
  certificates:
    - certFile: /certs/example.com.crt
      keyFile: /certs/example.com.key
    - certFile: /certs/sub.example.com/fullchain.pem
      keyFile: /certs/sub.example.com/privkey.pem
  stores:
    default:
      defaultCertificate:
        certFile: /certs/example.com.crt
        keyFile: /certs/example.com.key
```

## Building from source

```bash
# Binary
go build -o traefik-cert-watcher .

# Docker
docker build -t traefik-cert-watcher .
```

Images are published to `ghcr.io/metril/traefik-cert-watcher` for `linux/amd64` and `linux/arm64`.
