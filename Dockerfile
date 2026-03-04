FROM golang:1.22-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /traefik-cert-watcher .

FROM alpine:3.20

RUN addgroup -S app && adduser -S -G app app

COPY --from=builder /traefik-cert-watcher /usr/local/bin/traefik-cert-watcher

RUN mkdir -p /certs && chown app:app /certs

USER app

ENTRYPOINT ["traefik-cert-watcher"]
