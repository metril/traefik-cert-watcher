FROM golang:1.22-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /traefik-cert-watcher .

FROM alpine:3.20

RUN apk add --no-cache su-exec

COPY --from=builder /traefik-cert-watcher /usr/local/bin/traefik-cert-watcher
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN mkdir -p /certs

ENTRYPOINT ["/entrypoint.sh"]
