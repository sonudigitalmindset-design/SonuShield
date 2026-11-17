# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/main .

# Runtime stage: minimal image with only what the binary needs.
FROM alpine:3.21

# ca-certificates: the proxy fetches TLS fingerprint lists and version info
# over HTTPS at startup, so a CA bundle must be present.
# libcap: used once at build time to grant the binary cap_net_bind_service,
# so it can bind ports 80/443 while running as a non-root user.
RUN apk add --no-cache ca-certificates libcap \
    && adduser -D -H -s /sbin/nologin appuser

WORKDIR /app

COPY --from=builder /out/main ./main
# The assets/ directory is copied for convention: examples/config.json uses
# certificate paths under assets/server/, but no certificate or key is
# committed to this repository. Provide your own certificates by mounting
# them into the container (see README.md). Challenge pages are generated
# inline by the binary and fingerprint lists are fetched over HTTPS at
# startup, so no other repo files are needed here.
COPY assets/ ./assets/

RUN setcap 'cap_net_bind_service=+ep' /app/main \
    && chown -R appuser:appuser /app

# The proxy reads config.json from its working directory and writes crash.log
# there, so provide your config as a mounted file, e.g.:
#   docker run -d -p 80:80 -p 443:443 -v /path/to/config.json:/app/config.json sonushield
USER appuser

EXPOSE 80 443

CMD ["./main"]
