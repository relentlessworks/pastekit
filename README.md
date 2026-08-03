# pastekit

Agentic-first pastebin service. Create, share, and manage text snippets with TTL. Plain text API, agent-driven, single Go binary with JSON file storage.

## Quick Start

```bash
# Build
make build

# Run (defaults to :8470)
./pastekit

# Or with go run
go run ./cmd/pastekit
```

## API Reference

### Auth

```bash
# 1. Request OTP
curl -X POST http://localhost:8470/auth/request -d "email=user@example.com"

# 2. Verify OTP (code is logged to stderr if no SMTP configured)
curl -X POST http://localhost:8470/auth/verify -d "email=user@example.com&code=123456"
# → token=abc123... email=user@example.com expires=...
```

### Pastes

```bash
# Create a paste
curl -X POST http://localhost:8470/pastes \
  -H "Authorization: Bearer <token>" \
  -d "content=Hello, world!&title=Test&language=go&visibility=public"

# List pastes
curl http://localhost:8470/pastes -H "Authorization: Bearer <token>"

# Get a paste (public/unlisted don't need auth)
curl http://localhost:8470/pastes/paste_abc12

# Update a paste
curl -X PATCH http://localhost:8470/pastes/paste_abc12 \
  -H "Authorization: Bearer <token>" \
  -d "content=Updated content"

# Delete a paste
curl -X DELETE http://localhost:8470/pastes/paste_abc12 \
  -H "Authorization: Bearer <token>"
```

### Other Endpoints

```bash
# Workspace info
curl http://localhost:8470/workspace -H "Authorization: Bearer <token>"

# Audit log
curl http://localhost:8470/audit -H "Authorization: Bearer <token>"

# Health check
curl http://localhost:8470/health

# Help / agent manual
curl http://localhost:8470/help

# MCP endpoint
curl -X POST http://localhost:8470/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}'
```

## Response Formats

- **Plain text** (default): one record per line, `key=value` pairs
- **JSON**: send `Accept: application/json` or `?format=json`

## Visibility Levels

| Level | Auth to create | Auth to view |
|-------|---------------|-------------|
| public | yes | no |
| unlisted | yes | no |
| private | yes | yes |

## TTL Options

- `1h` — expires in 1 hour
- `24h` — expires in 24 hours
- `7d` — expires in 7 days
- `30d` — expires in 30 days
- empty — permanent until deleted

## Configuration

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| -addr | PASTEKIT_ADDR | :8470 | Listen address |
| -db | PASTEKIT_DB | pastekit.json | JSON storage file |
| -secret | PASTEKIT_SECRET | (auto) | Token signing secret |
| -smtp-host | PASTEKIT_SMTP_HOST | (empty) | SMTP server host |
| -smtp-port | PASTEKIT_SMTP_PORT | 587 | SMTP server port |
| -smtp-user | PASTEKIT_SMTP_USER | (empty) | SMTP username |
| -smtp-pass | PASTEKIT_SMTP_PASS | (empty) | SMTP password |
| -from-email | PASTEKIT_FROM_EMAIL | noreply@pastekit.local | From email for OTP |

## Build

```bash
make build    # CGO_ENABLED=0, static binary
make test     # go test -race
make vet      # go vet
```

## License

MIT
