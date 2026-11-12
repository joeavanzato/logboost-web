# LogBoost Web

A self-hosted **network intelligence platform** for security analysts. Paste any text, log file, or threat-intel feed; LogBoost Web extracts every IP and domain, enriches them with GeoIP, ASN, DNS, WHOIS, Shodan InternetDB, and threat-intel matches, then lets you pivot through the relationships in a graph view. Ships as a single Docker container with HTTPS enabled by default.

![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)
![Python](https://img.shields.io/badge/Python-3.12-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

<!-- TODO: replace with a real screenshot -->
<!-- ![LogBoost Web screenshot](docs/screenshot.png) -->

## 60-Second Quickstart

You need **Docker** and **Docker Compose**. Everything else (DB schemas, threat feeds, SSL cert) is auto-provisioned.

```bash
# 1. Generate a secret key — REQUIRED. The app refuses to start without one.
python -c "import secrets; print(secrets.token_hex(32))"

# 2. Save this docker-compose.yml (replace SECRET_KEY with the value from step 1)
cat > docker-compose.yml <<'EOF'
services:
  logboost-web:
    image: ghcr.io/joeavanzato/logboost-web:latest
    ports:
      - "8443:8443"
    environment:
      SECRET_KEY: "PASTE_GENERATED_KEY_HERE"
      FLASK_ENV: production
      SSL_COMMON_NAME: "localhost"
    volumes:
      - logboost-db:/data/db
      - logboost-maxmind:/data/maxmind
      - logboost-intel:/data/intel
      - logboost-config:/data/config
      - logboost-ssl:/data/ssl
    restart: unless-stopped

volumes:
  logboost-db:
  logboost-maxmind:
  logboost-intel:
  logboost-config:
  logboost-ssl:
EOF

# 3. Start the container
docker compose up -d

# 4. Get the one-time setup token from the log
docker compose logs logboost-web | grep "setup token"

# 5. Open https://localhost:8443 — accept the self-signed cert warning, then create your admin account using the token
```

That's it. On first visit you'll be prompted to create an admin user, then walked through MaxMind setup (upload `.mmdb` files or paste a free MaxMind API key). Threat intel feeds auto-populate from the bundled config.

> **Note on the cert warning:** the container generates a self-signed SSL cert on first boot. Browsers will warn — that's expected. For production, mount your own cert (see [SSL Configuration](#sslhttps-configuration)).

## FAQ

**Q: What do I need API keys for?**
Nothing critical. Geo, DNS, WHOIS, Shodan InternetDB, and threat intel matching all work without any API keys (though MaxMind's auto-update needs a free key — the manual `.mmdb` upload path doesn't). Paid keys unlock advanced features like Shodan search, ViewDNS pivots, and CIRCL passive DNS history. See the [API Integrations table](#api-integrations) below.

**Q: Will it run on a Raspberry Pi / ARM?**
The image is built for `linux/amd64`. ARM users should rebuild from source — the Dockerfile works on both architectures.

**Q: How big is `threats.db`?**
Around 400-500 MB after the first threat-intel update, with ~8M IP entries indexed. Expect ~2-3 minutes for the initial download/build on first run.

**Q: Can I use it without exposing it to the internet?**
Recommended. Bind it to `127.0.0.1:8443` or put it behind your VPN / Tailscale / Wireguard / reverse proxy. The admin panel doesn't have brute-force protection yet (planned).

**Q: How do I back up my data?**
A backup script ships with the container at `/app/scripts/backup.sh`. Schedule it from **Admin Panel → Settings → Backup Schedule**. Backups go to the `logboost-backups` volume; copy them off-host with `docker cp` or a host bind-mount.

**Q: How do I upgrade?**
`docker compose pull && docker compose up -d`. Volumes persist across upgrades; the SQLite admin DB has no migrations (yet) so backwards-compatibility is currently best-effort.

---

## Features

### Core Enrichment

- **Ad-hoc IP Enrichment** - Paste any text (logs, firewall output, SIEM exports), automatically extract and enrich all IP addresses
- **File Upload Processing** - Upload logs (CSV, JSON, TXT, LOG, GZ, CEF, Syslog) for batch processing with regex IP detection, full parse mode, and raw text fallback
- **MaxMind GeoLite2 Geolocation** - Country, city, and ASN data for every IP (upload MMDB files manually or auto-update via API key)
- **Threat Intelligence Matching** - Match IPs against configurable feeds; built-in feed list included, custom feeds supported

### DNS Enrichment (No API Key Required)

- **Reverse DNS (PTR)** - Resolve IP addresses to hostnames
- **Forward DNS Resolution** - A, AAAA, CNAME, MX, NS, TXT, SOA record types
- **Bulk Concurrent Resolution** - Configurable concurrency for large datasets
- **Configurable DNS Servers** - Use any resolver; cache TTL configurable per Admin Settings

### WHOIS Lookups (No API Key Required)

- **Domain Registration Data** - Registrant name, email, organization
- **Registrar Information** - Registrar name and dates
- **Creation and Expiration Dates** - Parsed and normalized
- **Name Servers** - Full NS list
- **Bulk Concurrent Lookups** - Up to 100 domains per request with result caching

### Shodan InternetDB (No API Key Required)

- **Open Ports and Services** - What's listening on an IP
- **Host Tags** - Cloud provider, VPN, proxy, Tor exit, honeypot labels
- **CPEs** - Common Platform Enumeration identifiers
- **Known Vulnerabilities (CVEs)** - Publicly disclosed issues for the host

### Optional API Integrations

- **Full Shodan API** - Search queries, IP pivots, account info (requires paid API key)
- **CIRCL Passive DNS** - Historical DNS associations for IPs and domains (free, registration required)
- **ViewDNS** - Reverse MX, Reverse NS, Reverse WHOIS pivoting (paid)
- **HackerTarget** - Shared nameserver discovery (free limited tier or paid)
- **Chaos (ProjectDiscovery)** - Subdomain enumeration from bug bounty program datasets (free API key)

### Admin Dashboard

- **Scheduled Tasks** - Auto-update GeoIP databases and threat intel feeds on configurable intervals
- **User Management** - Multi-user support with audit logging
- **API Key Management** - Configure all integration credentials in one place
- **Task Logs** - Full execution history with error tracking

### User Experience

- **Drag and Drop Upload** - Easy file upload interface
- **Paginated Results** - Handle large datasets in-browser
- **CSV Export** - Download enriched results
- **Shareable Links** - Share results with expiring links (configurable TTL)
- **Dark Theme** - Security-focused aesthetic

---

## What Works Without API Keys

If you upload the three MaxMind MMDB files (or use a MaxMind API key to download them), the following features work with no other configuration:

- All IP geolocation and ASN lookups (MaxMind GeoLite2)
- Threat intelligence matching (after running Update Threat Intel at least once)
- Shodan InternetDB enrichment (open ports, tags, CVEs) - uses the free public API
- DNS resolution and reverse DNS lookups
- WHOIS domain lookups
- File upload and batch processing
- Result sharing with expiring links

**API keys unlock additional capabilities:**

| Capability | Requires |
|-----------|---------|
| Automatic MaxMind database updates | MaxMind API key (free) |
| Full Shodan search and pivot queries | Shodan paid API key |
| Passive DNS history (domain/IP associations) | CIRCL account (free) |
| Reverse MX / Reverse NS / Reverse WHOIS | ViewDNS paid API key |
| Shared nameserver discovery | HackerTarget API key (free tier available) |
| Subdomain enumeration | Chaos API key (free) |

---

## Detailed Setup

The [60-Second Quickstart](#60-second-quickstart) above gets you running. This section covers the parts you may want to know more about once it's up.

### Endpoints

- **Main UI:** https://localhost:8443
- **Admin Panel:** https://localhost:8443/admin
- **Health check:** https://localhost:8443/health (use `curl -k` for self-signed certs)

### MaxMind GeoIP Setup

On first launch you'll see a setup screen prompting you to configure MaxMind databases. You need all three: `GeoLite2-ASN.mmdb`, `GeoLite2-Country.mmdb`, `GeoLite2-City.mmdb`.

**Option A — Upload existing files:** drag and drop them on the setup page.

**Option B — Auto-download:** create a free MaxMind account, generate an API key, paste it in **Admin → Settings → MaxMind API Key**, then click **Update Geolocation** on the dashboard. Schedule recurring updates from **Admin → Scheduled Tasks**.

---

## API Integrations

Configure all integrations in **Admin Panel -> Settings**. All API keys are stored encrypted in the database.

| Service | Purpose | API Key Required | Tier | Get Access |
|---------|---------|-----------------|------|-----------|
| **MaxMind** | Auto-download GeoLite2 database updates | Required for auto-update | Free | [Sign up](https://www.maxmind.com/en/geolite2/signup) |
| **Shodan** | Full Shodan API queries, search, pivots | Optional (InternetDB is free) | Paid | [shodan.io](https://www.shodan.io/) |
| **CIRCL** | Passive DNS historical records (username + password) | Required | Free (registration) | [circl.lu](https://www.circl.lu/services/passive-dns/) |
| **ViewDNS** | Reverse MX, Reverse NS, Reverse WHOIS | Required | Paid | [viewdns.info/api](https://viewdns.info/api/) |
| **HackerTarget** | Shared nameserver discovery | Optional (limited free tier) | Free/Paid | [hackertarget.com](https://hackertarget.com/ip-tools/) |
| **Chaos** | Subdomain enumeration (ProjectDiscovery dataset) | Required | Free | [chaos.projectdiscovery.io](https://chaos.projectdiscovery.io/) |

---

## SSL/HTTPS Configuration

LogBoost Web serves HTTPS on port 8443 by default. SSL certificates are managed automatically.

### Zero Configuration (Default)

On first startup, the container generates a self-signed SSL certificate:

- **Certificate location:** `/data/ssl/cert.pem` and `/data/ssl/key.pem`
- **Validity:** 10 years from generation
- **Common Name:** Value of `SSL_COMMON_NAME` env var (default: `localhost`)

The certificate is stored in the `logboost-ssl` volume and persists across container restarts.

### Using Custom Certificates

For production deployments, mount your own certificates:

**Option 1: Bind mount individual files**

```yaml
services:
  logboost-web:
    volumes:
      - /etc/ssl/certs/logboost.crt:/data/ssl/cert.pem:ro
      - /etc/ssl/private/logboost.key:/data/ssl/key.pem:ro
```

**Option 2: Mount certificate directory**

```yaml
services:
  logboost-web:
    volumes:
      - /etc/ssl/logboost:/data/ssl:ro
```

Your certificate directory must contain:
- `cert.pem` - PEM-encoded X.509 certificate
- `key.pem` - PEM-encoded private key (must match certificate)

The container validates that the certificate and key match on startup. If they don't match, the container fails with an error message.

### SSL Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SSL_PORT` | `8443` | Port for HTTPS access |
| `SSL_COMMON_NAME` | `localhost` | CN for auto-generated certificate |

### HTTPS-Only Mode

LogBoost Web serves HTTPS only. HTTP is not available. The health check endpoint (`/health`) is accessible via HTTPS.

For production deployments requiring advanced features, consider using a reverse proxy (nginx, Traefik) for:
- Automatic certificate renewal (Let's Encrypt)
- HTTP to HTTPS redirect
- Custom TLS configuration

---

## Configuration

### Environment Variables

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `SECRET_KEY` | (none) | **Yes** | Flask session signing key. Generate with `secrets.token_hex(32)` |
| `FLASK_ENV` | `production` | No | `production` enables secure cookies; `development` allows HTTP cookies |
| `SSL_PORT` | `8443` | No | HTTPS port for secure access |
| `SSL_COMMON_NAME` | `localhost` | No | Common Name (CN) for auto-generated self-signed certificate |
| `LOGBOOST_PATH` | `/app/logboost` | No | Path to LogBoost binary inside container |
| `MAXMIND_DIR` | `/data/maxmind` | No | Directory for MaxMind .mmdb files |
| `THREAT_DB_DIR` | `/data/intel` | No | Directory for threat intelligence database |
| `LOGBOOST_DB_PATH` | `/data/db/logboost_admin.db` | No | Path to admin SQLite database |
| `LOGBOOST_LOG_LEVEL` | `info` | No | Logging verbosity (`debug`, `info`, `warning`, `error`) |

### Generating a Secure Secret Key

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### Volume Mounts

| Volume | Purpose |
|--------|---------|
| `/data/db` | Admin database (users, settings, audit logs) |
| `/data/maxmind` | MaxMind GeoLite2 .mmdb files |
| `/data/intel` | Threat intelligence database |
| `/data/config` | Feed configuration (feed_config.json) |
| `/data/cache` | DNS, WHOIS, and enrichment caches |
| `/data/ssl` | SSL certificates (auto-generated or custom) |
| `/app/uploads` | Temporary file upload storage |
| `/app/output` | Processed output files |

### Cache Settings

All cache TTLs are configurable in **Admin Panel -> Settings**:

| Cache | Default TTL | Configurable |
|-------|------------|-------------|
| DNS cache TTL | 1 hour (3600s) | Yes |
| WHOIS cache TTL | 24 hours (86400s) | Yes |
| Shodan cache TTL | 1 hour (3600s) | Yes |
| CIRCL PDNS cache TTL | 7 days (604800s) | Yes |
| ViewDNS cache TTL | 24 hours (86400s) | Yes |
| HackerTarget cache TTL | 24 hours (86400s) | Yes |
| Chaos cache TTL | 24 hours (86400s) | Yes |

---

## Admin Panel

### First-Time Setup

On first launch, you'll be prompted to create an admin account. This requires a one-time setup token that the container writes to its log (`docker compose logs logboost-web | grep "setup token"`), so only someone with access to the host can claim the instance. There are no default credentials - you choose your own username and password during setup.

### Quick Actions

- **Update Geolocation** - Download latest MaxMind databases (requires MaxMind API key)
- **Update Threat Intel** - Refresh all configured threat indicator feeds
- **Upload MMDB Files** - Manually upload database files without an API key
- **Check for Updates** - Check and install LogBoost binary updates (Docker mode)

### Scheduled Tasks

Configure automatic updates:

- Set update intervals (hours)
- Enable or disable individual tasks
- View full execution history and logs

### User Management

- Create additional admin accounts
- Change passwords
- View audit logs for all user actions

---

## Backup & Restore

A POSIX shell script ships with the container at `/app/scripts/backup.sh` and handles both backup and restore for the two SQLite databases that hold your state: `logboost_admin.db` (users, settings, audit logs, saved graphs) and `threats.db` (threat-intel IOCs).

### Scheduling backups

Configure automatic backups from **Admin Panel → Settings → Backup Schedule**. Files land in the `logboost-backups` volume by default. To copy them off-host, either bind-mount the volume or use `docker cp`:

```bash
docker cp logboost-web:/data/backups ./local-backups
```

### Restore

The restore subcommand replaces the live databases with the contents of a previous backup.

```bash
# Restore both DBs from the most recent backup in /data/backups/latest/
docker exec -it logboost-web /app/scripts/backup.sh restore --from /data/backups

# Restore from a specific dated file
docker exec -it logboost-web /app/scripts/backup.sh restore \
    --admin /data/backups/logboost_admin_20260502_131908.db \
    --threat /data/backups/threats_20260502_131908.db

# Skip the confirmation prompt (for cron / unattended use)
docker exec logboost-web /app/scripts/backup.sh restore --from /data/backups --yes
```

What it does, in order:

1. **Verifies** each backup file (existence, non-zero size, `PRAGMA integrity_check`, expected tables present)
2. **Prompts for confirmation** — type `RESTORE` to proceed, anything else aborts (skip with `--yes`)
3. **Snapshots the current live DBs** as `*.pre-restore.{timestamp}.db` next to the originals (skip with `--no-safety-copy`)
4. **Replaces the live DBs** using SQLite's `.restore` command — this is an atomic page-copy that respects open connections rather than ripping the file out from under the running app
5. Tells you to run `docker restart` so workers re-open clean connections

If something looks wrong after the restore, roll back by copying the `*.pre-restore.*.db` snapshot back to its original path. Once you've verified the restore looks correct, you can delete those snapshots.

### Manual restore (escape hatch)

If the script doesn't fit your situation, the underlying operation is just a SQLite file swap. Stop the container, copy your backup file into the volume at `/data/db/logboost_admin.db` and `/data/intel/threats.db`, restart. Make sure file ownership is `1000:1000` (the `logboost` user) before starting.

---

## Usage

### Ad-hoc IP Enrichment

1. Navigate to main page
2. Paste any text containing IP addresses (logs, firewall output, SIEM exports, etc.)
3. Select enrichment options:
   - DNS Lookups
   - WHOIS
   - Shodan InternetDB
   - Built-In OSINT Threat Intelligence Database
4. Click **Enrich IP Addresses**
5. View results, filter, and download CSV

### File Upload

1. Click the **File Upload** tab
2. Drag and drop or select a file
3. Configure processing options:
   - **Regex IP Detection** - Find IPs via regex in any format
   - **Full Parse** - Deep key detection for variable log formats
   - **Raw Text Fallback** - Process unknown formats as plain text
4. Click **Process and Enrich File**
5. View paginated results and download

### Sharing Results

1. After enrichment, click **Share Results**
2. Link is copied to clipboard
3. Links expire after a configurable period (default: 7 days)

---

## Threat Intelligence

### Built-in Feeds

The bundled `feed_config.json` includes common threat intel sources. View and manage feeds in **Admin Panel -> Threat Intel**.

### Adding Custom Feeds

1. Go to Admin Panel -> Threat Intel
2. Click "Add Feed"
3. Configure:
   - Feed URL (plain text, one indicator per line)
   - Feed name and category
   - Update schedule

### Updating Feeds

- **Manual:** Dashboard -> Update Threat Intel
- **Automatic:** Configure scheduled task interval in Admin Settings

---

## Health Check

```bash
curl http://localhost:5000/health
```

Returns JSON with status of:

- LogBoost binary availability
- MaxMind database availability
- Database connectivity
- Disk space

---

## Building from Source

If you prefer to build locally instead of using the pre-built image:

```bash
git clone https://github.com/joeavanzato/logboost-web.git
cd logboost-web
docker compose up --build
```

---

## Troubleshooting

### 1. Container Won't Start

**Symptoms:** Container exits immediately or shows errors in `docker compose logs logboost-web`

**Check logs first:**
```bash
docker compose logs logboost-web
```

**Common causes and solutions:**

| Error Message | Cause | Solution |
|--------------|-------|----------|
| `ERROR: /data is not writable` | Volume permissions | `docker volume rm logboost-db` and restart (data lost), or fix host permissions for bind mounts |
| `ERROR: Database directory ... not writable` | DB path permission | Check that `LOGBOOST_DB_PATH` directory exists and is writable by UID 1000 |
| `ERROR: SSL certificate and key do not match` | Custom cert mismatch | Verify cert/key pair with `openssl x509 -noout -modulus -in cert.pem` vs `openssl rsa -noout -modulus -in key.pem` |
| `SECRET_KEY is required` | Missing env var | Set `SECRET_KEY` in `.env` file or docker-compose.yml |

### 2. Port Already in Use

**Symptoms:** `Error starting userland proxy: listen tcp4 0.0.0.0:8443: bind: address already in use`

**Solution:** Change the host port mapping:
```yaml
ports:
  - "9443:8443"   # Use 9443 on host instead
```

Or stop the conflicting service:
```bash
sudo lsof -i :8443  # Find what's using the port
```

### 3. Browser Certificate Warnings

**Symptoms:** Browser shows "Your connection is not private" or "NET::ERR_CERT_AUTHORITY_INVALID"

**Cause:** The container uses a self-signed certificate by default.

**Solutions:**

1. **Development:** Click "Advanced" > "Proceed to localhost (unsafe)"
2. **Production:** Mount your own trusted certificate (see [SSL Configuration](#sslhttps-configuration))
3. **Set correct hostname:** If accessing via IP or custom hostname, set `SSL_COMMON_NAME` to match:
   ```yaml
   environment:
     SSL_COMMON_NAME: "logboost.example.com"
   ```
   Then recreate the certificate by removing the SSL volume: `docker volume rm logboost-ssl`

### 4. "Setup Required" Screen

**Symptoms:** Main page redirects to setup wizard asking for MaxMind databases

**Cause:** GeoLite2 MMDB files are missing from `/data/maxmind`

**Solutions:**

1. **Upload manually:** Use the setup page to upload all three files:
   - GeoLite2-ASN.mmdb
   - GeoLite2-Country.mmdb
   - GeoLite2-City.mmdb

2. **Use MaxMind API:** Log into Admin Panel, go to Settings, enter your MaxMind API key, then click "Update Geolocation" on the Dashboard

3. **Pre-populate volume:** Copy MMDB files to Docker volume:
   ```bash
   docker cp GeoLite2-City.mmdb logboost-web:/data/maxmind/
   docker cp GeoLite2-Country.mmdb logboost-web:/data/maxmind/
   docker cp GeoLite2-ASN.mmdb logboost-web:/data/maxmind/
   ```

### 5. Health Check Failing

**Symptoms:** Docker shows container as `unhealthy`, or `curl -k https://localhost:8443/health` returns 503

**Check health status:**
```bash
curl -sk https://localhost:8443/health | python -m json.tool
```

**Common health failures:**

| Field | Issue | Solution |
|-------|-------|----------|
| `db_accessible: false` | SQLite DB corrupted or locked | Check DB path permissions; restart container |
| `logboost_available: false` | Binary missing | This is a warning only, not a failure |
| `maxmind_available: false` | MMDB files missing | Upload databases (see #4 above) |

### 6. SSL Not Working

**Symptoms:** HTTPS connection refused, or HTTP works but HTTPS doesn't

**Verify SSL is listening:**
```bash
docker compose exec logboost-web ss -tlnp | grep 8443
```

**Check certificate exists:**
```bash
docker compose exec logboost-web ls -la /data/ssl/
```

**Common fixes:**

1. **Port not exposed:** Ensure docker-compose.yml has `- "8443:8443"` in ports
2. **Certificate generation failed:** Check container logs for SSL errors
3. **Wrong SSL_PORT:** If you changed `SSL_PORT`, ensure port mapping matches

### 7. Enrichment Features Missing

**Symptoms:** CIRCL, ViewDNS, Chaos, or HackerTarget options don't appear in enrichment panel

**Cause:** These features only display when the API key is configured.

**Solution:** Go to **Admin Panel -> Settings** and enter the relevant API key. The option will appear immediately after saving.

### 8. Database Errors After Update

**Symptoms:** `sqlite3.OperationalError: no such table` or `database is locked`

**Solutions:**

1. **Schema migration:** The app handles migrations automatically, but if errors persist:
   ```bash
   # Backup existing database
   docker compose exec logboost-web cp /data/db/logboost_admin.db /data/db/logboost_admin.db.backup
   # Remove and let container recreate
   docker compose exec logboost-web rm /data/db/logboost_admin.db
   docker compose restart logboost-web
   ```

2. **Database locked:** Restart the container. SQLite can lock if the container was killed mid-write.

### 9. Permission Errors on File Upload

**Symptoms:** File upload fails with "Permission denied" or similar error

**Cause:** The container runs as UID 1000 and needs write access to upload/output directories.

**Solutions:**

1. **Named volumes (recommended):** Docker manages permissions automatically
2. **Bind mounts:** Fix host permissions:
   ```bash
   sudo chown -R 1000:1000 /path/to/uploads /path/to/output
   ```

### 10. LogBoost Binary Update Fails

**Symptoms:** "Check for Updates" shows an error or doesn't complete

**Common causes:**

1. **Network connectivity:** Container needs outbound HTTPS access to GitHub
2. **Write permission:** `/data/bin` must be writable (auto-created on named volumes)
3. **Download timeout:** Large binary downloads may time out on slow connections

**Check current binary:**
```bash
docker compose exec logboost-web /app/logboost --version
```

---

## Security Considerations

- **Use a strong admin password** during first-time setup
- **Set a strong SECRET_KEY** in production (required - no default)
- **HTTPS enabled by default** on port 8443 with auto-generated certificate
- **Use trusted certificates** for production (see [SSL Configuration](#sslhttps-configuration))
- **Restrict network access** to the admin panel if possible
- API keys are stored encrypted in the database
- The container runs as a non-root user (UID 1000)
- Session cookies use HttpOnly and SameSite=Lax flags
- Path traversal protection on all file operations
- CSRF protection on all form submissions

---

## License

MIT License - See [LICENSE](LICENSE)

## Credits

- [LogBoost](https://github.com/joeavanzato/LogBoost) by Joe Avanzato
- [Flask](https://flask.palletsprojects.com/) web framework
- [HTMX](https://htmx.org/) for dynamic updates
- [Gunicorn](https://gunicorn.org/) WSGI server
