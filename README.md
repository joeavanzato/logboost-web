# LogBoost Web

A web-based interface for [LogBoost](https://github.com/joeavanzato/LogBoost) - IP enrichment and log parsing at scale.

![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)
![Python](https://img.shields.io/badge/Python-3.12-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

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

## Quick Start

### Prerequisites

- Docker and Docker Compose
- MaxMind GeoLite2 databases OR a MaxMind account (free)

### 1. Create docker-compose.yml

```yaml
services:
  logboost-web:
    image: ghcr.io/joeavanzato/logboost-web:latest
    ports:
      - "8443:8443"   # HTTPS (primary access)
      - "5000:5000"   # HTTP (health checks)
    environment:
      SECRET_KEY: "generate-a-secure-key-here"
      FLASK_ENV: production
      SSL_COMMON_NAME: "localhost"  # Set to your hostname for valid cert
    volumes:
      - logboost-db:/data/db
      - logboost-maxmind:/data/maxmind
      - logboost-intel:/data/intel
      - logboost-config:/data/config
      - logboost-ssl:/data/ssl      # SSL certificates
    restart: unless-stopped

volumes:
  logboost-db:
  logboost-maxmind:
  logboost-intel:
  logboost-config:
  logboost-ssl:
```

### 2. Start the Container

```bash
docker compose up -d
```

### 3. Access the Application

- **Main UI:** https://localhost:8443
- **Admin Panel:** https://localhost:8443/admin
- **Health Check:** http://localhost:5000/health

> **Note:** On first run, the container generates a self-signed SSL certificate. Your browser will show a certificate warning - this is expected for self-signed certs. Click "Advanced" and proceed to the site. For production deployments, see the [SSL Configuration](#sslhttps-configuration) section for using custom certificates.

### 4. Initial Setup

On first launch you will see a setup screen prompting you to configure MaxMind databases:

**Option A: Upload MMDB Files**

Upload your existing GeoLite2-ASN.mmdb, GeoLite2-Country.mmdb, and GeoLite2-City.mmdb files directly from the setup page.

**Option B: Configure API Key**

1. Log into Admin Panel (create admin account on first visit)
2. Go to Settings, enter your MaxMind API Key
3. Return to Dashboard, click "Update Geolocation"

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

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `dev-placeholder...` | Flask session signing key (**change in production**) |
| `FLASK_ENV` | `production` | `production` or `development` |
| `LOGBOOST_PATH` | `/usr/local/bin/logboost` | Path to LogBoost binary |
| `MAXMIND_DIR` | `/data/maxmind` | Directory for .mmdb files |
| `THREAT_DB_DIR` | `/data/intel` | Directory for threats.db |
| `LOGBOOST_DB_PATH` | `/data/db/logboost_admin.db` | Admin database path |
| `LOGBOOST_LOG_LEVEL` | `WARNING` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

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
| `/data/uploads` | Temporary file upload storage |
| `/data/output` | Processed output files |

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

On first launch, you'll be prompted to create an admin account. There are no default credentials - you choose your own username and password during setup.

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

### "Setup Required" Screen

MaxMind databases are missing. Either:

- Upload .mmdb files via the setup page
- Configure MaxMind API key in Admin Settings and run "Update Geolocation"

### "MaxMind API Key Required" Error

You clicked "Update Geolocation" but no API key is configured. Go to Admin Settings first.

### Permission Errors

The container runs as UID 1000. If using bind mounts instead of named volumes:

```bash
sudo chown -R 1000:1000 /path/to/your/data
```

### Container Won't Start

Check logs:

```bash
docker compose logs logboost-web
```

Common issues:

- Port 5000 already in use
- Volume mount permissions

### Enrichment Feature Not Appearing

Some features only display in the UI when the corresponding API key is configured. If Chaos, ViewDNS, HackerTarget, or CIRCL options are missing from the enrichment panel, check **Admin Panel -> Settings** and confirm the relevant API key is saved.

---

## Security Considerations

- **Use a strong admin password** during first-time setup
- **Set a strong SECRET_KEY** in production
- **Use HTTPS** in production (reverse proxy recommended)
- **Restrict network access** to the admin panel if possible
- API keys are stored encrypted in the database
- The container runs as a non-root user (UID 1000)
- Session cookies use HttpOnly and SameSite=Lax flags

---

## License

MIT License - See [LICENSE](LICENSE)

## Credits

- [LogBoost](https://github.com/joeavanzato/LogBoost) by Joe Avanzato
- [Flask](https://flask.palletsprojects.com/) web framework
- [HTMX](https://htmx.org/) for dynamic updates
- [Gunicorn](https://gunicorn.org/) WSGI server
