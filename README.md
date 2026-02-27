# LogBoost Web

A web-based interface for [LogBoost](https://github.com/joeavanzato/LogBoost) - IP enrichment and log parsing at scale.

![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)
![Python](https://img.shields.io/badge/Python-3.12-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## Features

### Core Enrichment
- **Ad-hoc IP Enrichment** - Paste any text, automatically extract and enrich all IP addresses
- **File Upload Processing** - Upload logs (CSV, JSON, TXT, LOG, GZ, CEF, Syslog) for batch processing
- **Geolocation & ASN** - MaxMind GeoLite2 integration for IP geolocation
- **Threat Intelligence** - Match IPs against configurable threat feeds

### Optional API Integrations
- **DNS Reverse Lookups** - Resolve IP addresses to hostnames
- **WHOIS Lookups** - Domain and IP registration data
- **Shodan InternetDB** - Open ports, services, vulnerabilities
- **CIRCL Passive DNS** - Passive-DNS Domain/IP Associations
- **Chaos Project DB** - Bug bounty program data

### Admin Dashboard
- **Scheduled Tasks** - Auto-update GeoIP databases and threat intel feeds
- **User Management** - Multi-user support with audit logging
- **API Key Management** - Configure MaxMind, Shodan, and other API keys
- **Task Logs** - Full execution history with error tracking

### User Experience
- **Drag & Drop Upload** - Easy file upload interface
- **Paginated Results** - Handle large datasets in-browser
- **CSV Export** - Download enriched results
- **Shareable Links** - Share results with expiring links
- **Dark Theme** - Security-focused aesthetic

---

## Quick Start

### Prerequisites
- Docker and Docker Compose
- MaxMind GeoLite2 databases OR MaxMind API key

### 1. Create docker-compose.yml

```yaml
services:
  logboost-web:
    image: ghcr.io/joeavanzato/logboost-web:latest
    ports:
      - "5000:5000"
    environment:
      SECRET_KEY: "generate-a-secure-key-here"
      FLASK_ENV: production
    volumes:
      - logboost-db:/data/db
      - logboost-maxmind:/data/maxmind
      - logboost-intel:/data/intel
      - logboost-config:/data/config
    restart: unless-stopped

volumes:
  logboost-db:
  logboost-maxmind:
  logboost-intel:
  logboost-config:
```

### 2. Start the Container

```bash
docker compose up -d
```

### 3. Access the Application

- **Main UI:** http://localhost:5000
- **Admin Panel:** http://localhost:5000/admin

### 4. Initial Setup

On first launch, you'll see a setup screen prompting you to configure MaxMind databases:

**Option A: Upload MMDB Files**
- Upload your existing GeoLite2-ASN.mmdb, GeoLite2-Country.mmdb, and GeoLite2-City.mmdb files

**Option B: Configure API Key**
1. Log into Admin Panel (default: `admin` / `changeme`)
2. Go to Settings → Enter MaxMind API Key
3. Dashboard → Click "Update Geolocation"

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `dev-placeholder...` | Flask session signing key (**change in production**) |
| `FLASK_ENV` | `production` | `production` or `development` |
| `LOGBOOST_PATH` | `/app/logboost` | Path to LogBoost binary |
| `MAXMIND_DIR` | `/data/maxmind` | Directory for .mmdb files |
| `THREAT_DB_DIR` | `/data/intel` | Directory for threats.db |
| `LOGBOOST_DB_PATH` | `/data/db/logboost_admin.db` | Admin database path |

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
| `/data/config` | Feed configuration |

---

## Optional API Keys

Configure these in **Admin Panel → Settings** for enhanced enrichment:

| Service | Purpose | Get Key |
|---------|---------|---------|
| **MaxMind** | Auto-download GeoLite2 updates | [maxmind.com](https://www.maxmind.com/en/geolite2/signup) (free) |
| **Shodan** | Shodan Pivots/Queries | [shodan.io](https://www.shodan.io/) |
| **CIRCL** | Passive DNS | [circl.lu](https://www.circl.lu/) |
| **ViewDNS** | DNS/WHOIS lookups | [viewdns.info](https://viewdns.info/api/) |
| **HackerTarget** | DNS/IP tools | [hackertarget.com](https://hackertarget.com/ip-tools/) |

> **Note:** The app works without any API keys if you manually upload MMDB files. API keys enable automatic updates and additional enrichment sources.

---

## Admin Panel

### Default Credentials
- **Username:** `admin`
- **Password:** `changeme`

**Change the default password immediately after first login.**

### Quick Actions
- **Update Geolocation** - Download latest MaxMind databases (requires API key)
- **Update Threat Intel** - Refresh threat indicator feeds
- **Upload MMDB Files** - Manually upload database files

### Scheduled Tasks
Configure automatic updates:
- Set update intervals (hours)
- Enable/disable individual tasks
- View execution history and logs

### User Management
- Create additional admin accounts
- Change passwords
- View audit logs

---

## Usage

### Ad-hoc IP Enrichment

1. Navigate to main page
2. Paste any text containing IP addresses (logs, firewall output, etc.)
3. Select enrichment options:
   - DNS Lookups
   - WHOIS
   - Shodan InternetDB
   - Built-In OSINT Threat Intelligence Database
4. Click **Enrich IP Addresses**
5. View results, filter, and download CSV

### File Upload

1. Click **File Upload** tab
2. Drag & drop or select a file
3. Configure processing options:
   - **Regex IP Detection** - Find IPs via regex
   - **Full Parse** - Deep key detection for variable formats
   - **Raw Text Fallback** - Process unknown formats as text
4. Click **Process & Enrich File**
5. View paginated results and download

### Sharing Results

1. After enrichment, click **Share Results**
2. Link is copied to clipboard
3. Links expire after configurable period (default: 7 days)

---

## Threat Intelligence

### Built-in Feeds
The bundled `feed_config.json` includes common threat intel sources. View and manage feeds in **Admin Panel → Threat Intel**.

### Adding Custom Feeds

1. Go to Admin Panel → Threat Intel
2. Click "Add Feed"
3. Configure:
   - Feed URL (plain text, one indicator per line)
   - Feed name and category
   - Update schedule

### Updating Feeds

- **Manual:** Dashboard → Update Threat Intel
- **Automatic:** Configure scheduled task interval

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

---

## Security Considerations

- **Change default admin password** immediately
- **Set a strong SECRET_KEY** in production
- **Use HTTPS** in production (reverse proxy recommended)
- **Restrict network access** to admin panel if possible
- API keys are stored encrypted in the database

---

## License

MIT License - See [LICENSE](LICENSE)

## Credits

- [LogBoost](https://github.com/joeavanzato/LogBoost) by Joe Avanzato
- [Flask](https://flask.palletsprojects.com/) web framework
- [HTMX](https://htmx.org/) for dynamic updates
- [Gunicorn](https://gunicorn.org/) WSGI server
