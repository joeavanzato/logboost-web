# LogBoost Web UI

A web-based interface for [LogBoost](https://github.com/joeavanzato/LogBoost) - the log enrichment and parsing tool.

![LogBoost Web UI](https://img.shields.io/badge/Python-3.10+-green.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## Features

- **Ad-hoc IP Enrichment**: Paste any text and automatically extract and enrich all IP addresses
- **File Upload Processing**: Upload log files (CSV, LOG, TXT, JSON, GZ, CEF) for full LogBoost processing
- **All Enrichment Options**: 
  - Geolocation & ASN (MaxMind)
  - DNS Reverse Lookups
  - WhoIs Information
  - Shodan InternetDB
  - Threat Intelligence Matching
- **Full CLI Options Exposed**: All LogBoost command-line options available through the UI
- **Paginated Results**: View results in-browser with configurable page sizes
- **CSV Download**: Download enriched results as CSV files
- **Dark Theme**: Cyber security aesthetic

## Prerequisites

1. **LogBoost Binary**: Download from [LogBoost Releases](https://github.com/joeavanzato/LogBoost/releases)
2. **MaxMind Databases**: Free GeoLite2 databases from [MaxMind](https://www.maxmind.com/en/geolite2/signup)
3. **Python 3.10+**

## Installation

### 1. Clone or Copy Files

```bash
# Create directory
mkdir logboost-web
cd logboost-web

# Copy all files from this package
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure LogBoost Path

Set environment variables or use defaults:

```bash
# LogBoost binary location (default: 'LogBoost' in PATH)
export LOGBOOST_PATH=/path/to/LogBoost

# MaxMind database directory (default: current directory)
export MAXMIND_DIR=/path/to/maxmind/dbs

# Threat Intelligence DB directory (default: current directory)
export THREAT_DB_DIR=/path/to/threat/db
```

### 4. Prepare MaxMind Databases

Ensure these files are in your `MAXMIND_DIR`:
- `GeoLite2-ASN.mmdb`
- `GeoLite2-City.mmdb`
- `GeoLite2-Country.mmdb`
- `GeoLite2-Domain.mmdb` (optional, for TLD lookups)

### 5. (Optional) Build Threat Intelligence Database

```bash
./LogBoost -buildti
```

## Running the Application

### Development Mode

```bash
python app.py
```

Access at: `http://localhost:5000`

### Production Mode (Gunicorn)

```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install LogBoost
COPY LogBoost /usr/local/bin/
RUN chmod +x /usr/local/bin/LogBoost

# Copy MaxMind DBs
COPY *.mmdb /app/

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Set environment
ENV LOGBOOST_PATH=/usr/local/bin/LogBoost
ENV MAXMIND_DIR=/app
ENV THREAT_DB_DIR=/app

EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

## Usage

### Ad-hoc IP Enrichment

1. Select the **Ad-hoc IP Enrichment** tab
2. Paste any text containing IP addresses (logs, firewall output, etc.)
3. Select enrichment options (DNS, WhoIs, Shodan, Threat Intel)
4. Click **Enrich IP Addresses**
5. View paginated results and download CSV

### File Upload

1. Select the **File Upload** tab
2. Drag & drop or click to upload a log file
3. Configure enrichment and processing options:
   - **Regex IP Detection**: Find IPs via regex instead of column name
   - **Full Parse**: Deep key detection for variable-column formats
   - **Raw Text Fallback**: Process unknown formats as raw text
4. Optionally configure:
   - Column names (IP column, JSON column)
   - KV parsing separators
   - Date filtering
   - Performance tuning
5. Click **Process & Enrich File**
6. View results and download

## Configuration Options

### Enrichment Options

| Option | Description |
|--------|-------------|
| Geolocation/ASN | Always enabled - MaxMind geo data |
| DNS Lookups | Reverse DNS for IP addresses |
| WhoIs | WhoIs information for IPs/domains |
| Shodan InternetDB | Shodan data (ports, vulns, etc.) |
| Threat Intelligence | Match against threat feeds |

### Processing Options

| Option | Description |
|--------|-------------|
| Regex IP Detection | Use regex to find IPs |
| Full Parse (Deep Keys) | Scan entire file for all possible columns |
| Raw Text Fallback | Process unknown formats as raw text |
| Passthrough | Skip enrichment, only convert format |
| Combine Outputs | Merge multiple output files |

### Advanced Configuration

| Option | Description |
|--------|-------------|
| IP Column | Specify column name containing IPs |
| JSON Column | Column with embedded JSON blobs |
| KV Separator | Key-value separator (default: =) |
| KV Delimiter | KV pair delimiter (default: ,) |
| Date Filtering | Filter by date range |
| Performance | Goroutines, batch size tuning |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main UI |
| `/enrich/text` | POST | Ad-hoc text enrichment |
| `/enrich/file` | POST | File upload enrichment |
| `/results/page` | GET | Paginated results |
| `/download` | GET | Download current CSV |
| `/health` | GET | Health check |
| `/admin/` | GET | Admin dashboard |
| `/admin/login` | GET/POST | Admin login |
| `/admin/tasks` | GET | Scheduled tasks management |
| `/admin/logs` | GET | Task execution logs |
| `/admin/settings` | GET/POST | MaxMind API key settings |
| `/admin/accounts` | GET | Admin account management |

## Admin Panel

LogBoost Web UI includes an admin panel for managing scheduled updates and settings.

### Default Credentials
- **Username:** `admin`
- **Password:** `changeme`

⚠️ **Important:** Change the default password immediately after first login!

### Features

#### Scheduled Tasks
- **Update Geolocation**: Automatically download latest MaxMind GeoLite2 databases
- **Update Threat Intelligence**: Refresh threat indicator feeds
- Configure interval (every X hours)
- Enable/disable individual tasks
- Run tasks immediately on-demand
- View task execution history and logs

#### Settings
- Configure MaxMind API key
- Test API key validity before saving

#### Account Management
- Create additional admin accounts
- Change passwords
- Delete accounts (cannot delete your own or the last account)

### Task Scheduler
The scheduler runs as a background thread and checks for due tasks every minute. When a task is enabled:
1. The next run time is calculated based on the interval
2. When the scheduled time arrives, the task executes automatically
3. Logs are recorded for each execution
4. The next run time is recalculated after completion

## Directory Structure

```
logboost-web/
├── app.py                 # Flask application
├── admin.py               # Admin module (auth, scheduler, settings)
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── logboost_admin.db     # SQLite database (created on first run)
├── templates/
│   ├── index.html        # Main page template
│   ├── admin/            # Admin templates
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── dashboard.html
│   │   ├── tasks.html
│   │   ├── logs.html
│   │   ├── log_detail.html
│   │   ├── settings.html
│   │   ├── accounts.html
│   │   ├── create_account.html
│   │   └── change_password.html
│   └── partials/
│       ├── results.html       # Results container
│       ├── results_table.html # Paginated table
│       ├── stats.html         # Statistics panel
│       └── error.html         # Error display
├── static/
│   ├── style.css         # Main styles
│   └── admin.css         # Admin panel styles
├── uploads/              # Temporary upload storage
└── output/               # Processed results
```

## Troubleshooting

### LogBoost Binary Not Found

```
Error: LogBoost binary not found at: LogBoost
```

Solution: Set `LOGBOOST_PATH` environment variable to the full path of your LogBoost binary.

### MaxMind Databases Not Found

Ensure MaxMind `.mmdb` files are in `MAXMIND_DIR` or the current working directory.

### No Output Generated

1. Check that the input file format is supported
2. Enable `-rawtxt` option for unknown formats
3. Check LogBoost console output for errors

### Permission Errors

Ensure the `uploads/` and `output/` directories are writable by the web application user.

## License

MIT License - Same as LogBoost

## Credits

- [LogBoost](https://github.com/joeavanzato/LogBoost) by Joe Avanzato
- [HTMX](https://htmx.org/) for dynamic updates
- [Flask](https://flask.palletsprojects.com/) web framework
