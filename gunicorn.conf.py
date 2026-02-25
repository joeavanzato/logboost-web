# gunicorn.conf.py — All Gunicorn settings for LogBoost Web
# Loaded via: gunicorn --config gunicorn.conf.py app:app

import os

# Worker configuration
# workers=1 is MANDATORY — SQLite cannot handle concurrent write locks from multiple processes
# threads=4 provides concurrency within the single process via gthread worker class
workers = 1
threads = 4
worker_class = "gthread"

# Timeout configuration
# MUST exceed the LogBoost subprocess timeout (300s in app.py run_logboost())
# If gunicorn timeout < subprocess timeout, gunicorn kills the worker mid-enrichment
timeout = 310
graceful_timeout = 30

# Network binding — 0.0.0.0 required for Docker port mapping
bind = "0.0.0.0:5000"

# Logging — stdout/stderr for Docker log collection (per user's locked decision)
# "-" directs output to stdout (access) and stderr (error)
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("LOGBOOST_LOG_LEVEL", "info").lower()

# Process naming (visible in docker exec ps output)
proc_name = "logboost-web"
