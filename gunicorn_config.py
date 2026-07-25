import multiprocessing
import os

# Bind
bind = "0.0.0.0:5000"

# Workers — override with GUNICORN_WORKERS if you need to tune for your
# host's CPU/RAM; defaults to a sane (2 * CPU) + 1 formula.
workers = int(os.environ.get("GUNICORN_WORKERS", multiprocessing.cpu_count() * 2 + 1))
worker_class = "sync"
threads = int(os.environ.get("GUNICORN_THREADS", 2))

# Timeouts
timeout = int(os.environ.get("GUNICORN_TIMEOUT", 60))
graceful_timeout = 30
keepalive = 5

# Logging — stdout/stderr so `docker compose logs` captures everything
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "info")
access_log_format = '%(h)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)sus'

# Restart workers periodically to shed any slow memory growth
max_requests = 1000
max_requests_jitter = 100

# Don't preload — db.create_all() runs at import time and each worker
# should complete its own DB connection setup rather than sharing state
# from a single preloaded parent process.
preload_app = False
