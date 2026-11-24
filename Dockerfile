# ── Stage 1: Builder ───────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app
COPY HoneyGuard/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Runtime ───────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY HoneyGuard/ .

# Create persistent directories
RUN mkdir -p reports canary_files

# Default environment (overridden on Render/Railway via env vars)
ENV PORT=5000 \
    DASHBOARD_USERNAME=admin \
    DASHBOARD_PASSWORD=honeyguard_admin \
    DRY_RUN=True \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE $PORT

# Gunicorn with eventlet for SocketIO support.
# 1 worker + eventlet async is the recommended setup for Flask-SocketIO.
CMD gunicorn \
        --worker-class eventlet \
        --workers 1 \
        --bind 0.0.0.0:$PORT \
        --timeout 120 \
        --log-level info \
        "dashboard:app"
