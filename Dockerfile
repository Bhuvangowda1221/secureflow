# ─── Stage 1: Build stage ─────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─── Stage 2: Production image ────────────────────────────────────────────────
FROM python:3.11-slim AS production

# Security: create non-root user
RUN groupadd -r secureflow && useradd -r -g secureflow -m -d /home/secureflow secureflow

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source code
COPY --chown=secureflow:secureflow . .

# Create required directories with correct ownership
RUN mkdir -p /app/instance /app/scan_workspace /app/reports \
    && chown -R secureflow:secureflow /app

# Switch to non-root user
USER secureflow

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

# Environment defaults (override at runtime)
ENV FLASK_ENV=production \
    FLASK_PORT=5000 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Start application
CMD ["python", "run.py"]
