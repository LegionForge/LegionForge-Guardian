# packages/guardian/Dockerfile
# Standalone Guardian sidecar — no LegionForge source required.
# Phase G3: this Dockerfile replaces guardian/Dockerfile in the root.
#
# Build:  docker build -f packages/guardian/Dockerfile -t legionforge-guardian:standalone .
# Run:    docker-compose -f packages/guardian/docker-compose.yml up

FROM python:3.11-slim

# Security: non-root user
RUN addgroup --system guardian && adduser --system --ingroup guardian guardian

WORKDIR /app

# Install the package and its dependencies
COPY packages/guardian/ /app/packages/guardian/
RUN pip install --no-cache-dir /app/packages/guardian/

# Runtime directories
RUN mkdir -p /app/logs && chown -R guardian:guardian /app

USER guardian

EXPOSE 9766

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9766/health')"

CMD ["python", "-m", "legionforge_guardian"]
