# ── Stage 1: build the React UI ───────────────────────────────────────────────
FROM node:20-slim AS ui-builder

WORKDIR /app/ui
COPY ui/package*.json ./
RUN npm ci --prefer-offline
COPY ui/ ./
RUN npm run build


# ── Stage 2: Python backend + pre-built UI ────────────────────────────────────
FROM python:3.12-slim AS runtime

# System deps (tree-sitter needs a C compiler at install time)
RUN apt-get update && apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python package
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install --no-cache-dir -e ".[dev]"

# Copy built UI into a location the API can serve as static files
COPY --from=ui-builder /app/ui/dist ./ui/dist

# Runtime config
ENV VULNSCAN_DATA_DIR=/data
ENV VULNSCAN_UI_DIR=/app/ui/dist
EXPOSE 8765

# Persistent data directory (mount a volume here on Render/Fly)
RUN mkdir -p /data

CMD ["sh", "-c", "uvicorn vulnscan.api:app --host 0.0.0.0 --port ${PORT:-8765}"]
