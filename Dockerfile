FROM python:3.10-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

WORKDIR /app

# Install system utilities needed for digital forensics triage
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    curl \
    lsof \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Run pre-initialization of hashes and evidence
RUN python -c "from forensic_toolkit.hashing import hash_menu; from forensic_toolkit.super_timeline import build_super_timeline; build_super_timeline()" 2>/dev/null || true

EXPOSE 8000

CMD ["sh", "-c", "uvicorn gui_app:app --host 0.0.0.0 --port ${PORT:-8000}"]
