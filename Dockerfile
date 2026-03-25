# ============================================================
# TelSec Dockerfile
# Base: Kali Linux Rolling
# Exposes: 8501 (Streamlit UI)
# ============================================================

FROM kalilinux/kali-rolling:latest

LABEL maintainer="TelSec Security Team"
LABEL description="Telecom Security Penetration Testing Framework"
LABEL version="1.0.0"

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Core tools
    python3 python3-pip python3-venv \
    git curl wget \
    # Network tools
    nmap wireshark-common tshark \
    net-tools iputils-ping \
    # Telecom tools (best-effort)
    gr-gsm \
    osmocom-nitb \
    # Runtime dependencies
    libssl-dev libffi-dev \
    build-essential \
    erlang \
    default-jdk \
    # Metasploit (optional — large package)
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /teleaudit

# Install Python dependencies first (layer cache optimization)
COPY requirements.txt .
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create reports directory
RUN mkdir -p reports/ deps/ logs/

# Clone dependencies (non-fatal)
RUN git clone --depth=1 https://github.com/SigPloiter/SigPloit deps/sigploit 2>/dev/null || true && \
    git clone --depth=1 https://github.com/ernw/ss7MAPer deps/ss7maper 2>/dev/null || true && \
    git clone --depth=1 https://github.com/open5gs/open5gs deps/open5gs 2>/dev/null || true

# tshark non-root capture (lab environments)
RUN setcap cap_net_raw,cap_net_admin+eip $(which tshark) 2>/dev/null || true

# Non-root user for security
RUN useradd -m -u 1000 teleaudit && chown -R teleaudit:teleaudit /teleaudit
USER teleaudit

# Expose Streamlit port
EXPOSE 8501

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Default command
CMD ["streamlit", "run", "app.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true", \
     "--browser.gatherUsageStats=false"]
