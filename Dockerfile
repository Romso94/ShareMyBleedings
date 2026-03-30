# ShareMyBleedings — SMB audit tool with optional content scanning
# Build:  docker build -t sharemybleedings .
# Run:    docker run --rm --network host -v "$PWD/out:/out" sharemybleedings scan --ranges 192.168.1.0/24 --output /out/report.html --no-open-browser

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LANG=C.UTF-8

# System dependencies:
#   nmap            -> discovery agent (python-nmap fallback)
#   libmagic1       -> file type detection for content scanner
#   antiword        -> .doc text extraction (manspider)
#   poppler-utils   -> .pdf text extraction (manspider)
#   unrtf           -> .rtf text extraction
#   tesseract-ocr   -> OCR for scanned PDFs (manspider) — ~30 MB
#   libreoffice-core -> .docx/.xlsx/.pptx text extraction (manspider) — ~200 MB
#   tini            -> proper PID 1 / signal handling
# Note: tesseract-ocr + libreoffice-core add ~230 MB to the image.
# They are required for manspider's full document extraction (--scan-content).
# If you don't use content scanning, you can remove them to shrink the image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        libmagic1 \
        antiword \
        poppler-utils \
        unrtf \
        tesseract-ocr \
        libreoffice-core \
        pipx \
        git \
        tini \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install manspider (BlackLanternSecurity) — content scanner.
# CLI-only tool, used as subprocess by smb_bleedings/agents/content_scanner.py.
ENV PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin
RUN pipx install git+https://github.com/blacklanternsecurity/MANSPIDER@070a81e9

WORKDIR /app

# Install Python deps first for better layer caching
COPY pyproject.toml ./
COPY smb_bleedings ./smb_bleedings

RUN pip install --upgrade pip setuptools wheel \
    && pip install ".[nmap]"

# Default loot/output directories (mount these as volumes)
RUN mkdir -p /out /loot
VOLUME ["/out", "/loot"]

# Non-root user for safety (network scans still work; raw sockets not needed)
RUN useradd --create-home --shell /bin/bash bleedings \
    && chown -R bleedings:bleedings /app /out /loot
USER bleedings

ENTRYPOINT ["/usr/bin/tini", "--", "bleedings"]
CMD ["--help"]
