# Get HAProxy from official image
FROM haproxy:2.3 AS haproxy

# Main application image
FROM python:3.11-bullseye

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    gnupg \
    ca-certificates \
    supervisor \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libasound2 \
    libgtk-3-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy HAProxy binary to both locations for compatibility
RUN mkdir -p /usr/local/sbin
COPY --from=haproxy /usr/local/sbin/haproxy /usr/local/sbin/haproxy
COPY --from=haproxy /usr/local/etc/haproxy /usr/local/etc/haproxy

COPY --from=haproxy /usr/lib/x86_64-linux-gnu/liblua5.3.so.0* /usr/lib/x86_64-linux-gnu/
COPY --from=haproxy /usr/lib/x86_64-linux-gnu/libpcre2-8.so.*   /usr/lib/x86_64-linux-gnu/
COPY --from=haproxy /usr/lib/x86_64-linux-gnu/libssl.so.*       /usr/lib/x86_64-linux-gnu/
COPY --from=haproxy /usr/lib/x86_64-linux-gnu/libcrypto.so.*    /usr/lib/x86_64-linux-gnu/
COPY --from=haproxy /lib/x86_64-linux-gnu/libz.so.*             /lib/x86_64-linux-gnu/

# ARM version (for M4)
# COPY --from=haproxy /usr/lib/aarch64-linux-gnu/liblua5.3.so.0* /usr/lib/aarch64-linux-gnu/
# COPY --from=haproxy /usr/lib/aarch64-linux-gnu/libpcre2-8.so.*   /usr/lib/aarch64-linux-gnu/
# COPY --from=haproxy /usr/lib/aarch64-linux-gnu/libssl.so.*       /usr/lib/aarch64-linux-gnu/
# COPY --from=haproxy /usr/lib/aarch64-linux-gnu/libcrypto.so.*    /usr/lib/aarch64-linux-gnu/
# COPY --from=haproxy /lib/aarch64-linux-gnu/libz.so.*             /lib/aarch64-linux-gnu/

# Create necessary directories and symlinks
RUN mkdir -p /etc/haproxy \
    && ln -s /usr/local/etc/haproxy /etc/haproxy \
    && groupadd --system haproxy \
    && useradd --system --gid haproxy haproxy \
    && mkdir -p /run/haproxy \
    && chown haproxy:haproxy /run/haproxy

# Set Python3.9 as default
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 1

WORKDIR /app

# Copy and install Python dependencies
COPY ./app/requirements.txt ./
RUN pip3 install --upgrade pip && pip3 install --no-cache-dir -r requirements.txt

# Set environment variable for Playwright
ENV PLAYWRIGHT_BROWSERS_PATH=/app/.cache/ms-playwright

# Install Playwright and its dependencies
RUN pip3 install playwright
RUN playwright install-deps
RUN playwright install firefox

# Copy application and flag
COPY ./app ./
COPY ./flag.txt /flag.txt

# Expose the application port
EXPOSE 1337

# HAProxy config (overrides the default)
COPY config/haproxy.cfg /usr/local/etc/haproxy/

# Copy supervisor config
COPY config/supervisord.conf /etc/supervisord.conf

# Disable pycache
ENV PYTHONDONTWRITEBYTECODE=1

# Start supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
