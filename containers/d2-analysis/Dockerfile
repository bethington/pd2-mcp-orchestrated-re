# containers/d2-analysis/Dockerfile
FROM ubuntu:22.04

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install Wine, VNC, and debugging tools
RUN dpkg --add-architecture i386 && \
    apt-get update && apt-get install -y \
    wine32 \
    winetricks \
    x11vnc \
    xvfb \
    x11-utils \
    xdotool \
    fluxbox \
    wget \
    curl \
    unzip \
    gdb \
    strace \
    ltrace \
    psmisc \
    net-tools \
    lsof \
    python3 \
    python3-pip \
    nano \
    vim \
    mousepad \
    supervisor \
    procps \
    imagemagick \
    scrot \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies for memory scanning and MCP server
COPY containers/d2-analysis/requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

# Set up Wine environment
ENV WINEPREFIX=/root/.wine
ENV WINEARCH=win32
ENV WINEDEBUG=-all
ENV DISPLAY=:1

# Initialize Wine
RUN wine wineboot --init

# Create directories
RUN mkdir -p /game /screenshots /memory_dumps /sessions /home/wine /var/log/supervisor /var/run

# Copy scripts and configuration
COPY containers/d2-analysis/scripts/setup_wine.sh /usr/local/bin/
COPY containers/d2-analysis/scripts/start_d2.sh /usr/local/bin/
COPY containers/d2-analysis/scripts/capture_screenshot_hotkey.sh /usr/local/bin/
COPY containers/d2-analysis/src/game_state_api_fixed.py /app/
COPY containers/d2-analysis/src/diablo2_mcp_server.py /app/
COPY containers/d2-analysis/src/diablo2_monitor.py /usr/local/bin/
COPY containers/d2-analysis/src/simple_mcp_server.py /usr/local/bin/
COPY containers/d2-analysis/config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY containers/d2-analysis/config/fluxbox_keys /root/.fluxbox/keys
RUN chmod +x /usr/local/bin/setup_wine.sh /usr/local/bin/start_d2.sh /usr/local/bin/capture_screenshot_hotkey.sh && \
    mkdir -p /root/.fluxbox

# Copy shared platform modules and source code
COPY shared/ /app/shared/
COPY src/ /app/src/

# Set Python path
ENV PYTHONPATH=/app/shared:/app/src:/app:/usr/local/bin

# Copy Project Diablo 2 game files (you need to provide these)
COPY data/pd2 /game/pd2/

# Expose ports:
# 5900 - VNC server for remote desktop access
# 3000 - HTTP health check endpoint
# 3001 - Game State API
# 8765 - MCP server (HTTP/SSE transport for Claude Desktop)
EXPOSE 5900 3000 3001 8765

WORKDIR /game

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
