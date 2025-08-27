# containers/novnc-proxy/Dockerfile
FROM alpine:3.18

# Install Python and git for noVNC and websockify
RUN apk add --no-cache \
    python3 \
    py3-pip \
    git \
    && rm -rf /var/cache/apk/*

# Install websockify
RUN pip3 install websockify

# Clone noVNC
RUN cd /opt && \
    git clone https://github.com/novnc/noVNC.git && \
    cd noVNC && \
    ln -s vnc.html index.html

# Expose port for web interface
EXPOSE 5901

# Set working directory
WORKDIR /opt/noVNC

# Command to start noVNC web proxy
CMD ["python3", "-m", "websockify", "--web", "/opt/noVNC", "5901", "d2-analysis:5900"]
