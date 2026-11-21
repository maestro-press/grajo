FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV DISPLAY=:99

# System deps: Xvfb, VNC, noVNC, browser libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    xvfb x11vnc novnc websockify \
    x11-utils xauth \
    curl ca-certificates \
    fonts-liberation fonts-noto-color-emoji \
    libnss3 libatk-bridge2.0-0 libdrm2 libxkbcommon0 \
    libgbm1 libpango-1.0-0 libcairo2 libasound2 \
    libxcomposite1 libxdamage1 libxrandr2 libatspi2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 24 LTS
RUN curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# The CDP relay starts itself as the gateway's uid through setpriv (util-linux, part of
# the base image — no package is added for this). It is what makes the relay's
# /proc/<pid>/fd, cwd and exe readable by the gateway: a process that calls setuid()
# itself turns non-dumpable, and the add-on wall then refuses the listener.
RUN test -x /usr/bin/setpriv

WORKDIR /app

# Install deps from the committed lockfile (a floating resolve pulls a newer Playwright)
COPY package.json package-lock.json ./
RUN npm ci

# Install Playwright Chromium
RUN npx playwright install chromium --with-deps

# Record the Chromium this image holds. The entrypoint compares it with the version that
# last wrote the persistent profile and refuses to start on a downgrade: Chromium cannot
# open a profile written by a newer major, and would crash-loop. The build fails rather
# than ship an image whose Chromium version cannot be read.
RUN node -e 'const browsers = require("./node_modules/playwright-core/browsers.json").browsers; const chromium = browsers.find((b) => b.name === "chromium"); if (!chromium || !chromium.browserVersion) { console.error("playwright-core/browsers.json has no chromium browserVersion"); process.exit(1); } require("fs").writeFileSync("/opt/crow-chromium-version", chromium.browserVersion + "\n");'

COPY entrypoint.sh ./
COPY cdp-relay.mjs ./
RUN chmod +x entrypoint.sh

# 6080 is noVNC; 9222 is the CDP relay (Chromium itself listens on no port — it
# runs on --remote-debugging-pipe and only the relay answers, with a bearer token).
EXPOSE 6080 9222

ENTRYPOINT ["/app/entrypoint.sh"]
