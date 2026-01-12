FROM node:18-slim

RUN apt-get update \
  && apt-get install -y chromium \
  && rm -rf /var/lib/apt/lists/*

ENV PUPPETEER_SKIP_DOWNLOAD=1
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
ENV FLAG="uoftctf{533M5_l1k3_17_W4snt_50_p3r50n41...}"

WORKDIR /app

COPY web/package.json web/package-lock.json* ./web/
RUN cd web && npm install --production

COPY bot/package.json bot/package-lock.json* ./bot/
RUN cd bot && npm install --production

COPY web ./web
COPY bot ./bot
COPY start.sh ./start.sh
RUN chmod +x ./start.sh

EXPOSE 3000

CMD ["./start.sh"]
