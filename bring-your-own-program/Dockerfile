FROM node:20-bullseye-slim AS app

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /data/public
COPY ./src/data/* /data/public/
RUN mkdir -p /challenge
WORKDIR /challenge
COPY ./src/chal.js .
COPY ./src/flag.txt /flag.txt

FROM pwn.red/jail

COPY --from=app / /srv
RUN mkdir -p /srv/app
COPY --chmod=555 ./src/run /srv/app/run

ENV JAIL_PIDS=40 JAIL_MEM=100M JAIL_TIME=120