FROM pwn.red/jail

COPY --from=python@sha256:2751cbe93751f0147bc1584be957c6dd4c5f977c3d4e0396b56456a9fd4ed137 / /srv

RUN mkdir -p /srv/app
WORKDIR /srv/app
COPY --chmod=555 chall.py run
COPY flag.txt .

ENV JAIL_PIDS=10 JAIL_MEM=50M JAIL_TIME=200
