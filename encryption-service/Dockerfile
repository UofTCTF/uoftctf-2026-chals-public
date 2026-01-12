FROM python:3-slim AS app

WORKDIR /app

# Install crypto dependency
RUN pip install --no-cache-dir pycryptodome

# Copy your script
COPY enc.py .
COPY run.sh run
COPY flag.txt /flag.txt

FROM pwn.red/jail
COPY --from=app / /srv

ENV JAIL_PIDS=20 JAIL_MEM=30M JAIL_TIME=120 JAIL_TMP_SIZE=5M