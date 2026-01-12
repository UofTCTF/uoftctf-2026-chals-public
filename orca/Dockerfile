FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends socat \
    && pip install --no-cache-dir pycryptodome \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY ./src/server.py /app/server.py
COPY ./src/flag.txt /app/flag.txt

EXPOSE 5000
CMD ["socat", "-T300", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:python -u /app/server.py"]
