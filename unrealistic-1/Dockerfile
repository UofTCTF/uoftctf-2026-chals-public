FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
  ; apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
    ca-certificates \
    fonts-liberation \
  ; rm -rf /var/lib/apt/lists/*

ENV CHROME_BIN=/usr/bin/chromium \
  CHROMEDRIVER_BIN=/usr/bin/chromedriver

WORKDIR /app

COPY ./src/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY ./src /app

RUN mkdir -p /app/db

EXPOSE 5000 5001

CMD ["python", "-u", "app.py"]
