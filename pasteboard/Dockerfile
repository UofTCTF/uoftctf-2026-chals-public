FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        chromium \
        chromium-driver \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CHROME_BIN=/usr/bin/chromium \
    CHROMEDRIVER_PATH=/usr/bin/chromedriver

WORKDIR /app

RUN pip install --no-cache-dir flask selenium

COPY ./src /app

RUN chown -R www-data:www-data /app

RUN mkdir -p /var/www

RUN chown -R www-data:www-data /var/www

USER www-data

EXPOSE 5000

CMD ["python", "app.py"]
