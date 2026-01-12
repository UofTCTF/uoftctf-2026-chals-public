FROM python:3.11-slim

RUN apt-get update && apt-get install -y curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY ./src/requirements.txt .
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY ./src .

RUN curl -sSL https://raw.githubusercontent.com/google/kctf/v1/docker-images/challenge/pow.py -o /app/pow.py

EXPOSE 5000

ENV POW_DIFFICULTY=31337

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000"]
