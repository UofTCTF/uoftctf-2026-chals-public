FROM gcc:14 AS builder

WORKDIR /build

COPY catflag.c catflag.c

RUN gcc -O2 -static -s catflag.c -o catflag \
 && chown root:root catflag \
 && chmod 4755 catflag 

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY --from=builder /build/catflag /catflag
COPY --chmod=400 flag.txt /flag.txt

# Run as non-root
RUN useradd -m flaskuser
USER flaskuser

WORKDIR /app

RUN mkdir /home/flaskuser/flask_download

# Install dependencies
RUN pip download -d /home/flaskuser/flask_download flask

# Copy application code
COPY app.py app.sh .

# Create upload directory with safe permissions
RUN mkdir /app/uploads && chmod 755 /app/uploads

EXPOSE 5000

CMD ["bash", "app.sh"]