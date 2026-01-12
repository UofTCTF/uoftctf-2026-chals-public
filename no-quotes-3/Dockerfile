FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends mariadb-server mariadb-client gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY ./src/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY ./src ./

RUN chmod +x /app/entrypoint.sh

RUN echo "uoftctf{r3cuR510n_7h30R3M_m0M3n7}" > /root/flag.txt && \
    chmod 400 /root/flag.txt && \
    chown root:root /root/flag.txt

COPY ./src/readflag.c /readflag.c
RUN gcc /readflag.c -o /readflag
RUN rm /readflag.c
RUN chmod 4755 /readflag

EXPOSE 5000

CMD ["/app/entrypoint.sh"]
