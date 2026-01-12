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

RUN echo "uoftctf{d1d_y0u_wR173_4_pr0P3r_qU1n3_0r_u53_INFORMATION_SCHEMA???}" > /root/flag.txt && \
    chmod 400 /root/flag.txt && \
    chown root:root /root/flag.txt

COPY ./src/readflag.c /readflag.c
RUN gcc /readflag.c -o /readflag
RUN rm /readflag.c
RUN chmod 4755 /readflag

EXPOSE 5000

CMD ["/app/entrypoint.sh"]
