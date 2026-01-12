FROM nginx:1.29.3

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang llvm gcc make \
        iproute2 \
        python3 \
        libbpf-dev linux-libc-dev \
        ca-certificates nginx && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY firewall.c entrypoint.sh ./
RUN chmod +x /src/entrypoint.sh

COPY index.html /usr/share/nginx/html/index.html
COPY flag.html /usr/share/nginx/html/flag.html

RUN sed -i 's/listen\s\+80;/listen 5000;/' /etc/nginx/conf.d/default.conf
EXPOSE 5000

ENTRYPOINT ["/src/entrypoint.sh"]
