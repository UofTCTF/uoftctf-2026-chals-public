FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    socat gcc autoconf bison flex g++ git \
    libprotobuf-dev libnl-route-3-dev \
    libtool make pkg-config protobuf-compiler curl \
    && rm -rf /var/lib/apt/lists/*
RUN python3 -m pip install requests pycryptodome ecdsa gmpy2

RUN git clone https://github.com/google/nsjail.git /src/nsjail
WORKDIR /src/nsjail
RUN make

COPY ./readflag.c /readflag.c
RUN gcc /readflag.c -o /readflag
RUN rm /readflag.c
RUN chmod 111 /readflag

WORKDIR /app
COPY ./vibe_code.py /app/vibe_code.py
COPY ./run_vibe_code.sh /app/run_vibe_code.sh

RUN curl -sSL https://raw.githubusercontent.com/google/kctf/v1/docker-images/challenge/pow.py -o /app/pow.py

RUN useradd -m ctf

RUN mkdir /ctf && chown ctf /ctf && chmod 300 /ctf

USER ctf

EXPOSE 5000
CMD socat TCP-LISTEN:5000,reuseaddr,fork \
  EXEC:'python3 /app/vibe_code.py',pty,setsid,ctty,stderr,echo=0