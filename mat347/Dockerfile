FROM sagemath/sagemath:latest

USER root
RUN apt-get update -y && \
    apt-get install -y socat curl

WORKDIR /app
COPY chall.py run.sh flag.txt /app/

RUN chmod +x /app/chall.py /app/run.sh

RUN curl -sSL https://raw.githubusercontent.com/google/kctf/v1/docker-images/challenge/pow.py -o /app/pow.py

USER sage
RUN /home/sage/sage/local/var/lib/sage/venv-python3.12.5/bin/python3.12 -m pip install pycryptodome ecdsa

EXPOSE 5000

CMD ["socat", \
     "TCP-LISTEN:5000,reuseaddr,fork", \
     "EXEC:/app/run.sh,stderr"]
