FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    socat coreutils \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 ctf

WORKDIR /home/ctf

COPY service ./service
COPY flag.txt /flag

RUN chown root:root ./service /flag \
    && chmod 555 ./service \
    && chmod 444 /flag

USER ctf

EXPOSE 31337

CMD ["socat", "-T", "60", "TCP-LISTEN:31337,reuseaddr,fork", "EXEC:/usr/bin/timeout 60 /home/ctf/service,stderr"]