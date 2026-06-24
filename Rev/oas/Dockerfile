FROM ubuntu:18.04@sha256:152dc042452c496007f07ca9127571cb9c29697f42acbfad72324b2bb2e43c98

WORKDIR /v1t

COPY oas ./oas
COPY quiz ./quiz

RUN chmod +x ./oas
RUN ./oas quiz

CMD ["./oas", "quiz"]