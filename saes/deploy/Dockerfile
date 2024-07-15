FROM ubuntu:jammy-20240125@sha256:bcc511d82482900604524a8e8d64bf4c53b2461868dac55f4d04d660e61983cb AS builder

ADD --chmod=0755 --checksum=sha256:4c97fd03a3b181996b1473f3a99b69a1efc6ecaf2b4ede061b6bd60a96b9325a \
    https://raw.githubusercontent.com/reproducible-containers/repro-sources-list.sh/v0.1.0/repro-sources-list.sh \
    /usr/local/bin/repro-sources-list.sh

RUN \
    --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    /usr/local/bin/repro-sources-list.sh && \
    apt-get update && apt-get install -y \
    musl-dev \
    musl-tools \
    make \
    xz-utils

WORKDIR /work

ADD --chmod=0666 --checksum=sha256:4300f2fbc3996bc389d3c03a74662bfff3106ac1930942c5bd27580c7ba5053d \
    https://yx7.cc/code/ynetd/ynetd-0.1.2.tar.xz \
    /work/ynetd-0.1.2.tar.xz

RUN tar -xJf ynetd-0.1.2.tar.xz && cd ynetd-0.1.2 && CC="musl-gcc" CFLAGS="-static" make

FROM python:3.12.4-slim-bookworm@sha256:d5f16749562233aa4bd26538771d76bf0dfd0a0ea7ea8771985e267451397ae4
COPY --from=builder /work/ynetd-0.1.2/ynetd /usr/local/bin

RUN mkdir /chall
WORKDIR /chall
COPY aes.py chall.py flag.txt saes.py .

EXPOSE 1024
CMD [ "ynetd", "-si", "y", "-so", "y", "-se", "y", "-p", "1024", "/usr/local/bin/python3 chall.py" ]
