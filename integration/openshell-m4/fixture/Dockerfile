FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /mission/input /mission/output /mission/unrelated /sandbox \
    && printf '%s\n' 'field-lab-input' > /mission/input/input.txt \
    && printf '%s\n' 'not-a-grant' > /mission/unrelated/secret.txt \
    && printf '%s\n' 'workdir-only' > /sandbox/only-via-workdir.txt \
    && chmod 0777 /mission /mission/input /mission/output /mission/unrelated /sandbox \
    && chmod 0666 /mission/input/input.txt /mission/unrelated/secret.txt /sandbox/only-via-workdir.txt

COPY probe.py /mission/input/probe.py

WORKDIR /sandbox
