FROM golang:1.23.1-bookworm AS builder

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

RUN apt-get -y update && apt-get install -y make bash && apt clean -y && rm -rf /var/lib/apt/lists/*

WORKDIR /event-generator

COPY . .

RUN make


FROM debian:bookworm-slim

RUN apt-get -y update && \
    apt-get -y install policykit-1 libcap-dev e2fsprogs openssh-client openssh-server nmap netcat-openbsd wget \
    curl && \
    apt clean -y && rm -rf /var/lib/apt/lists/*

COPY --from=builder --chmod=0755 /event-generator/event-generator /bin/event-generator

ENTRYPOINT ["/bin/event-generator"]
