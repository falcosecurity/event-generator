FROM golang:1.23.1-alpine3.20 AS builder

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

RUN apk add --no-cache make bash

WORKDIR /event-generator

COPY . .

RUN make


FROM alpine:3.20

RUN apk add --no-cache sudo polkit libcap e2fsprogs-extra openssh nmap netcat-openbsd wget curl

COPY --from=builder /event-generator/event-generator /bin/event-generator

ENTRYPOINT ["/bin/event-generator"]
