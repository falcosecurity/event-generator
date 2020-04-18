FROM golang:alpine

RUN mkdir -p /usr/src/app

RUN apk add --no-cache make bash

WORKDIR /usr/src/app

COPY . .

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

RUN make

ENTRYPOINT ["./event-generator"]
