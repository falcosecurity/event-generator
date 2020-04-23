FROM golang:1.14-alpine3.11 as builder

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

RUN apk add --no-cache make bash git

WORKDIR /event-generator
COPY . .

RUN make

FROM alpine:3.11
COPY --from=builder /event-generator/event-generator /bin/event-generator

# Need to have this for helper.RunShell
RUN apk add bash 

# Need to have this for syscall.WriteBelowRpmDatabase
RUN mkdir -p /var/lib/rpm/

ENTRYPOINT ["/bin/event-generator"]
