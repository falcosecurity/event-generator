FROM alpine:latest as builder

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

RUN apk add --no-cache make bash git build-base go

WORKDIR /event-generator
COPY . .

RUN make

FROM alpine:latest

COPY --from=builder /event-generator/event-generator /bin/event-generator

# Need to have this for helper.RunShell
RUN apk add bash

# Need to have this for syscall.WriteBelowRpmDatabase
RUN mkdir -p /var/lib/rpm/

ENTRYPOINT ["/bin/event-generator"]
