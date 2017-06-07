FROM alpine:3.6

# This container is for daily development.

RUN apk add --no-cache build-base git gcc go libseccomp-dev linux-headers

RUN mkdir -p /root/workspace/src
ENV GOPATH=/root/workspace

RUN go get github.com/seccomp/libseccomp-golang
RUN go get github.com/fatih/color

ENV TERM=xterm-256color

WORKDIR /root/workspace/src/github.com/lablup/sorna-jail
CMD ["/bin/ash"]
