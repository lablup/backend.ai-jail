FROM golang:1.12-alpine
# This container is for daily development.

RUN apk add --no-cache build-base git libseccomp-dev linux-headers

CMD ["/bin/ash"]
