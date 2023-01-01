FROM golang:1.19.4-alpine
# This container is for daily development.

RUN apk add --no-cache build-base git libseccomp-dev linux-headers libseccomp-static

CMD ["/bin/ash"]
