FROM golang:1.12-alpine
# This container is for daily development.

RUN apk add --no-cache build-base git libseccomp-dev linux-headers
#RUN go get github.com/seccomp/libseccomp-golang && \
#    go get github.com/fatih/color && \
#    go get github.com/gobwas/glob && \
#    go get gopkg.in/yaml.v2

# Only one CMD command, so change this to RUN
# CMD ["make", "inside-container"]

# When running this image, mount the working copy root to
# /go/src/github.com/lablup/backend.ai-jail

CMD ["/bin/ash"]
