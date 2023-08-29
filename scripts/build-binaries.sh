#! /bin/bash
if [ $(uname) = "Darwin" ]; then
    readlink="greadlink"
    dirname="gdirname"
else
    readlink="readlink"
    dirname="dirname"
fi

PROJECT_ROOT=$($dirname $($dirname "$($readlink -f "$0")"))
PLATFORM=$1

mkdir -p dist

case "$PLATFORM" in
"alpine3.17") DOCKER_TAG="3.17"; VARIANT="alpine";;
"alpine3.18") DOCKER_TAG="3.18"; VARIANT="alpine";;
"ubuntu18.04") DOCKER_TAG="buster"; VARIANT="debian";;
"ubuntu20.04") DOCKER_TAG="bullseye"; VARIANT="debian";;
"ubuntu22.04") DOCKER_TAG="bookworm"; VARIANT="debian";;
"buster") DOCKER_TAG="buster"; VARIANT="debian";;
"bullseye") DOCKER_TAG="bullseye"; VARIANT="debian";;
"bookworm") DOCKER_TAG="bookworm"; VARIANT="debian";;
*) echo "Unsupported Platform $1"; exit 1;;
esac

if [ $VARIANT = "alpine" ]; then
    DOCKERFILE=$(cat <<EOF
FROM alpine:$DOCKER_TAG
RUN apk update && apk add build-base libseccomp libseccomp-dev musl-dev curl
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="$PATH:/root/.cargo/bin"
ENV RUSTFLAGS="-C target-feature=-crt-static"
CMD ["/io/scripts/build.sh"]
EOF
    )
elif [ $VARIANT = "debian" ]; then
    DOCKERFILE=$(cat <<EOF
FROM rust:$DOCKER_TAG
RUN apt update && apt install -y libseccomp-dev
CMD ["/io/scripts/build.sh"]
EOF
    )
fi

echo "$DOCKERFILE" > jail-builder.dockerfile

docker build -t jail-builder -f jail-builder.dockerfile .
docker run --rm -e FILEUSER="$(id -u):$(id -g)" -e PLATFORM=$PLATFORM -v $PROJECT_ROOT:/io jail-builder
rm jail-builder.dockerfile
ls dist/
