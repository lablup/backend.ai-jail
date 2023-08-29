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
"alpine") DOCKER_TAG="alpine";;
"ubuntu18.04") DOCKER_TAG="buster";;
"ubuntu20.04") DOCKER_TAG="bullseye";;
"ubuntu22.04") DOCKER_TAG="bookworm";;
"buster") DOCKER_TAG="buster";;
"bullseye") DOCKER_TAG="bullseye";;
"bookworm") DOCKER_TAG="bookworm";;
*) echo "Unsupported Platform $1"; exit 1;;
esac

docker run --rm -e FILEUSER="$(id -u):$(id -g)" -e PLATFORM=$PLATFORM -v $PROJECT_ROOT:/io rust:$DOCKER_TAG /io/scripts/build.sh
ls dist/
