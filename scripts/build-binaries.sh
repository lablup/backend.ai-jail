#! /bin/bash
mkdir -p dist
PLATFORM=$1
case "$PLATFORM" in
"alpine") DOCKER_TAG="alpine";
"ubuntu18.04") DOCKER_TAG="buster";
"ubuntu20.04") DOCKER_TAG="bullseye";
"ubuntu22.04") DOCKER_TAG="bookworm";
*) echo "Unsupported Platform $1"; exit 1;;
esac

docker run --rm -u $(id -u):$(id -g) -e PLATFORM=$PLATFORM -v $PROJECT_ROOT:/io rust:$DOCKER_TAG /io/scripts/build.sh
ls dist/
