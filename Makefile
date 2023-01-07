CONTAINER_WORKDIR := /src
ARCH := $(shell uname -i)

all: ubuntu18.04 ubuntu20.04 ubuntu22.04 alpine3.8

prepare-dev:
	docker build -t jail-dev -f dockerfiles/Dockerfile.dev .
	docker rm -f rust || true
	docker create -i -t -v "$(shell pwd)":$(CONTAINER_WORKDIR) -w $(CONTAINER_WORKDIR) --security-opt=seccomp:unconfined --name rust jail-dev /bin/bash
	docker start rust

ubuntu18.04:
	docker build -f dockerfiles/Dockerfile.builder-ubuntu18.04 -t jail-builder-ubuntu18.04 .
	docker run --rm -v "$(shell pwd)":$(CONTAINER_WORKDIR) -w $(CONTAINER_WORKDIR) jail-builder-ubuntu18.04
	mkdir -p out
	cp target/release/backendai-jail out/jail.ubuntu18.04.${ARCH}.bin

ubuntu20.04:
	docker build -f dockerfiles/Dockerfile.builder-ubuntu20.04 -t jail-builder-ubuntu20.04 .
	docker run --rm -v "$(shell pwd)":$(CONTAINER_WORKDIR) -w $(CONTAINER_WORKDIR) jail-builder-ubuntu20.04
	mkdir -p out
	cp target/release/backendai-jail out/jail.ubuntu20.04.${ARCH}.bin

ubuntu22.04:
	docker build -f dockerfiles/Dockerfile.builder-ubuntu22.04 -t jail-builder-ubuntu22.04 .
	docker run --rm -v "$(shell pwd)":$(CONTAINER_WORKDIR) -w $(CONTAINER_WORKDIR) jail-builder-ubuntu22.04
	mkdir -p out
	cp target/release/backendai-jail out/jail.ubuntu22.04.${ARCH}.bin

alpine3.8:
	docker build -f dockerfiles/Dockerfile.builder-alpine3.8 -t jail-builder-alpine3.8 .
	docker run --rm -v "$(shell pwd)":$(CONTAINER_WORKDIR) -w $(CONTAINER_WORKDIR) jail-builder-alpine3.8
	mkdir -p out
	cp target/release/backendai-jail out/jail.alpine3.8.${ARCH}.bin

