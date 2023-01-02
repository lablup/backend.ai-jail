CONTAINER_WORKDIR=/src

prepare-dev:
	docker build -t jail-dev .
	docker rm -f rust || true
	docker create -i -t -v "$(shell pwd)":$(CONTAINER_WORKDIR) -w $(CONTAINER_WORKDIR) --security-opt=seccomp:unconfined --name rust jail-dev /bin/bash
	docker start rust

manylinux:
	docker build -f Dockerfile.builder-manylinux -t jail-builder-manylinux .
	docker run --rm -v "$(shell pwd)":$(CONTAINER_WORKDIR) -w $(CONTAINER_WORKDIR) jail-builder-manylinux
	mkdir -p out
	cp target/release/backendai-jail out/jail.manylinux.bin

musllinux:
	docker build -f Dockerfile.builder-musllinux -t jail-builder-musllinux .
	docker run --rm -v "$(shell pwd)":$(CONTAINER_WORKDIR) -w $(CONTAINER_WORKDIR) jail-builder-musllinux
	mkdir -p out
	cp target/release/backendai-jail out/jail.musllinux.bin
