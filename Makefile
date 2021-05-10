CONTAINER_WORKDIR=/backend.ai-jail

manylinux:
	docker build -f Dockerfile.builder-manylinux -t jail-builder-manylinux .
	docker run --rm -v "$(shell pwd)":$(CONTAINER_WORKDIR) -w $(CONTAINER_WORKDIR) jail-builder-manylinux
	mkdir -p build-manylinux
	mv backend.ai-jail build-manylinux/jail

musllinux:
	docker build -f Dockerfile.builder-musllinux -t jail-builder-musllinux .
	docker run --rm -v "$(shell pwd)":$(CONTAINER_WORKDIR) -w $(CONTAINER_WORKDIR) jail-builder-musllinux
	mkdir -p build-musllinux
	mv backend.ai-jail build-musllinux/jail

inside-container:
	go build -tags netgo -ldflags '-extldflags "-static"' -v

prepare-dev:
	docker build -f Dockerfile -t jail-dev .
	docker create -i -t -v "$(shell pwd)":$(CONTAINER_WORKDIR) -w $(CONTAINER_WORKDIR) --security-opt=seccomp:unconfined --name jail-dev jail-dev

build:
	go mod tidy
	go build -tags netgo -ldflags '-extldflags "-static"' -v
