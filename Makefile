CONTAINER_WORKDIR=/go/src/github.com/lablup/sorna-jail

manylinux:
	docker build -f Dockerfile.builder-manylinux -t jail-builder-manylinux .
	docker run --rm -v "$(shell pwd)":$(CONTAINER_WORKDIR) -w $(CONTAINER_WORKDIR) jail-builder-manylinux
	mkdir -p build-manylinux
	mv sorna-jail build-manylinux/jail

musllinux:
	docker build -f Dockerfile.builder-musllinux -t jail-builder-musllinux .
	docker run --rm -v "$(shell pwd)":$(CONTAINER_WORKDIR) -w $(CONTAINER_WORKDIR) jail-builder-musllinux
	mkdir -p build-musllinux
	mv sorna-jail build-musllinux/jail

inside-container:
	go get -u github.com/fatih/color
	go get -u github.com/seccomp/libseccomp-golang
	go build -v

prepare-dev:
	docker build -f Dockerfile -t jail-dev .
	docker create -i -t -v "$(shell pwd)":$(CONTAINER_WORKDIR) -w $(CONTAINER_WORKDIR) --name jail-dev jail-dev
