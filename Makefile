CONTAINER_WORKDIR=/go/src/github.com/lablup/backend.ai-jail

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
	export GOPATH=/go/src/github.com/lablup/backend.ai-jail
	go build -tags netgo -ldflags '-extldflags "-static"' -v

prepare-dev:
	docker build -f Dockerfile -t jail-dev .
	docker create -i -t -v "$(shell pwd)":$(CONTAINER_WORKDIR) -w $(CONTAINER_WORKDIR) --security-opt=seccomp:unconfined --security-opt=apparmor:unconfined --name jail-dev jail-dev

test-dev:
	docker build -f Dockerfile -t test-dev .
	docker create -i -t -v "$(shell pwd)":$(CONTAINER_WORKDIR) -w $(CONTAINER_WORKDIR) --security-opt=seccomp:unconfined --security-opt=apparmor:un      confined --name test-dev test-dev

clean:
	docker rm jail-dev
