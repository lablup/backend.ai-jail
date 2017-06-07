# sorna-jail

A dynamic sandbox for Sorna kernels.

 * Requirements: Docker, make


## Testing and Debugging

Run `make prepare-dev` to build and create a development container based on
Alpine Linux.  Afterwards, you can `docker start jail-dev` and `docker attach
jail-dev` to access its shell.

Inside the container, you can use `go get`, `go build`, and so on seamlessly.

To test the jail, run `./sorna-jail <policy-name> <command-args>`.
Note that this jail binary cannot be executed outside the container even though
it exists inside the working copy, if you use different OS/architectures for
the host (e.g., macOS).

To debug, set the following environment variable: `JAIL_DEBUG=1`.


## Building Release Binaries

Run `make manylinux` for glibc-based binaries (for Ubuntu/Debian Linux) and
`make musllinux` for musl-based binaries (for Alpine Linux).

