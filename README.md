# Backend.AI Jail

A dynamic sandbox for Backend.AI kernels.

## Testing and Debugging

* Requirements: Docker, make

Just run `make prepare-dev` to build and create a development container based
on Ubuntu.  Afterwards, you can `docker start jail-dev` and `docker
attach jail-dev` to access its shell.

Inside the container, run `cargo build`. This will build our backend.ai-jail.

To test the jail, run `target/debug/backendai-jail [--policy <policy-name>] <command-args>`.
Note that this jail binary cannot be executed outside the container even though
it exists inside the working copy, if you use different OS/architectures for
the host (e.g., macOS).

To debug, add `--debug` flag to the command-line arguments.

## Building Release Binaries

Run `make manylinux` for glibc-based binaries (for Ubuntu/Debian Linux) and
`make musllinux` for musl-based binaries (for Alpine Linux).

On the target systems or images, you need to install libseccomp 2.2 or higher
to use Backend.AI Jail.