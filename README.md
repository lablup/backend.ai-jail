# Backend.ai-jail

A dynamic sandbox for Backend.Ai kernels.


## Testing and Debugging

 * Requirements: Docker, make

For this project, we use Go's module system - the Go's official depedency management system built into the go command.

**To run:

Just run `make prepare-dev` to build and create a development container based
on Alpine Linux.  Afterwards, you can `docker start jail-dev` and `docker
attach jail-dev` to access its shell.

Inside the container, run `make build`. This will build our backend.ai-jail. 

To test the jail, run `./backend.ai-jail <policy-name> <command-args>`.
Note that this jail binary cannot be executed outside the container even though
it exists inside the working copy, if you use different OS/architectures for
the host (e.g., macOS).

To debug, add `-debug` flag to the command-line arguments.


## Building Release Binaries

Run `make manylinux` for glibc-based binaries (for Ubuntu/Debian Linux) and
`make musllinux` for musl-based binaries (for Alpine Linux).

On the target systems or images, you need to install libseccomp 2.2 or higher
to use Sorna jail.
