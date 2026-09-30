# docker-heist

A collection of small, statically-linked tools that pull off the tricks Docker
makes awkward: running host tools on container networks, making bind-mount
ownership just work, getting a daemon's file-only logs onto stderr.

| Tool | Problem it solves |
| --- | --- |
| [**docker-bluff**](crates/docker-bluff/README.md) | Bind mounts give you a UID/GID mismatch, files a container creates come out `root`-owned on the host, and your files aren't writable by the container's user. It wraps the bind mounts in Linux **idmapped mounts** so both sides see the files as their own, at native speed, no `bindfs`/FUSE, no `chown -R`. |
| [**docker-intrude**](crates/docker-intrude/README.md) | You want a *host* tool (`psql`, `curl`, a debugger, your app under `mvn`/`cargo run`) to reach container IPs and service DNS names on a **specific Docker network**, without dockerizing it or publishing ports. It drops your command straight into that network's namespace, still running as you. |
| [**docker-snitch**](crates/docker-snitch/README.md) | Runs a command and relays whatever gets appended to a set of files to stderr, removing from the files what it has relayed. For daemons (MySQL, MariaDB, ...) that insist on writing some logs to **regular files** and refuse `/dev/stderr`, pipes and FIFOs: those logs reach `docker logs` and stop growing forever. |

## Install

The tools are packaged for Debian/Ubuntu (`amd64`) and Fedora/RHEL/openSUSE
(`x86_64`), one package per tool. Set up the
[optionfactory package repository](https://github.com/optionfactory/linux-packages#setup)
once, then install the ones you need:

```bash
sudo apt install docker-bluff docker-intrude   # or: sudo dnf install ...
```

The setup commands run unattended, so they work as-is in provisioning scripts
and Dockerfiles; see [In a Dockerfile](https://github.com/optionfactory/linux-packages#in-a-dockerfile)
for installing `docker-snitch` in an image.

The packages install each developer tool as `make install` does: `root:docker`,
mode `750`, with its capability set, creating the `docker` group if it is
missing. The tools run only for members of that group; if you are not one yet,
add yourself and log out and back in (membership is root-equivalent, see
[Threat Model](#threat-model)):

```bash
sudo usermod -aG docker "$USER"
```

## Threat Model

### Developer tools: docker-bluff, docker-intrude

**These are developer tools for trusted, single-tenant workstations, not a
security boundary.** They perform privileged mount and namespace operations and
are installed executable only by the `docker` group, whose members are already
root-equivalent on the host (`docker run -v /:/host --privileged ...`), so the
tools grant them no new privilege. That premise holds only where a Docker daemon
is installed: the packages create the `docker` group if it is missing, and on a
machine without Docker that group is not root-equivalent, so adding a user to it
does grant the tools' capabilities. They are explicitly **not** hardened against
a hostile local user and are not meant for multi-tenant or production machines.

Within that scope each tool minimizes what it exposes: it runs as the invoking
user with file capabilities (never setuid-root), holds those capabilities only for
the privileged setup and drops them before waiting, and hands the command it runs
no capabilities of its own. See each tool's README for its specific measures.

### docker-snitch

**docker-snitch is used in production images**, where it runs *inside* the
container as the service user (after the entrypoint has dropped privileges with
`setpriv`), with no capabilities and no setuid bit, and performs no privileged
operation:
it opens files, spawns one child, waits, and forwards signals. It never talks to
the Docker daemon. Its attack surface is that of any process running as the
service user: it can read and truncate the log files it was given, and nothing
more than the daemon it wraps already could.

## Layout

This is a Cargo workspace; the tools share one version and are released
together.

```
crates/docker-bluff     # tool: idmapped-mount wrapper
crates/docker-intrude   # tool: network-namespace entry
crates/docker-snitch    # tool: relays a daemon's file logs to stderr, compacting them
crates/dockersock       # shared: Docker daemon Unix-socket client
crates/privileges       # shared: Linux capability drop/query
crates/signals          # shared: parent-side signal handling
```

## Build & install

```bash
make build            # debug build of every tool
make build-release    # static musl release build of every tool
make test             # run all tests

make install                 # install the developer tools (each with its own capabilities)
make install-docker-bluff    # or just one
make install-docker-snitch  # for local testing only; images install it from the release asset
```

Each developer tool installs `root:docker`, mode `750` (runnable only by the
`docker` group, which is already root-equivalent), with a tool-specific `setcap`
set, see the per-crate README for exactly which capabilities each one needs and
why. `docker-snitch` needs no capabilities: image builds download it from the
release assets and install it plain.

To install a prebuilt binary instead, download the tool's
`<tool>-linux-amd64-musl` asset from the [latest
release](https://github.com/optionfactory/docker-heist/releases/latest), then set
its ownership and capabilities the same way `make install-<tool>` does, the
per-crate README lists the exact `chown`/`chmod`/`setcap` for that tool.
