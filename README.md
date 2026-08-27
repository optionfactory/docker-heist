# docker-heist

A collection of small, statically-linked **developer tools** for local
workstations that pull off the tricks Docker makes awkward, running host tools on
container networks, and making bind-mount ownership just work.

| Tool | Problem it solves |
| --- | --- |
| [**docker-bluff**](crates/docker-bluff/README.md) | Bind mounts give you a UID/GID mismatch, files a container creates come out `root`-owned on the host, and your files aren't writable by the container's user. It wraps the bind mounts in Linux **idmapped mounts** so both sides see the files as their own, at native speed, no `bindfs`/FUSE, no `chown -R`. |
| [**docker-intrude**](crates/docker-intrude/README.md) | You want a *host* tool (`psql`, `curl`, a debugger, your app under `mvn`/`cargo run`) to reach container IPs and service DNS names on a **specific Docker network**, without dockerizing it or publishing ports. It drops your command straight into that network's namespace, still running as you. |

## Threat Model

**These are developer tools for trusted, single-tenant workstations, not a
security boundary.** They perform privileged mount and namespace operations and
are installed executable only by the `docker` group, whose members are already
root-equivalent on the host (`docker run -v /:/host --privileged ...`), so the
tools grant them no new privilege. They are explicitly **not** hardened against a
hostile local user and are not meant for multi-tenant or production machines.

Within that scope each tool minimizes what it exposes: it runs as the invoking
user with file capabilities (never setuid-root), holds those capabilities only for
the privileged setup and drops them before waiting, and hands the command it runs
no capabilities of its own. See each tool's README for its specific measures.

## Layout

This is a Cargo workspace; the tools share one version and are released
together.

```
crates/docker-bluff     # tool: idmapped-mount wrapper
crates/docker-intrude   # tool: network-namespace entry
crates/dockersock       # shared: Docker daemon Unix-socket client
crates/privileges       # shared: Linux capability drop/query
crates/signals          # shared: parent-side signal handling
```

## Build & install

```bash
make build            # debug build of every tool
make build-release    # static musl release build of every tool
make test             # run all tests

make install                 # install every tool (each with its own capabilities)
make install-docker-bluff    # or just one
```

Each tool installs `root:docker`, mode `750` (runnable only by the `docker`
group, which is already root-equivalent), with a tool-specific `setcap` set,
see the per-crate README for exactly which capabilities each one needs and why.

To install a prebuilt binary instead, download the tool's
`<tool>-linux-amd64-musl` asset from the [latest
release](https://github.com/optionfactory/docker-heist/releases/latest), then set
its ownership and capabilities the same way `make install-<tool>` does, the
per-crate README lists the exact `chown`/`chmod`/`setcap` for that tool.
