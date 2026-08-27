# docker-intrude

Run a local host binary as if it were inside a specific Docker network - reaching
container IPs and service DNS names - without dockerizing the tool or publishing
ports. It's a **developer tool** for local workstations, one of the
[docker-heist](../../README.md) tools.

## The Problem

You're developing against services running on a Docker network (a database, a
message broker, other containers). You want to point a *host* tool at them - `psql`,
`redis-cli`, `curl`, a debugger, or your app under `cargo run` / `mvn` - and have it
resolve container names and reach container IPs, exactly as a container on that
network would. The usual options are all awkward: publish ports and hardcode
`localhost:port`, dockerize the tool just to run it, or fiddle with `/etc/hosts`.

`docker-intrude` drops your command straight into the network namespace of that
Docker network, so it sees the network like any container does - and it still runs
as *you*, with your files, environment and terminal.

## How It Works

It provisions a temporary "holder" container to keep the Docker network namespace
open, then uses `setns(2)` to attach your host command to that network.

A host binary would otherwise read the host's `/etc/resolv.conf` and fail to
resolve names on the network, so - without touching the host filesystem - it also
redirects DNS inside a private mount namespace:

1. `unshare(CLONE_NEWNS)` to isolate mount changes from the host.
2. Make the root mount private (`MS_REC | MS_PRIVATE`) so nothing propagates back.
3. Write Docker's embedded resolver config (`nameserver 127.0.0.11`, `options ndots:0`) to a `/dev/shm` file.
4. Bind-mount that file over `/etc/resolv.conf` and unlink the source.

## Security & Trust Model

**This is a developer tool for trusted, single-tenant workstations.** It performs
privileged namespace and mount operations and is installed executable only by the
`docker` group - whose members are already root-equivalent on the host (`docker run
-v /:/host --privileged ...`), so it grants them no new privilege. It is **not** a
security boundary against a hostile local user, and is not meant for multi-tenant
or production machines.

Within that scope it minimizes what the target command is handed. By default it is
built to run tools that need Linux file capabilities (like `/bin/ping` or `gdb`),
and before exec it applies:

- **Capability shedding** - it holds its capabilities (`cap_sys_admin`,
  `cap_sys_ptrace`, `cap_setpcap`) only long enough to enter the namespace and
  mount `resolv.conf`. After `fork()` the parent drops **all** capability sets
  (including the bounding set) before it waits; the child drops
  effective/permitted/inheritable/ambient (and the bounding set, in `--strict`)
  before exec.
- **Setuid protection** - it sets and **locks** `SECBIT_NOROOT` (and
  `SECBIT_NO_CAP_AMBIENT_RAISE`) so legacy setuid-root binaries cannot silently
  regain root during exec. Locking makes the boundary irreversible for the
  process's lifetime; unlocked, `SECBIT_NOROOT` is advisory only (any process can
  clear it via `prctl` without a capability).
- **Bounding set preserved** by default, so legitimate file-capability tools keep working.

Accepted tradeoffs, since this is a dev wrapper:

- **Environment inheritance** - the target inherits your environment unaltered
  (`PATH`, `HOME`, tokens); required for build tools, but not scrubbed.
- **`DOCKER_HOST`** - honored only for a local `unix://` socket, whose owner must
  be `root` or the current user.

### Strict Mode (`--strict`)

If your command needs no file capabilities, `--strict` also clears the bounding
set for maximum isolation:

```bash
docker-intrude --name my-project --net dev-net --ip 172.18.0.22 --strict -- ping 172.18.0.1
```

### Lax Mode (`--lax`)

If your command needs a setuid-root binary to actually become root (e.g. `sudo`, a
legacy installer), the locked `SECBIT_NOROOT` boundary would block it. `--lax`
skips securebits entirely so setuid-root works through the normal kernel path
(file capabilities still work; the bounding set is preserved). It reduces
isolation and is mutually exclusive with `--strict`.

```bash
docker-intrude --name my-project --net dev-net --ip 172.18.0.22 --lax -- sudo whoami
```

## Prerequisites

- Linux (relies on native kernel namespaces).
- A local Docker daemon reachable over a `unix://` socket.

## Installation

Built and installed from the [docker-heist](../../README.md) workspace:

```bash
make install-docker-intrude
```

That installs the binary `root:docker`, mode `750` (runnable only by the
already-root-equivalent `docker` group) and grants the capabilities below. By
hand (also how you'd install a released binary):

```bash
sudo install -o root -g docker -m 750 docker-intrude /usr/local/bin/docker-intrude
sudo setcap cap_sys_admin,cap_sys_ptrace,cap_setpcap+ep /usr/local/bin/docker-intrude
```

Why each capability:

- **`cap_sys_admin`** - `setns(2)` into the container's network namespace, plus
  the mount work (`unshare(CLONE_NEWNS)`, bind-mounting `resolv.conf`).
- **`cap_sys_ptrace`** - reach the holder container's `/proc/<pid>/ns` files to
  enter its namespace.
- **`cap_setpcap`** - drop the capability bounding set (`PR_CAPBSET_DROP`) in
  `--strict`.

See the [workspace README](../../README.md) for building all the tools and the release/download process.

## Usage

```
docker-intrude --name <NAME> --net <NET> --ip <IP> [-v] [--strict|--lax] -- <COMMAND...>
```

| Option | Meaning |
| --- | --- |
| `--name`, `-n` | Name of the temporary holder container. |
| `--net` | Docker network to join. |
| `--ip` | IPv4 address to assign to the container. |
| `--verbose`, `-v` | Detailed setup and status logging. |
| `--strict` | Also clear the capability bounding set (max isolation; breaks file-capability tools like `ping`/`gdb`). |
| `--lax` | Disable setuid-root protection (no securebits); for commands needing `sudo`/legacy setuid tools. Mutually exclusive with `--strict`. |
| `--` | Separates wrapper options from the command being run. |

### Examples

```bash
# Run a local Maven app on the dev-net network (reaches db, other services by name)
docker-intrude --name my-project --net dev-net --ip 172.18.0.22 -- ./mvnw spring-boot:run

# Talk to a container-only Postgres from the host psql
docker-intrude --name psql --net dev-net --ip 172.18.0.23 -- psql -h db -U app

# Debug connectivity with ping (needs file capabilities, so not --strict)
docker-intrude --name dbg --net dev-net --ip 172.18.0.24 -- ping 172.18.0.1
```
