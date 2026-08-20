# docker-intrude

Linux statically-linked utility that executes local host binaries inside a specific Docker network namespace. 

It spins up a temporary container with a static IP, uses `nsenter` to attach your command to its network, and runs it under your current user.

## Security & Trust Model

By default, `docker-intrude` is designed to run tools that require Linux file capabilities (like `/bin/ping` or `gdb`). 
To balance usability and security, it applies the following isolation measures before executing your command:
- **Capability Shedding:** The wrapper holds its file capabilities (`cap_sys_admin`, `cap_sys_ptrace`, `cap_setpcap`) only long enough to enter the namespace and mount `resolv.conf`. After `fork()`, the parent drops **all** capability sets (including Bounding) before entering its wait loop; the child drops Effective/Permitted/Inheritable/Ambient (and Bounding, in `--strict` mode) before exec'ing the target.
- **Setuid Protection:** Activates and **locks** `SECBIT_NOROOT` (and `SECBIT_NO_CAP_AMBIENT_RAISE`) so that legacy setuid-root binaries can no longer automatically acquire root privileges during execution. Locking makes the boundary irreversible for the lifetime of the spawned process; without the lock, `SECBIT_NOROOT` would be advisory only, since any process can clear it via `prctl` without requiring any capability.
- **Bounding Set Preservation:** Leaves the Capability Bounding Set intact by default so that legitimate file capabilities continue to function.

### Accepted Design Tradeoffs & Operational Limits

Because `docker-intrude` is designed as a local development and debugging wrapper, certain operational behaviors are intentional tradeoffs:

* **Environment Variable Inheritance:** The target command inherits your current environment variables unaltered (including `PATH`, `HOME`, and API tokens). This is required for build tools (like Maven, Gradle, or npm) to function properly, but means `docker-intrude` does not scrub sensitive variables from the target process.
* **Elevated File Capabilities (`setcap`):** The binary requires `cap_sys_admin`, `cap_sys_ptrace`, and `cap_setpcap` to manipulate kernel network namespaces without `sudo`. Users in the local `docker` group are already equivalent to `root` on Linux systems; these capabilities are restricted to executing namespaces and should only be installed on single-tenant or trusted developer workstations.
* **Custom Socket Paths (`DOCKER_HOST`):** The tool honors the `DOCKER_HOST` environment variable if pointing to a local UNIX socket. While `docker-intrude` validates that the socket owner matches the current user or `root`, users should ensure their environment variables are not manipulated.

### Strict Mode (`--strict`)
If your command doesn't need file capabilities, or if you prefer maximum privilege isolation, 
pass the `--strict` flag to clear the Bounding Set as well:

```bash
docker-intrude --name my-project --net dev-net --ip 172.18.0.22 --strict -- ping 172.18.0.1
```

### Lax Mode (`--lax`)
If your command needs a setuid-root binary to actually function as root (for example `sudo`, or a
legacy installer), the default locked `SECBIT_NOROOT` boundary will block it. Pass `--lax` to skip
securebits manipulation entirely, so setuid-root binaries can acquire privileges through the normal
kernel path. File capabilities continue to work (the Bounding Set is preserved).

`--lax` reduces isolation and is mutually exclusive with `--strict`. Use it only when the command
genuinely requires it.

```bash
docker-intrude --name my-project --net dev-net --ip 172.18.0.22 --lax -- sudo whoami
```

## How It Works & DNS Resolution
`docker-intrude` provisions a temporary network container to hold a specific Docker network namespace open. 

It then uses kernel namespaces (`setns`) to attach your host command to that network.

Host binary would still read the host's `/etc/resolv.conf` and fail to resolve names in most distros.
To address this without modifying your host filesystem, `docker-intrude` overrides the configuration:

1. It unshares the mount namespace (`CLONE_NEWNS`) to isolate filesystem changes from the host.
2. It marks the root mount as private (`MS_PRIVATE | MS_REC`) to prevent mount propagation.
3. It creates a temporary file (`/dev/shm`) and writes Docker's embedded DNS configuration (`nameserver 127.0.0.11\noptions ndots:0\n`) to it.
4. It bind-mounts this file directly over `/etc/resolv.conf` and unlinks the source file from `/dev/shm`.


## Prerequisites
- **Linux only** (relies on native kernel namespaces).
- **Docker** running and accessible.

## Installation
Install the latest pre-compiled binary via curl:
```bash
curl -sSL \
  https://github.com/optionfactory/docker-intrude/releases/latest/download/docker-intrude-linux-amd64-musl \
  | sudo tee /usr/local/bin/docker-intrude > /dev/null \
  && sudo chown root:docker /usr/local/bin/docker-intrude \
  && sudo chmod 750 /usr/local/bin/docker-intrude \
  && sudo setcap cap_sys_admin,cap_sys_ptrace,cap_setpcap+ep /usr/local/bin/docker-intrude
```

## Build from Source
Ensure you have Rust installed, then clone the repository and build:

```bash
git clone [https://github.com/optionfactory/docker-intrude](https://github.com/optionfactory/docker-intrude)
cd docker-intrude
make build-release 
make install
```

## Usage
```bash
docker-intrude --name <name> --net <network> --ip <ip-address> [-v] -- <command...>
```

## Example
Run a local Maven project inside the dev-net Docker network:
```bash
docker-intrude --name my-project --net dev-net --ip 172.18.0.22 -- ./mvn spring-boot:run
```

## Options
- `--name`, `-n` : Name of the temporary Docker container.
- `--net` : The Docker network to join.
- `--ip` : The IP address to assign to the container.
- `--verbose`, `-v` : Enable detailed setup and status logging.
- `--strict` : Clear the Capability Bounding Set (maximum isolation; breaks file-capability tools like `ping`/`gdb`).
- `--lax` : Disable setuid-root protection entirely (no securebits). For commands needing `sudo`/legacy setuid tools. Mutually exclusive with `--strict`.
- `--` : Separates wrapper arguments from the command being executed.
