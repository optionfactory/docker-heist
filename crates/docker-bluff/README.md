# docker-bluff

Run `docker run`, or any command, with bind-mounted directories wrapped in Linux
idmapped mounts, so the process's user and the host user see each other's files
as their own - at native speed, with no `bindfs`/FUSE and no `chown -R`. It's a
**developer tool** for local workstations, one of the
[docker-heist](../../README.md) tools.

## The Problem

Bind mounts hand you a UID/GID mismatch. A container usually runs as `root` (or
some fixed uid baked into the image), while your files on the host are owned by
*you*. So:

- files the container writes into a mounted directory come out `root`-owned on the
  host, and you need `sudo` to delete or edit them afterwards;
- files you own aren't writable by the container's user, so builds and tools inside
  the container fail with permission errors.

The usual workarounds are all bad: `chown -R` back and forth (slow, races,
destroys ownership), `bindfs`/FUSE (a userspace filesystem in the hot path), or
running the container as your uid (breaks images that expect their own user).

`docker-bluff` fixes it at the mount layer: the kernel translates uids/gids on the
mount itself (`mount_setattr(MOUNT_ATTR_IDMAP)`, Linux >= 5.12), so the container's
user and you each see the files as your own, with no copying and nothing to undo.

## How It Works

`docker-bluff` is a prefix wrapper (like `sudo`/`strace`): its options come first,
then the command to run.

### The id mapping

Each `--id DISK:SEEN` installs a **swap** in the mount's `uid_map`/`gid_map`; every
id you don't name is passed through unchanged. For `--id me:0` (your uid being
`1000`):

```
0    1000 1        # disk 0 (root) -> appears as 1000 to the process
1    1    999
1000 0    1        # disk 1000 (you) -> appears as root to the process
1001 1001 4294966294
```

The left column is the id stored on disk, the right column the id observed through
the mount; the reverse mapping applies when the process creates files. So `--id
me:0` makes the container's `root` see your files as its own, and files it
writes land on disk owned by you. `DISK`/`SEEN` may be a number or `me` (your
uid in a uid map, gid in a gid map); a `u:`/`g:` prefix restricts a swap to one
column. `--id` is repeatable (disjoint swaps).

### Docker mode (`docker run`)

For each `-v /host/dir:/path` (or `--mount type=bind,...`) of an existing
directory, docker-bluff clones it (`open_tree`), idmaps it
(`mount_setattr(MOUNT_ATTR_IDMAP)`), attaches it at `/run/docker-bluff/<uuid>`
(`move_mount`), and rewrites the bind source to that path. It polls the Docker API
until the container is running (runc has bound the tree into the container's mount
namespace by then), then lazily unmounts the host-side path (`umount2(MNT_DETACH)`
+ `rmdir`) and waits for `docker run` to exit. Everything else in the command is
forwarded unchanged.

### Generic mode (any command)

Any other command runs in a private mount namespace, with each `--map` directory
idmapped **in place** (at the same path). No paths change and nothing is left on
the host - the overmounts vanish when the process tree exits. The command runs as
whoever launched docker-bluff (root under `sudo`, you under the capability install).

## Security & Trust Model

**This is a developer tool for trusted, single-tenant workstations.** It performs
privileged mount operations and is installed executable only by the `docker` group
- whose members are already root-equivalent on the host (`docker run -v /:/host
--privileged ...`), so it grants them no new privilege. It is **not** a security
boundary against a hostile local user, and is not meant for multi-tenant or
production machines.

Within that scope it minimizes privilege:

- **File capabilities, not setuid-root** - installed with `cap_sys_admin`,
  `cap_setuid`, `cap_setgid`, `cap_setfcap`, `cap_sys_ptrace`, it runs as the
  invoking user and never becomes a full uid 0. It **drops its own capabilities**
  once the mounts are set up and it only has to wait.
- **The child is unprivileged** - the exec'd command (the `docker` CLI, or your
  command) inherits no capabilities: `execve` recomputes them and docker-bluff
  never populates the ambient/inheritable sets. In docker mode the CLI is also
  dropped to the invoking user.
- **Least exposure on disk** - `/run/docker-bluff` is `root:docker 0770`, and each
  per-run mount point exists only until the container has started.

Under `sudo` (rather than the capability install) a command in generic mode runs
as real root - docker-bluff warns when it will. Use the capability install to run
it as yourself.

## Prerequisites

- Linux >= 5.12, with the bind-mounted filesystem supporting idmapped mounts
  (ext4, xfs, btrfs, tmpfs, f2fs, zfs >= 2.2, ...).
- Docker mode also needs a local Docker daemon over a `unix://` socket.
- A `uid_map`/`gid_map` is limited to 5 extents before Linux 5.19. Each `--id`
  swap costs up to ~2.5 extents, so more than one or two swaps needs Linux >= 5.19
  (docker-bluff reports this clearly if the map write is rejected).

## Installation

Built and installed from the [docker-heist](../../README.md) workspace:

```bash
make install-docker-bluff
```

That installs the binary `root:docker`, mode `750` (runnable only by the
already-root-equivalent `docker` group), grants the capabilities below, and adds
a `tmpfiles.d` entry keeping `/run/docker-bluff` present (`root:docker 0770`)
across reboots - a capability-only process can't create it in root-owned `/run`.
By hand (also how you'd install a released binary):

```bash
sudo install -o root -g docker -m 750 docker-bluff /usr/local/bin/docker-bluff
sudo setcap cap_sys_admin,cap_setuid,cap_setgid,cap_setfcap,cap_sys_ptrace+ep /usr/local/bin/docker-bluff
printf 'd /run/docker-bluff 0770 root docker -\n' | sudo tee /usr/lib/tmpfiles.d/docker-bluff.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/docker-bluff.conf
```

Why each capability:

- **`cap_sys_admin`** - the mount syscalls (`open_tree`, `mount_setattr`,
  `move_mount`, `unshare(CLONE_NEWNS)`).
- **`cap_setuid`, `cap_setgid`** - write the id maps to `/proc/<pid>/{uid,gid}_map`
  for the mount's user namespace.
- **`cap_setfcap`** - the id map maps uid 0 (e.g. `--id me:0`), and the
  kernel's `verify_root_map` guard (CVE-2018-18955) only permits writing such a
  map with `CAP_SETFCAP` over the parent namespace; without it the write fails
  `EPERM`.
- **`cap_sys_ptrace`** - read `/proc/<container-init>/root` to verify the mount
  reached the container (best-effort; the tool degrades gracefully without it).

See the [workspace README](../../README.md) for building all the tools and the release/download process.

## Usage

```
docker-bluff --id DISK:SEEN ... [--] docker run [DOCKER RUN OPTIONS] IMAGE [CMD...]
docker-bluff --id DISK:SEEN ... --map DIR ... [--] COMMAND [ARGS...]
```

| Option | Meaning |
| --- | --- |
| `--id [u:\|g:]DISK:SEEN` | Swap two ids on the mount (both uid and gid unless `u:`/`g:`). `DISK`/`SEEN` is a number or `me`. Repeatable; at least one required. |
| `--map SRC[:DST]` | Idmap directory `SRC` in place, or at `DST`. Repeatable. Required unless the command is `docker run`. |
| `--verbose` | Explain what is being mounted (and, for docker, released). |
| `-h`, `--help` / `-V`, `--version` | Help / version. |

Append `noremap` to a bind's options to pass it through untouched:
`-v /etc/localtime:/etc/localtime:ro,noremap`.

### Examples

```bash
# Build in a container as root; the files it writes come out owned by you
docker-bluff --id me:0 -- docker run --rm -v "$PWD:/work" maven:3 mvn package

# Same, for any command, in place - via sudo it runs as root, files stay yours
sudo docker-bluff --id me:0 --map "$PWD" -- make

# Edit root-owned files as yourself (capability install, runs as your uid)
docker-bluff --id 0:me --map /srv/app -- "$EDITOR" /srv/app/config
```

## Limitations

- Docker `--restart` policies and `docker start` of a stopped container can't work:
  the host-side path is gone once the container has started.
- Rootless Docker, `dockerd --userns-remap`, and remote daemons (`tcp://`, `ssh://`)
  are not supported.
- Filesystems without idmapped-mount support (older FUSE/NFS, docker's overlay2
  rootfs) fail with `mount_setattr(...): Invalid argument`.
- A `SIGKILL` between mount and container start in docker mode leaves a mount under
  `/run/docker-bluff/`; `umount -l` and `rmdir` it. Generic mode has no such window.
