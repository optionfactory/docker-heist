# docker-snitch

Runs a command and, while it runs, relays whatever gets appended to a set of
files to stderr, removing from the files what it has relayed. One of the
[docker-heist](../../README.md) tools.

```bash
docker-snitch /var/run/mysqld/slow.log /var/run/mysqld/general.log -- \
    mariadbd --defaults-file=/etc/my.cnf
```

## What It Does

`docker-snitch <file>... -- <command>` runs the command and, while it runs:

- **Provisions** each file: creates it if absent (its directory must exist), as
  the user it runs as, so the daemon can open it right away, and starts following
  from the file's current end, like `tail -n 0 -F`.
- **Relays**: every `--interval` (default 250 ms) it copies newly appended bytes
  of each file to stderr (`--stdout` to use stdout). It follows the file by
  *name*: truncation by someone else restarts from 0, a rename-and-recreate
  rotation drains the old inode then switches, a removed file is recreated so
  the daemon's next `FLUSH LOGS` has somewhere to write.
- **Compacts**: after each relay it drops the relayed prefix from the file, in
  place and losslessly, with whichever `fallocate` mode the filesystem supports
  (probed when the file is provisioned): `FALLOC_FL_COLLAPSE_RANGE` on ext4/xfs
  cuts the prefix out and shifts the rest down, so the file never holds more than
  the last block plus one interval's worth of new data; `FALLOC_FL_PUNCH_HOLE`
  on tmpfs/btrfs/zfs deallocates the prefix instead, so the file stays small on
  disk but sparse, its apparent size growing (announced once per directory at
  startup).
  A filesystem supporting neither is refused before the command starts. The
  daemons this is for append with `O_APPEND`, so a write racing with either
  operation still lands at the end and is never touched.

When the command exits, the files are drained one last time, emptied (not
removed: they may not be ours), and docker-snitch exits with the command's
status (`128 + signal` if it was killed). Because the command runs as its child,
docker-snitch also does what a parent should: forwards `SIGTERM`, `SIGINT`,
`SIGQUIT`, `SIGHUP`, `SIGUSR1`, `SIGUSR2` to it and reaps orphaned descendants
(it sets `PR_SET_CHILD_SUBREAPER`, so this holds whether or not it is PID 1).

A single thread, polling with `stat` and `read`: no inotify, no threads, no
dependencies beyond `libc`. An idle set of files costs one `stat` per file per
interval.

### What can be lost

Nothing. Both mechanisms only act on bytes already relayed and never move or
discard what follows them, however busy the writer is; the block rounding leaves
at most one partial block of relayed data in place until the next round. The
daemon's own writes are never blocked or failed by docker-snitch, and a closed
stdio pipe makes it drop output, not the daemon.

## Where It Is Used

Containers log to stdout/stderr; `docker logs` and every log collector
build on that. Some daemons don't cooperate for part of their output: MySQL's
slow-query and general logs accept only a **regular file** as target
(`/dev/stderr`, a TTY or a FIFO are rejected with *"Could not use ... for
logging"*), MariaDB's fail with `EACCES` on Docker's root-owned stdio pipes and
`ESPIPE` on a TTY. Writing them to a file then means two chores nobody wants in
an entrypoint: a `tail -F` to relay the file, and something to stop it from
filling the disk, because these daemons never rotate their own logs.

So docker-snitch is baked into such images and the entrypoint `exec`s the daemon
through it, after dropping privileges:

```bash
exec setpriv --reuid=mysql --regid=docker-machines --init-groups -- \
    docker-snitch /var/run/mysqld/slow.log /var/run/mysqld/general.log -- \
    mariadbd --defaults-file=/etc/my.cnf
```

docker-snitch becomes PID 1 with the daemon as its only child. `docker stop`
sends `SIGTERM` to it, it forwards the signal, the daemon shuts down cleanly, its
last log lines are relayed, and the container exits with the daemon's status.
Nothing else in the image changes.

### Filesystem requirements

In a container the log directory (`/var/run/mysqld` above) normally lives in the
container's writable layer, which is **overlayfs**. overlayfs does not implement
`fallocate` itself: it forwards the call to the file on its upper layer (stacked
file operations since Linux 4.19; earlier kernels handed out the underlying file
directly, with the same effect), so what decides between collapse, punch and
refusal is the filesystem backing Docker's data root (`docker info --format
'{{.DockerRootDir}}'`, then `df -T` on it): ext4 and xfs collapse, btrfs and zfs
punch, and so does NFSv4.2 (Linux clients since 4.16 map punch-hole to
`DEALLOCATE`). A `--tmpfs` or `emptyDir` mount on the log directory punches.
Anything without both modes, e.g. a data root on vfat or on NFS v3/4.0/4.1 (or a
v4.2 server without `DEALLOCATE`), or a log directory explicitly bind-mounted
through 9p/virtiofs, makes docker-snitch refuse to start with
`Cannot compact logs in '<dir>': filesystem supports neither collapse-range nor
punch-hole`, before the daemon runs; point the log files at a supported location
to fix it. This is stricter than a `tail -F` + `truncate` entrypoint, which runs
anywhere at the price of a lossy truncation; the refusal is deliberate and loud.

### Security & Trust Model

Used this way, docker-snitch runs as the service user, after the entrypoint has
dropped privileges. It has no capabilities, no setuid bit, and performs no
privileged operation: it opens files, forks once, waits and signals its child. It
never contacts the Docker daemon. Its reach is exactly that of the daemon it
wraps: it can read and compact the files it was given.

### Installation

Image builds download the static binary from the [latest
release](https://github.com/optionfactory/docker-heist/releases/latest) and
install it plain:

```bash
install -o root -g root -m 755 docker-snitch-linux-amd64-musl /usr/local/bin/docker-snitch
```

For local testing on a workstation, `make install-docker-snitch` from the
workspace does the same.

## Usage

```
docker-snitch [options] <file>... -- <command> [args...]
```

| Option | Meaning |
| --- | --- |
| `<file>...` | Absolute paths of the log files to provision and relay. |
| `--interval <MS>` | Poll interval in milliseconds. Default `250`. |
| `--stdout` | Relay to stdout instead of stderr. |
| `--` | Separates wrapper options and files from the command. Required. |

Exit status: the command's; `128 + signal` if it died from a signal; `1` for
docker-snitch's own errors (bad arguments, a file that cannot be provisioned, a
filesystem that supports neither collapse-range nor punch-hole, exec failure).

### Example: MariaDB with slow and general logs on stderr

`/etc/my.cnf`:

```ini
[mysqld]
log_output=FILE
slow_query_log=1
slow_query_log_file=/var/run/mysqld/slow.log
long_query_time=3
general_log=0
general_log_file=/var/run/mysqld/general.log
```

entrypoint:

```bash
exec setpriv --reuid=mysql --regid=docker-machines --init-groups -- \
    docker-snitch /var/run/mysqld/slow.log /var/run/mysqld/general.log -- \
    mariadbd --defaults-file=/etc/my.cnf
```

`SET GLOBAL general_log=1` at runtime streams every statement to `docker logs`
while the file underneath stays a few kilobytes (on ext4/xfs; a few kilobytes on
disk and a growing apparent size on btrfs/zfs/tmpfs).
