//! docker-bluff: run `docker run` with bind mounts wrapped in idmapped mounts.
//!
//! Flow:
//! 1. Parse wrapper options and the `docker run` arguments; pick out bind mounts.
//! 2. Build a user namespace whose id maps swap `host <-> container` ids.
//! 3. For each bind: `open_tree(CLONE)` -> `mount_setattr(IDMAP)` ->
//!    `move_mount` onto `/run/docker-bluff/<uuid>`.
//! 4. Spawn `docker run` with the sources rewritten and a tracking label.
//! 5. Poll the Docker socket until the container has started (runc has bound
//!    our mount into the container's mount namespace by then), or the run
//!    failed.
//! 6. Lazily unmount (`MNT_DETACH`) and remove the host-side mount points.
//! 7. Wait for `docker run` to exit and propagate its exit status.

mod cli;
mod docker;
mod mount;
mod userns;

use std::ffi::CString;
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

use cli::{Bind, ExecOptions, Ids, Invocation, LABEL_KEY, Options, RunSpec};
use docker::DockerClient;
use mount::AttachedMount;
use userns::{ID_LIMIT, IdMapping, UserNamespace};

const BASE_DIR: &str = "/run/docker-bluff";
/// Search path used to locate the `docker` binary when running privileged, so
/// a caller-controlled `PATH` cannot make us execute something else as root.
const SECURE_PATH: &[&str] = &[
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    "/usr/local/sbin",
    "/usr/sbin",
    "/sbin",
];
/// Signals the parent ignores so it stays alive to clean up and forward. The
/// terminal delivers these to the whole process group, so the child still gets
/// them directly. SIGTERM is *not* here - the parent catches it (via the
/// `signals` crate) and forwards it to the child.
const PARENT_IGNORED_SIGNALS: &[libc::c_int] = &[libc::SIGINT, libc::SIGHUP, libc::SIGQUIT];
/// Signals the child resets to default before exec, so the target has normal
/// dispositions regardless of what the parent installed.
const CHILD_RESET_SIGNALS: &[libc::c_int] = &[libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

fn main() {
    let code = match cli::parse_invocation(std::env::args().skip(1)) {
        Ok(Invocation::Help) => {
            println!("{}", cli::usage());
            0
        }
        Ok(Invocation::Version) => {
            println!("docker-bluff {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Ok(Invocation::Run(opts)) => match run(opts) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("docker-bluff: {e}");
                125
            }
        },
        Ok(Invocation::Exec(opts)) => match exec_generic(opts) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("docker-bluff: {e}");
                125
            }
        },
        Err(e) => {
            eprintln!("docker-bluff: {e}");
            eprintln!("Try `docker-bluff --help`.");
            2
        }
    };
    std::process::exit(code);
}

struct Log {
    verbose: bool,
}

impl Log {
    fn note(&self, msg: impl AsRef<str>) {
        if self.verbose {
            eprintln!("docker-bluff: {}", msg.as_ref());
        }
    }

    fn warn(&self, msg: impl AsRef<str>) {
        eprintln!("docker-bluff: warning: {}", msg.as_ref());
    }
}

/// A bind mount we decided to remap, with the host-side path Docker will see.
struct Plan<'a> {
    bind_index: usize,
    bind: &'a Bind,
    mount_point: PathBuf,
}

fn run(opts: Options) -> Result<i32, String> {
    let log = Log { verbose: opts.verbose };
    let spec = RunSpec::parse(opts.run_args.clone())?;

    let invoker = detect_invoking_user();
    let mapping = build_mapping(&opts.uid_swaps, &opts.gid_swaps, invoker)?;
    create_missing_sources(&spec.binds, invoker, &log)?;

    let mut plans: Vec<Plan> = Vec::new();
    for (bind_index, bind) in spec.remappable_binds() {
        let meta =
            std::fs::metadata(&bind.source).map_err(|e| format!("bind mount source {}: {e}", bind.source.display()))?;
        if !meta.is_dir() {
            log.note(format!(
                "{} is not a directory, forwarding it to docker unchanged",
                bind.source.display()
            ));
            continue;
        }
        plans.push(Plan {
            bind_index,
            bind,
            mount_point: Path::new(BASE_DIR).join(uuid_v4()?),
        });
    }
    if mapping.is_identity() && !plans.is_empty() {
        log.note("the id map is empty (all swaps are no-ops): nothing to remap");
        plans.clear();
    }

    let session = uuid_v4()?;
    let replacements: Vec<(usize, PathBuf)> = plans.iter().map(|p| (p.bind_index, p.mount_point.clone())).collect();
    // Reassemble the full docker argument vector: [globals...] run [--label ...] [run args...].
    let mut docker_args = opts.global_flags.clone();
    docker_args.push("run".to_string());
    docker_args.extend(spec.render(&session, &replacements));

    let mut identity = ChildIdentity::resolve(invoker)?;
    let docker_bin = locate_program(&opts.argv0)?;

    if plans.is_empty() {
        log.note("no bind mounts to remap, executing docker directly");
        let err = build_docker_command(&docker_bin, &docker_args, &identity).exec();
        return Err(format!("failed to execute {}: {err}", docker_bin.display()));
    }

    require_mount_privilege()?;
    let client = DockerClient::from_env()?;
    client.ping()?;
    identity.check_socket_access(client.socket_path(), &log)?;

    log.note("id mapping:");
    for line in mapping.uid_map().lines() {
        log.note(format!("  uid_map: {line}"));
    }
    for line in mapping.gid_map().lines() {
        log.note(format!("  gid_map: {line}"));
    }

    // Ignore terminal signals the container handles itself, but catch SIGTERM so
    // a `kill` of the wrapper is forwarded on to `docker run`.
    signals::install(PARENT_IGNORED_SIGNALS);

    let docker_gid = std::fs::metadata(client.socket_path()).map(|m| m.gid()).unwrap_or(0);
    secure_base_dir(Path::new(BASE_DIR), docker_gid)?;
    let userns = UserNamespace::create(&mapping).map_err(|e| format!("creating user namespace: {e}"))?;
    let mut mounts: Vec<(AttachedMount, String)> = Vec::with_capacity(plans.len());
    for plan in &plans {
        let tree = mount::idmapped_tree(&plan.bind.source, userns.as_fd()).map_err(|e| e.to_string())?;
        if !tree.is_recursive() {
            log.note(format!(
                "{}: submounts could not be idmapped, mounting the top-level directory only",
                plan.bind.source.display()
            ));
        }
        mount::ensure_dir(&plan.mount_point, 0o700)
            .map_err(|e| format!("mkdir {}: {e}", plan.mount_point.display()))?;
        let attached = tree.attach(&plan.mount_point).map_err(|e| {
            let _ = std::fs::remove_dir(&plan.mount_point);
            e.to_string()
        })?;
        log.note(format!(
            "mounted {} idmapped at {} (container path {})",
            plan.bind.source.display(),
            plan.mount_point.display(),
            plan.bind.target
        ));
        mounts.push((attached, plan.bind.target.clone()));
    }
    drop(userns); // the mounts hold their own reference to the namespace

    log.note(format!(
        "executing: {} {}",
        docker_bin.display(),
        shell_join(&docker_args)
    ));
    let mut child = build_docker_command(&docker_bin, &docker_args, &identity)
        .spawn()
        .map_err(|e| format!("failed to spawn {}: {e}", docker_bin.display()))?;

    match wait_until_started(&client, &session, &mut child, &log) {
        Ok(Outcome::Started(id)) => {
            log.note(format!(
                "container {} is running, releasing host-side mounts",
                short(&id)
            ));
            verify_container_sees_mounts(&client, &id, &mounts, &log);
        }
        Ok(Outcome::Finished(id)) => log.note(format!(
            "container {} finished before start-up sync completed, releasing host-side mounts",
            id.as_deref().map(short).unwrap_or("?")
        )),
        Ok(Outcome::DockerExited) => log.note("docker exited without starting a container, releasing host-side mounts"),
        Ok(Outcome::Terminated) => {
            log.note("received SIGTERM during start-up; releasing host-side mounts and forwarding it")
        }
        Err(e) => log.warn(format!(
            "start-up synchronisation failed ({e}); releasing host-side mounts now"
        )),
    }
    release(&mut mounts, &log);
    // The mounts are released and the docker child was spawned long ago; we only
    // wait on it from here, so we no longer need any capabilities.
    drop_own_capabilities(&log);

    let status = wait_for(&mut child, "docker")?;
    Ok(exit_code(status))
}

enum Outcome {
    /// The container reached a started state; `String` is its id.
    Started(String),
    /// The container exited/was removed before we saw it running.
    Finished(Option<String>),
    /// `docker run` exited and no container carrying our label exists.
    DockerExited,
    /// A SIGTERM arrived during start-up; forward it to docker after cleanup.
    Terminated,
}

/// Poll the Docker API for the container carrying our session label until it
/// has started (its mount namespace now holds a bind of our idmapped tree),
/// or until it is clear that it never will.
fn wait_until_started(client: &DockerClient, session: &str, child: &mut Child, log: &Log) -> Result<Outcome, String> {
    let mut delay = Duration::from_millis(20);
    let mut consecutive_errors = 0u32;
    let mut last_state: Option<String> = None;
    loop {
        if signals::terminate_pending() {
            return Ok(Outcome::Terminated);
        }
        let docker_exited = child
            .try_wait()
            .map_err(|e| format!("polling docker process: {e}"))?
            .is_some();
        match client.find_by_label(LABEL_KEY, session) {
            Ok(Some(c)) => {
                consecutive_errors = 0;
                if last_state.as_deref() != Some(c.state.as_str()) {
                    log.note(format!("container {} is {}", short(&c.id), c.state.as_str()));
                    last_state = Some(c.state.as_str().to_string());
                }
                if c.state.has_started() {
                    return Ok(Outcome::Started(c.id));
                }
                if c.state.is_terminal() || docker_exited {
                    return Ok(Outcome::Finished(Some(c.id)));
                }
            }
            Ok(None) => {
                consecutive_errors = 0;
                if docker_exited {
                    return Ok(Outcome::DockerExited);
                }
            }
            Err(e) => {
                consecutive_errors += 1;
                if consecutive_errors >= 10 {
                    return Err(e);
                }
            }
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(250));
    }
}

/// Best-effort sanity check: through `/proc/<init pid>/root`, the container's
/// mount target must resolve to the same inode as the host source. If it does
/// not, the daemon most likely lives in a private mount namespace and bound an
/// empty directory instead of our idmapped tree.
fn verify_container_sees_mounts(client: &DockerClient, id: &str, mounts: &[(AttachedMount, String)], log: &Log) {
    let pid = match client.inspect_pid(id) {
        Ok(pid) if pid > 0 => pid,
        Ok(_) => return,
        Err(e) => {
            log.note(format!("skipping mount verification: {e}"));
            return;
        }
    };
    for (mount, target) in mounts {
        let in_container = PathBuf::from(format!("/proc/{pid}/root{target}"));
        let (Ok(seen), Ok(expected)) = (std::fs::metadata(&in_container), std::fs::metadata(mount.source())) else {
            // Typically EACCES without CAP_SYS_PTRACE, or the container already died.
            log.note(format!("cannot verify {} inside the container", target));
            continue;
        };
        if (seen.dev(), seen.ino()) != (expected.dev(), expected.ino()) {
            log.warn(format!(
                "{} inside the container does not resolve to {} on the host; is the Docker daemon \
                 running in a private mount namespace (systemd MountFlags/PrivateMounts)?",
                target,
                mount.source().display()
            ));
        } else {
            log.note(format!(
                "verified {} inside the container is {}",
                target,
                mount.source().display()
            ));
        }
    }
}

fn release(mounts: &mut [(AttachedMount, String)], log: &Log) {
    for (mount, _) in mounts.iter_mut() {
        match mount.lazy_unmount() {
            Ok(()) => log.note(format!("released {}", mount.path().display())),
            Err(e) => log.warn(e.to_string()),
        }
    }
}

/// Generic mode: idmap each `--map` directory in place inside a private mount
/// namespace, then exec an arbitrary command. Because the command runs in *our*
/// mount namespace (not a daemon's), the remapped directories are visible at
/// their original paths and no rewriting is needed; the mounts disappear when
/// the process tree exits, so there is nothing to poll for and nothing to clean
/// up. The command runs with the identity that launched docker-bluff (root
/// under sudo, the invoking user under a capability install) - we only apply the
/// mount idmap, we do not change the command's user.
fn exec_generic(opts: ExecOptions) -> Result<i32, String> {
    let log = Log { verbose: opts.verbose };
    let invoker = detect_invoking_user();
    let mapping = build_mapping(&opts.uid_swaps, &opts.gid_swaps, invoker)?;
    if mapping.is_identity() {
        return Err("the id map is empty (all swaps are no-ops): nothing to remap".to_string());
    }

    // Resolve and validate every mapped directory up front.
    let mut targets: Vec<(std::path::PathBuf, std::path::PathBuf)> = Vec::with_capacity(opts.maps.len());
    for map in &opts.maps {
        let meta = std::fs::metadata(&map.source).map_err(|e| format!("--map source {}: {e}", map.source.display()))?;
        if !meta.is_dir() {
            return Err(format!("--map source {} is not a directory", map.source.display()));
        }
        if map.target != map.source && !map.target.is_dir() {
            return Err(format!(
                "--map target {} does not exist as a directory",
                map.target.display()
            ));
        }
        targets.push((map.source.clone(), map.target.clone()));
    }

    let command = locate_program(&opts.command[0])?;

    require_mount_privilege()?;
    if geteuid() == 0 {
        log.warn(format!(
            "'{}' will run as root (uid 0) on the host; use the capability install (not sudo) to run it as yourself",
            opts.command[0]
        ));
    }

    log.note("id mapping:");
    for line in mapping.uid_map().lines() {
        log.note(format!("  uid_map: {line}"));
    }
    for line in mapping.gid_map().lines() {
        log.note(format!("  gid_map: {line}"));
    }

    let userns = UserNamespace::create(&mapping).map_err(|e| format!("creating user namespace: {e}"))?;

    // Enter a private mount namespace so the in-place overmounts are invisible
    // to the rest of the host and are torn down automatically at exit.
    mount::unshare_mount_namespace().map_err(|e| format!("unshare(CLONE_NEWNS): {e}"))?;
    mount::make_rprivate(Path::new("/")).map_err(|e| format!("making / private: {e}"))?;

    for (src, dst) in &targets {
        let tree = mount::idmapped_tree(src, userns.as_fd()).map_err(|e| e.to_string())?;
        if !tree.is_recursive() {
            log.note(format!(
                "{}: submounts could not be idmapped, remapping the top-level directory only",
                src.display()
            ));
        }
        tree.attach_over(dst).map_err(|e| e.to_string())?;
        if src == dst {
            log.note(format!("idmapped {} in place", src.display()));
        } else {
            log.note(format!("idmapped {} at {}", src.display(), dst.display()));
        }
    }
    drop(userns); // the mounts hold their own reference to the namespace

    // The wrapper stays as the parent, waiting; the command runs with our own
    // identity (no privilege drop) - capabilities do not survive the execve, so
    // the command is unprivileged - in the mount namespace we prepared.
    signals::install(PARENT_IGNORED_SIGNALS);
    log.note(format!(
        "executing: {} {}",
        command.display(),
        shell_join(&opts.command[1..])
    ));
    let mut cmd = build_command(&command, &opts.command[1..], None);
    // Re-enter the working directory so `.`-relative access goes through the
    // idmapped overmounts. The inherited cwd is a reference captured before we
    // overmounted, so without this `ls` (which lists `.`) would show the
    // pre-mapping ownership even when the cwd is a mapped directory. Setting the
    // command's cwd makes the child chdir to it inside our mount namespace,
    // re-resolving the path through the new mounts.
    if let Ok(cwd) = std::env::current_dir() {
        cmd.current_dir(cwd);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn {}: {e}", command.display()))?;
    // The mounts are done and the child has forked; we only wait from here.
    drop_own_capabilities(&log);
    let status = wait_for(&mut child, "the command")?;
    Ok(exit_code(status))
}

/// Build the id mapping from the parsed `--id` swaps, resolving `me` to the
/// invoking user's uid (for uid swaps) and gid (for gid swaps).
fn build_mapping(uid_swaps: &[cli::Swap], gid_swaps: &[cli::Swap], invoker: Ids) -> Result<IdMapping, String> {
    let uids = cli::resolved_pairs(uid_swaps, invoker.uid);
    let gids = cli::resolved_pairs(gid_swaps, invoker.gid);
    IdMapping::from_swaps(&uids, &gids, ID_LIMIT)
}

/// Locate the program to execute (the docker binary, or a generic command): an
/// explicit path is used as-is; a bare name is resolved against a fixed secure
/// `PATH` when privileged (so a caller-controlled `PATH` cannot redirect what we
/// run while holding CAP_SYS_ADMIN) or the caller's `PATH` otherwise.
fn locate_program(name: &str) -> Result<PathBuf, String> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return if p.is_file() {
            Ok(p)
        } else {
            Err(format!("{name}: no such file"))
        };
    }
    let dirs: Vec<PathBuf> = if privileged() {
        SECURE_PATH.iter().map(PathBuf::from).collect()
    } else {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default()
    };
    dirs.iter().map(|d| d.join(name)).find(|p| p.is_file()).ok_or_else(|| {
        format!(
            "`{name}` not found in {}",
            dirs.iter()
                .map(|d| d.display().to_string())
                .collect::<Vec<_>>()
                .join(":")
        )
    })
}

/// True when the process can perform the mount syscalls: either it is root, or
/// it holds an effective CAP_SYS_ADMIN (a capability-endowed install). Used both
/// to gate the work and to decide whether to trust `PATH`.
fn privileged() -> bool {
    geteuid() == 0 || privileges::has_effective(privileges::CAP_SYS_ADMIN)
}

fn require_mount_privilege() -> Result<(), String> {
    if privileged() {
        return Ok(());
    }
    Err(
        "creating idmapped mounts needs CAP_SYS_ADMIN: install docker-bluff with file \
         capabilities (see the README) or run it via sudo"
            .into(),
    )
}

/// Drop the capabilities we no longer need. Called *after* the child is spawned
/// (so the child forked with our full sets and its own execve already computed
/// its capabilities) and *after* all privileged work (mounts, and in docker mode
/// the lazy unmount) is done - from here we only wait. We drop the
/// effective/permitted/inheritable and ambient sets, which removes every
/// capability this process can act on; the bounding set is left alone (dropping
/// it would need CAP_SETPCAP, which docker-bluff is not granted, and it is only a
/// ceiling on a process that no longer execs anything). Best-effort: a failure
/// here does not affect the already-running child.
fn drop_own_capabilities(log: &Log) {
    if let Err(e) = privileges::clear_eff_perm_inh().and_then(|()| privileges::clear_ambient()) {
        log.note(format!("could not drop own capabilities: {e}"));
    } else {
        log.note("dropped own capabilities for the wait");
    }
}

/// The invoking human user: the sudo caller when running under sudo, else the
/// real uid/gid (which is the invoking user for a capability install). Used to
/// expand `me` in the id map and as the user the docker CLI runs as.
fn detect_invoking_user() -> Ids {
    let (ruid, rgid) = (getuid(), getgid());
    if ruid == 0 {
        let env_id = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u32>().ok());
        if let (Some(uid), Some(gid)) = (env_id("SUDO_UID"), env_id("SUDO_GID")) {
            return Ids { uid, gid };
        }
    }
    Ids { uid: ruid, gid: rgid }
}

/// Create the source directory of every bind flagged `bind-create-src` that
/// does not exist yet, parents included. Docker (29+) implements the option
/// too, but creates the directory owned by root; we make every directory we
/// create owned by the invoking user, so that through the id map the container
/// user sees it as its own and the host user keeps control of it. Existing
/// sources (directories or not) are left alone.
fn create_missing_sources(binds: &[Bind], owner: Ids, log: &Log) -> Result<(), String> {
    for bind in binds.iter().filter(|b| b.create) {
        if bind.source.exists() {
            continue;
        }
        let created = create_dir_all_owned(&bind.source, owner)
            .map_err(|e| format!("creating bind mount source {}: {e}", bind.source.display()))?;
        log.note(format!(
            "created bind mount source {} ({} director{}, owner {owner})",
            bind.source.display(),
            created,
            if created == 1 { "y" } else { "ies" }
        ));
    }
    Ok(())
}

/// `mkdir -p` that hands ownership of the directories it creates (and only
/// those) to `owner`. Returns how many directories were created.
fn create_dir_all_owned(path: &Path, owner: Ids) -> std::io::Result<usize> {
    let missing: Vec<&Path> = path.ancestors().take_while(|p| !p.exists()).collect();
    std::fs::create_dir_all(path)?;
    for dir in &missing {
        std::os::unix::fs::chown(dir, Some(owner.uid), Some(owner.gid))?;
    }
    Ok(missing.len())
}

/// Who the `docker` child runs as. We hold root only for the mount syscalls;
/// the Docker CLI itself runs as the invoking user whenever that user can
/// reach the daemon socket, so their credentials, contexts and config apply.
struct ChildIdentity {
    /// `Some` when privileges are dropped before exec.
    drop_to: Option<DropTarget>,
    /// True when we are setuid-root (real uid != 0): the environment is
    /// caller-controlled, so running the CLI as root is never acceptable.
    setuid_mode: bool,
}

struct DropTarget {
    ids: Ids,
    groups: Vec<libc::gid_t>,
    /// (`$HOME`, user name) to install when the caller's environment does not
    /// already belong to the target user (i.e. under sudo).
    home: Option<(String, String)>,
}

impl DropTarget {
    /// Resolve the supplementary groups and home for running as `ids`. When the
    /// real uid already is `ids.uid` the caller's own groups/environment are
    /// kept; otherwise they are looked up from the passwd/group databases.
    fn resolve(ids: Ids) -> Self {
        let (groups, home) = if getuid() == ids.uid {
            (current_groups(), None)
        } else {
            let pw = Passwd::lookup(ids.uid);
            let groups = pw
                .as_ref()
                .map(|pw| pw.group_list(ids.gid))
                .unwrap_or_else(|| vec![ids.gid]);
            (groups, pw.map(|pw| (pw.home, pw.name)))
        };
        let mut groups = groups;
        if !groups.contains(&ids.gid) {
            groups.push(ids.gid);
        }
        Self { ids, groups, home }
    }
}

impl ChildIdentity {
    fn resolve(host: Ids) -> Result<Self, String> {
        let (ruid, euid) = (getuid(), geteuid());
        let setuid_mode = euid == 0 && ruid != 0;
        if euid != 0 || host.uid == 0 {
            return Ok(Self {
                drop_to: None,
                setuid_mode,
            });
        }
        Ok(Self {
            drop_to: Some(DropTarget::resolve(host)),
            setuid_mode,
        })
    }

    /// If the target user cannot open the daemon socket, either keep running
    /// the CLI as root (sudo: the environment was sanitised by sudo) or refuse
    /// (setuid: the environment is the caller's).
    fn check_socket_access(&mut self, socket: &Path, log: &Log) -> Result<(), String> {
        let Some(target) = &self.drop_to else { return Ok(()) };
        if socket_writable_by(socket, target.ids, &target.groups) {
            return Ok(());
        }
        if self.setuid_mode {
            return Err(format!(
                "user {} cannot access {} (not in the docker group?)",
                target.ids.uid,
                socket.display()
            ));
        }
        log.note(format!(
            "user {} cannot access {}, running the docker CLI as root",
            target.ids.uid,
            socket.display()
        ));
        self.drop_to = None;
        Ok(())
    }
}

fn socket_writable_by(socket: &Path, ids: Ids, groups: &[libc::gid_t]) -> bool {
    let Ok(meta) = std::fs::metadata(socket) else {
        return false;
    };
    let mode = meta.mode();
    if meta.uid() == ids.uid {
        mode & 0o200 != 0
    } else if groups.contains(&meta.gid()) {
        mode & 0o020 != 0
    } else {
        mode & 0o002 != 0
    }
}

fn build_docker_command(docker_bin: &Path, args: &[String], identity: &ChildIdentity) -> Command {
    build_command(docker_bin, args, identity.drop_to.as_ref())
}

/// Build a `Command` for `program` that, before exec, resets the signal
/// dispositions we ignore in the parent and (if `drop_to` is set) drops
/// group/user credentials. `$HOME`/`$USER`/`$LOGNAME` are updated when the
/// target user differs from the invoking one.
fn build_command(program: &Path, args: &[String], drop_to: Option<&DropTarget>) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args);
    let drop = drop_to.map(|t| (t.ids, t.groups.clone()));
    if let Some(DropTarget {
        home: Some((home, name)),
        ..
    }) = drop_to
    {
        cmd.env("HOME", home).env("USER", name).env("LOGNAME", name);
    }
    // SAFETY: the closure only calls async-signal-safe functions (signal,
    // setgroups, setresgid, setresuid) and touches pre-allocated memory.
    unsafe {
        cmd.pre_exec(move || {
            signals::reset_to_default(CHILD_RESET_SIGNALS);
            let Some((ids, groups)) = &drop else { return Ok(()) };
            if libc::setgroups(groups.len(), groups.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setresgid(ids.gid, ids.gid, ids.gid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setresuid(ids.uid, ids.uid, ids.uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd
}

/// Ensure the mount-point parent exists and is not accessible to other users.
///
/// When we are root (sudo) we create it `0700`. Under a capability-only install
/// the process runs as the invoking user and cannot write to root-owned `/run`,
/// so the directory is expected to already exist - created root:docker `0770` by
/// the tmpfiles.d snippet the installer ships (see the README). We accept a
/// directory owned by root or by us, but reject one any other user can enter,
/// since through an idmapped mount root-owned files appear owned by the host user.
fn secure_base_dir(dir: &Path, docker_gid: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if !dir.exists() {
        // Only reachable as root (a capability-only run can't write root-owned
        // /run). Create it root:docker 0770 - the shared layout both sudo and
        // capability runs need, matching the tmpfiles.d snippet the installer
        // ships - so a sudo run doesn't leave a root:root 0700 dir that later
        // capability runs can't write into.
        mount::ensure_dir(dir, 0o770).map_err(|e| {
            format!(
                "{} does not exist and could not be created ({e}); create it once as \
                 root, or install the tmpfiles.d snippet (see the README)",
                dir.display()
            )
        })?;
        let _ = std::os::unix::fs::chown(dir, None, Some(docker_gid));
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o770));
    }
    let meta = std::fs::symlink_metadata(dir).map_err(|e| format!("stat {}: {e}", dir.display()))?;
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    if meta.uid() != 0 && meta.uid() != geteuid() {
        return Err(format!(
            "{} must be owned by root or by the invoking user (is uid {})",
            dir.display(),
            meta.uid()
        ));
    }
    if meta.mode() & 0o007 != 0 {
        // Other users can enter it. Try to tighten (works when we own it or are
        // root, e.g. sudo, or a path Docker auto-created 0755); if it stays
        // loose we can't fix it (capability-only, not the owner) - refuse.
        let tightened = meta.mode() & 0o7770;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(tightened));
        let mode = std::fs::symlink_metadata(dir).map(|m| m.mode()).unwrap_or(meta.mode());
        if mode & 0o007 != 0 {
            return Err(format!(
                "{} is accessible to other users (mode {:o}) and could not be tightened; \
                 fix it to at most 0770 (see the README's tmpfiles.d snippet)",
                dir.display(),
                mode & 0o7777
            ));
        }
    }
    // Make sure we can actually create the per-run mount point here, rather than
    // failing later with a confusing EACCES from mkdir - e.g. a dir left
    // root:root 0700 by an older sudo run is unwritable by a capability run.
    let meta = std::fs::symlink_metadata(dir).map_err(|e| format!("stat {}: {e}", dir.display()))?;
    if !dir_writable_by_us(&meta) {
        return Err(format!(
            "{} (uid {}, mode {:o}) is not writable by the invoking user; make it \
             root:docker 0770 (see the README's tmpfiles.d snippet)",
            dir.display(),
            meta.uid(),
            meta.mode() & 0o7777
        ));
    }
    Ok(())
}

/// Whether the current process can create entries in a directory with metadata
/// `meta`, by the usual owner/group/other rules (root always can).
fn dir_writable_by_us(meta: &std::fs::Metadata) -> bool {
    if geteuid() == 0 {
        return true;
    }
    let mode = meta.mode();
    if meta.uid() == geteuid() {
        mode & 0o200 != 0
    } else if getgid() == meta.gid() || current_groups().contains(&meta.gid()) {
        mode & 0o020 != 0
    } else {
        mode & 0o002 != 0
    }
}

/// Wait for `child`, forwarding a SIGTERM aimed at the wrapper on to it. This is
/// a poll loop (std's `Child` gives us no interruptible wait), which is fine for
/// a wrapper: the child is what does the work.
fn wait_for(child: &mut Child, what: &str) -> Result<ExitStatus, String> {
    loop {
        if let Some(status) = child.try_wait().map_err(|e| format!("waiting for {what}: {e}"))? {
            return Ok(status);
        }
        if signals::terminate_requested() {
            return terminate_child(child, what);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Forward SIGTERM to the child, give it up to 10s to exit, then SIGKILL.
fn terminate_child(child: &mut Child, what: &str) -> Result<ExitStatus, String> {
    let pid = child.id() as libc::pid_t;
    // SAFETY: signalling our own child.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().map_err(|e| format!("waiting for {what}: {e}"))? {
            return Ok(status);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // SAFETY: signalling our own child.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    child.wait().map_err(|e| format!("waiting for {what}: {e}"))
}

fn exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.code().or_else(|| status.signal().map(|s| 128 + s)).unwrap_or(1)
}

fn uuid_v4() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| format!("reading /dev/urandom: {e}"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}

fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|a| {
            if a.is_empty() || a.contains(|c: char| c.is_whitespace() || "'\"$`\\!*?[](){}<>|&;".contains(c)) {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn getuid() -> u32 {
    // SAFETY: always safe.
    unsafe { libc::getuid() }
}

fn getgid() -> u32 {
    // SAFETY: always safe.
    unsafe { libc::getgid() }
}

fn geteuid() -> u32 {
    // SAFETY: always safe.
    unsafe { libc::geteuid() }
}

fn current_groups() -> Vec<libc::gid_t> {
    // SAFETY: first call sizes the buffer, second fills it.
    unsafe {
        let n = libc::getgroups(0, std::ptr::null_mut());
        if n <= 0 {
            return Vec::new();
        }
        let mut groups = vec![0 as libc::gid_t; n as usize];
        let n = libc::getgroups(n, groups.as_mut_ptr());
        if n < 0 {
            return Vec::new();
        }
        groups.truncate(n as usize);
        groups
    }
}

struct Passwd {
    name: String,
    home: String,
}

impl Passwd {
    fn lookup(uid: u32) -> Option<Self> {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 16 * 1024];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: getpwuid_r writes into the buffers we provide.
        let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr().cast(), buf.len(), &mut result) };
        if rc != 0 || result.is_null() {
            return None;
        }
        // SAFETY: on success the pointers reference NUL-terminated strings inside `buf`.
        let cstr = |p: *const libc::c_char| unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned();
        Some(Self {
            name: cstr(pwd.pw_name),
            home: cstr(pwd.pw_dir),
        })
    }

    fn group_list(&self, primary: u32) -> Vec<libc::gid_t> {
        let Ok(name) = CString::new(self.name.as_bytes()) else {
            return vec![primary];
        };
        let mut n: libc::c_int = 64;
        loop {
            let mut groups = vec![0 as libc::gid_t; n as usize];
            // SAFETY: getgrouplist fills at most `n` entries and updates `n`.
            let rc = unsafe { libc::getgrouplist(name.as_ptr(), primary, groups.as_mut_ptr(), &mut n) };
            if rc >= 0 {
                groups.truncate(n.max(0) as usize);
                return groups;
            }
            if n <= groups.len() as libc::c_int {
                // musl reports -1 without growing `n` when the buffer is too small.
                n = (groups.len() * 2) as libc::c_int;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_format() {
        let u = uuid_v4().unwrap();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
        assert!(matches!(&u[19..20], "8" | "9" | "a" | "b"));
        assert_ne!(u, uuid_v4().unwrap());
    }

    #[test]
    fn shell_join_quotes_when_needed() {
        assert_eq!(
            shell_join(&["a".into(), "b c".into(), "it's".into()]),
            "a 'b c' 'it'\\''s'"
        );
    }

    #[test]
    fn exit_codes() {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(exit_code(ExitStatus::from_raw(3 << 8)), 3);
        assert_eq!(exit_code(ExitStatus::from_raw(libc::SIGINT)), 130);
    }

    #[test]
    fn create_dir_all_owned_creates_only_the_missing_part() {
        let base = std::env::temp_dir().join(format!("docker-bluff-test-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let me = Ids {
            uid: getuid(),
            gid: getgid(),
        };
        let target = base.join("a/b/c");
        assert_eq!(create_dir_all_owned(&target, me).unwrap(), 3);
        assert!(target.is_dir());
        // Already there: nothing to create, no error.
        assert_eq!(create_dir_all_owned(&target, me).unwrap(), 0);
        // A file in the way is an error, not silently accepted.
        let file = base.join("file");
        std::fs::write(&file, b"").unwrap();
        assert!(create_dir_all_owned(&file.join("x"), me).is_err());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn socket_permission_check() {
        let dir = std::env::temp_dir().join(format!("docker-bluff-sock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("s");
        std::fs::write(&sock, b"").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o660)).unwrap();
        let me = std::fs::metadata(&sock).unwrap();
        let owner = Ids {
            uid: me.uid(),
            gid: me.gid(),
        };
        assert!(socket_writable_by(&sock, owner, &[]));
        let other = Ids {
            uid: me.uid() + 1,
            gid: me.gid() + 1,
        };
        assert!(!socket_writable_by(&sock, other, &[other.gid]));
        assert!(socket_writable_by(&sock, other, &[me.gid()]));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
