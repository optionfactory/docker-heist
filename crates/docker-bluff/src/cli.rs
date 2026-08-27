//! Command-line handling.
//!
//! `docker-bluff` is a prefix wrapper, like `sudo` or `strace`:
//!
//! ```text
//! docker-bluff --id DISK:SEEN ... [options] [--] docker run [OPTIONS] IMAGE [CMD...]
//! docker-bluff --id DISK:SEEN ... --map DIR ... [--] COMMAND [ARGS...]
//! ```
//!
//! Everything after our options (or after `--`) is the command, verbatim. When
//! the program is `docker` and a `run` subcommand is present, it is handled in
//! *docker mode*: bind-mount sources (`-v`/`--mount`) are rewritten to point at
//! idmapped mount points, the rest forwarded unchanged. To find the bind
//! sources reliably we must know where the image name starts (a `-v` after the
//! image belongs to the container command), so this module carries the table of
//! `docker run` flags that take no value; every other flag is assumed to consume
//! the next argument unless written as `--flag=value`.
//!
//! Any other command runs in *generic mode*: the directories named by `--map`
//! are idmapped in place (at the same path, inside a private mount namespace),
//! so no path rewriting is needed.

use std::path::PathBuf;

pub const LABEL_KEY: &str = "docker-bluff.id";
/// Per-mount option (in `-v src:dst:opts` or `--mount ...,noremap`) that
/// excludes a bind mount from remapping. Stripped before reaching Docker.
pub const NOREMAP_OPTION: &str = "noremap";

/// `docker run` long flags that never take a value (from `docker run --help`,
/// Docker 29). Unknown flags are assumed to take a value.
const BOOL_LONG: &[&str] = &[
    "detach",
    "disable-content-trust",
    "help",
    "init",
    "interactive",
    "no-healthcheck",
    "oom-kill-disable",
    "privileged",
    "publish-all",
    "quiet",
    "read-only",
    "rm",
    "sig-proxy",
    "tty",
    "use-api-socket",
];
/// `docker run` short flags that take a value. Any other short flag (a boolean
/// like `-i`/`-t`, or one Docker will reject) is treated as valueless.
const VALUE_SHORT: &[char] = &['a', 'c', 'e', 'h', 'l', 'm', 'p', 'u', 'v', 'w'];

/// The long-flag name a value-taking short flag maps to for remapping. Only `-v`
/// (volume) is remapped; other value-taking short flags just have their value
/// consumed (an empty name records nothing).
fn short_flag_name(c: char) -> &'static str {
    if c == 'v' { "volume" } else { "" }
}

/// A resolved user identity (uid + gid), used when dropping privileges for the
/// child. Distinct from the id *mappings* (`--id`), which are per-column swaps.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Ids {
    pub uid: u32,
    pub gid: u32,
}

fn parse_id(s: &str) -> Option<u32> {
    s.parse::<u32>().ok().filter(|&id| id != u32::MAX)
}

impl std::fmt::Display for Ids {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.uid, self.gid)
    }
}

/// One side of a swap: a literal id, or `me` (resolved to the invoking
/// user's uid in a uid map, or gid in a gid map).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndId {
    Invoker,
    Num(u32),
}

impl EndId {
    fn parse(flag: &str, spec: &str, tok: &str) -> Result<Self, String> {
        if tok == "me" {
            Ok(EndId::Invoker)
        } else {
            parse_id(tok)
                .map(EndId::Num)
                .ok_or_else(|| format!("{flag}: invalid id {tok:?} in {spec:?} (a number or `me`)"))
        }
    }

    /// Concrete id, given the invoking user's id for this column.
    pub fn resolve(self, current: u32) -> u32 {
        match self {
            EndId::Invoker => current,
            EndId::Num(n) => n,
        }
    }
}

/// A single id swap: the id stored on disk (`disk`) is shown through the mount
/// as `seen`, and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Swap {
    pub disk: EndId,
    pub seen: EndId,
}

/// Options common to every mode. Each `--id` adds one or two swaps (uid and/or
/// gid); every id not named is passed through the mount unchanged.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Common {
    pub verbose: bool,
    pub uid_swaps: Vec<Swap>,
    pub gid_swaps: Vec<Swap>,
}

impl Common {
    /// Try to consume `arg` (and, for the separate-value form, pull the value
    /// from `rest`) as a common option. Returns `Ok(true)` if it was one.
    fn consume(&mut self, arg: &str, rest: &mut impl Iterator<Item = String>) -> Result<bool, String> {
        match arg {
            "--verbose" => self.verbose = true,
            "--id" => {
                let value = rest.next().ok_or("missing value for --id")?;
                self.add_id(&value)?;
            }
            _ => match arg.strip_prefix("--id=") {
                Some(value) => self.add_id(value)?,
                None => return Ok(false),
            },
        }
        Ok(true)
    }

    /// Parse an `--id` value: `[u:|g:]DISK:SEEN`. Without a `u:`/`g:` prefix the
    /// swap applies to both the uid and the gid map.
    fn add_id(&mut self, value: &str) -> Result<(), String> {
        let parts: Vec<&str> = value.split(':').collect();
        let (col, disk_tok, seen_tok) = match parts.as_slice() {
            [d, s] => (None, *d, *s),
            ["u", d, s] => (Some(Column::Uid), *d, *s),
            ["g", d, s] => (Some(Column::Gid), *d, *s),
            _ => {
                return Err(format!(
                    "--id: expected [u:|g:]DISK:SEEN, got {value:?} (e.g. `me:950`, `u:0:33`)"
                ));
            }
        };
        let swap = Swap {
            disk: EndId::parse("--id", value, disk_tok)?,
            seen: EndId::parse("--id", value, seen_tok)?,
        };
        match col {
            Some(Column::Uid) => self.uid_swaps.push(swap),
            Some(Column::Gid) => self.gid_swaps.push(swap),
            None => {
                self.uid_swaps.push(swap);
                self.gid_swaps.push(swap);
            }
        }
        Ok(())
    }
}

enum Column {
    Uid,
    Gid,
}

/// Resolve `[(disk, seen)]` pairs for `IdMapping::from_swaps`, given the
/// invoking user's id for this column (used to expand `me`).
pub fn resolved_pairs(swaps: &[Swap], current: u32) -> Vec<(u32, u32)> {
    swaps
        .iter()
        .map(|s| (s.disk.resolve(current), s.seen.resolve(current)))
        .collect()
}

/// Docker mode: the command is `docker run ...`. We split it into the docker
/// binary as typed (`argv0`), any global flags between it and `run`
/// (e.g. `--context foo`), and the `docker run` arguments proper.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Options {
    pub verbose: bool,
    pub uid_swaps: Vec<Swap>,
    pub gid_swaps: Vec<Swap>,
    /// The `docker` program as the user typed it (e.g. `docker` or `/usr/bin/docker`).
    pub argv0: String,
    /// Global docker flags before the `run` subcommand.
    pub global_flags: Vec<String>,
    /// Arguments after `run`.
    pub run_args: Vec<String>,
}

/// One `--map SRC[:DST]` directory to idmap in place (generic mode). `target`
/// defaults to `source`, i.e. the directory is remapped at its own path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapSpec {
    pub source: PathBuf,
    pub target: PathBuf,
}

impl MapSpec {
    fn parse(spec: &str) -> Result<Self, String> {
        let (source, target) = match spec.split_once(':') {
            Some((s, t)) => (s, t),
            None => (spec, spec),
        };
        if source.is_empty() || target.is_empty() {
            return Err(format!(
                "invalid --map {spec:?}: expected SRC[:DST] with non-empty paths"
            ));
        }
        if !source.starts_with('/') || !target.starts_with('/') {
            return Err(format!("invalid --map {spec:?}: paths must be absolute"));
        }
        Ok(Self {
            source: PathBuf::from(source),
            target: PathBuf::from(target),
        })
    }
}

/// Generic mode: run any command with directories idmapped in place.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExecOptions {
    pub verbose: bool,
    pub uid_swaps: Vec<Swap>,
    pub gid_swaps: Vec<Swap>,
    pub maps: Vec<MapSpec>,
    /// The command and its arguments.
    pub command: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Invocation {
    Help,
    Version,
    Run(Options),
    Exec(ExecOptions),
}

/// Parse `argv[1..]`.
///
/// `docker-bluff` is a prefix wrapper, like `sudo` or `strace`: our own options
/// come first, then the command line to run - either after `--`, or starting at
/// the first token that is not one of our options. Everything from there on is
/// passed to the child verbatim; nothing is rewritten except bind-mount sources
/// in a `docker run` command.
///
/// The command is treated as a `docker run` invocation (with the container
/// start-up sync and lazy unmount) when its program is `docker` and it contains
/// a `run` subcommand. Otherwise it is run as a plain command with each `--map`
/// directory idmapped in place.
pub fn parse_invocation<I: IntoIterator<Item = String>>(args: I) -> Result<Invocation, String> {
    let mut args = args.into_iter();
    let mut common = Common::default();
    let mut maps = Vec::new();
    let mut command = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--" => {
                command.extend(args.by_ref());
                break;
            }
            "--help" | "-h" => return Ok(Invocation::Help),
            "--version" | "-V" => return Ok(Invocation::Version),
            "--map" => {
                let value = args.next().ok_or("missing value for --map")?;
                maps.push(MapSpec::parse(&value)?);
            }
            other => {
                if let Some(value) = other.strip_prefix("--map=") {
                    maps.push(MapSpec::parse(value)?);
                    continue;
                }
                if common.consume(other, &mut args)? {
                    continue; // consumed as a common option
                }
                if other.starts_with('-') {
                    return Err(format!(
                        "unknown option {other:?}; if it is part of the command, put the command after `--` \
                         (usage: docker-bluff [options] [--map DIR]... [--] COMMAND [ARGS...])"
                    ));
                }
                // First non-option token starts the command; take the rest verbatim.
                command.push(other.to_string());
                command.extend(args.by_ref());
                break;
            }
        }
    }

    if command.is_empty() {
        return Err(
            "no command given: usage is `docker-bluff --id DISK:SEEN [options] [--] docker run ...` \
             or `docker-bluff --id DISK:SEEN --map DIR ... [--] <command>`"
                .to_string(),
        );
    }
    if common.uid_swaps.is_empty() && common.gid_swaps.is_empty() {
        return Err("at least one --id mapping is required (e.g. --id me:0)".to_string());
    }

    if looks_like_docker_run(&command) {
        if !maps.is_empty() {
            return Err(
                "--map is not used with `docker run`; docker bind mounts are taken from -v/--mount instead".to_string(),
            );
        }
        let (argv0, global_flags, run_args) = split_docker_run(command)?;
        Ok(Invocation::Run(Options {
            verbose: common.verbose,
            uid_swaps: common.uid_swaps,
            gid_swaps: common.gid_swaps,
            argv0,
            global_flags,
            run_args,
        }))
    } else {
        if maps.is_empty() {
            return Err(format!(
                "nothing to remap: {:?} is not a `docker run` command, so at least one --map DIR is required",
                command[0]
            ));
        }
        Ok(Invocation::Exec(ExecOptions {
            verbose: common.verbose,
            uid_swaps: common.uid_swaps,
            gid_swaps: common.gid_swaps,
            maps,
            command,
        }))
    }
}

/// `docker` global flags that take a separate value, so the value token isn't
/// mistaken for the subcommand when locating `run`.
const DOCKER_VALUE_GLOBALS: &[&str] = &[
    "--config",
    "-c",
    "--context",
    "-H",
    "--host",
    "-l",
    "--log-level",
    "--tlscacert",
    "--tlscert",
    "--tlskey",
];

/// If `command` is `docker [globals] run ...`, return the index of the `run`
/// subcommand. Global flags (and the values of value-taking ones) before it are
/// skipped and the *first non-flag token* must be `run`, so `docker exec ...`
/// (even one that mentions `run` later) and a global-flag value that happens to
/// be `run` are not misread as `docker run`.
fn docker_run_index(command: &[String]) -> Option<usize> {
    let prog = command[0].rsplit('/').next().unwrap_or(&command[0]);
    if prog != "docker" {
        return None;
    }
    let mut i = 1;
    while i < command.len() {
        let tok = &command[i];
        if tok.starts_with('-') {
            // `--flag=value` is self-contained; a value-taking global consumes
            // the next token; everything else is a boolean flag.
            i += if tok.contains('=') || !DOCKER_VALUE_GLOBALS.contains(&tok.as_str()) {
                1
            } else {
                2
            };
            continue;
        }
        return (tok == "run").then_some(i);
    }
    None
}

fn looks_like_docker_run(command: &[String]) -> bool {
    docker_run_index(command).is_some()
}

/// Split `docker [globals] run [run args]` into (`docker`, globals, run args).
fn split_docker_run(command: Vec<String>) -> Result<(String, Vec<String>, Vec<String>), String> {
    let run_idx =
        docker_run_index(&command).ok_or("docker mode selected but the command is not `docker [globals] run ...`")?;
    let mut iter = command.into_iter();
    let argv0 = iter.next().ok_or("empty docker command")?;
    let global_flags: Vec<String> = iter.by_ref().take(run_idx - 1).collect();
    let _run = iter.next(); // the "run" token
    let run_args: Vec<String> = iter.collect();
    Ok((argv0, global_flags, run_args))
}

pub fn usage() -> String {
    format!(
        "docker-bluff {version}
A prefix wrapper (like sudo/strace) that runs a container, or any command, with
bind-mounted directories wrapped in Linux idmapped mounts, so that the process's
user and the host user see each other's files as their own - at native speed,
with no bindfs/FUSE and no chown -R.

USAGE:
    docker-bluff --id DISK:SEEN ... [--] docker run [OPTIONS] IMAGE [CMD...]
    docker-bluff --id DISK:SEEN ... --map DIR ... [--] COMMAND [ARGS...]

Everything after our options (or after `--`) is the command to run, verbatim.
It is treated as a `docker run` invocation - with the container start-up sync and
lazy unmount - when the program is `docker` and a `run` subcommand is present;
otherwise it is run directly, with each --map directory idmapped IN PLACE (at the
same path, in a private mount namespace) so nothing needs rewriting and nothing
is left on the host. A plain command runs as whoever launched docker-bluff
(root under sudo, you under a capability install).

    Docker : bind-mount sources (-v / --mount) are idmapped and rewritten; the
             rest of the `docker run` command is forwarded unchanged.
    Command: each --map directory is idmapped in place; the mounts vanish when
             the command exits.

OPTIONS:
    --id [u:|g:]DISK:SEEN      Swap two ids on the mount: an id stored as DISK on
                              disk is shown as SEEN, and vice versa. Without a
                              u:/g: prefix the swap applies to both uid and gid.
                              DISK/SEEN are a number or `me` (the invoking
                              user's uid or gid). Repeatable; at least one required.
                                --id me:0       my files <-> root (uid+gid)
                                --id u:0:33 --id g:0:33   root's files <-> uid/gid 33
    --map SRC[:DST]           Idmap directory SRC; the command sees it at DST
                              (default: SRC, i.e. in place). Repeatable. Required
                              unless the command is `docker run`.
    --verbose                 Explain what is being mounted (and, for docker, released).
    -h, --help                Show this help.
    -V, --version             Show the version.

PER-MOUNT OPTION (docker):
    Append `{noremap}` to a bind mount's options to pass it through untouched:
        -v /host/dir:/data:ro,{noremap}
        --mount type=bind,source=/host/dir,target=/data,{noremap}

Only bind mounts of *directories* with absolute host paths are remapped; named
volumes, anonymous volumes and single-file binds are forwarded as-is.

EXAMPLES:
    docker-bluff --id me:0 -- docker run --rm -v \"$PWD:/work\" maven:3 mvn package
    docker-bluff --id me:0 --map \"$PWD\" -- make    # via sudo: run as root, files stay yours
    docker-bluff --id 0:me --map /srv/data -- \\
        tar xf backup.tar                               # edit root-owned files as yourself

Requires Linux >= 5.12 (>= 5.19 for several --id swaps at once; older kernels
cap an id map at 5 extents). Docker mode additionally needs a local Docker
daemon over a unix:// socket. Both need CAP_SYS_ADMIN (a capability-endowed
install, see the README) or root (sudo) for the mount syscalls.",
        version = env!("CARGO_PKG_VERSION"),
        noremap = NOREMAP_OPTION,
    )
}

/// Where a flag's value sits in the argument vector, so it can be rewritten.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ValueLoc {
    /// The value is the whole argument at `index`.
    Separate { index: usize },
    /// The value is `args[index][prefix.len()..]` (`--volume=...`, `-v...`, `-itv...`).
    Inline { index: usize, prefix: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BindSyntax {
    /// `-v src:dst[:opt,opt]`
    Volume { target: String, options: Vec<String> },
    /// `--mount type=bind,source=src,target=dst,...`; `source_index` is the
    /// position of the `source=`/`src=` entry inside `entries`.
    Mount { entries: Vec<String>, source_index: usize },
}

/// A bind mount with an absolute host path found in the `docker run` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    pub source: PathBuf,
    pub target: String,
    /// False when the user opted out with `noremap`.
    pub remap: bool,
    loc: ValueLoc,
    syntax: BindSyntax,
}

impl Bind {
    fn render_value(&self, source: &str) -> String {
        match &self.syntax {
            BindSyntax::Volume { target, options } => {
                let mut spec = format!("{source}:{target}");
                if !options.is_empty() {
                    spec.push(':');
                    spec.push_str(&options.join(","));
                }
                spec
            }
            BindSyntax::Mount { entries, source_index } => {
                let mut entries = entries.clone();
                let key = entries[*source_index].split('=').next().unwrap_or("source").to_string();
                entries[*source_index] = format!("{key}={source}");
                entries.join(",")
            }
        }
    }
}

/// Parsed `docker run` argument vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSpec {
    args: Vec<String>,
    pub binds: Vec<Bind>,
    /// Index of the image argument, if found.
    pub image_index: Option<usize>,
}

impl RunSpec {
    pub fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut spec = RunSpec {
            args,
            binds: Vec::new(),
            image_index: None,
        };
        let mut i = 0;
        while i < spec.args.len() {
            let arg = spec.args[i].clone();
            if arg == "--" {
                spec.image_index = spec.args.get(i + 1).map(|_| i + 1);
                break;
            }
            if let Some(rest) = arg.strip_prefix("--") {
                i += spec.consume_long_flag(i, rest)?;
                continue;
            }
            if arg.len() > 1 && arg.starts_with('-') {
                i += spec.consume_short_cluster(i, &arg)?;
                continue;
            }
            spec.image_index = Some(i);
            break;
        }
        Ok(spec)
    }

    /// Handle a `--name[=value]` argument at index `i`; returns how many args it
    /// consumed (1 for a boolean or inline value, 2 for a separate value).
    fn consume_long_flag(&mut self, i: usize, rest: &str) -> Result<usize, String> {
        let (name, inline) = match rest.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (rest, None),
        };
        if BOOL_LONG.contains(&name) {
            return Ok(1);
        }
        let (value, loc, consumed) = match inline {
            Some(v) => (
                v,
                ValueLoc::Inline {
                    index: i,
                    prefix: format!("--{name}="),
                },
                1,
            ),
            None => {
                let v = self
                    .args
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| format!("docker run: flag needs an argument: --{name}"))?;
                (v, ValueLoc::Separate { index: i + 1 }, 2)
            }
        };
        self.record(name, value, loc);
        Ok(consumed)
    }

    /// Handle a cluster of short flags at index `i`, e.g. `-it`, `-itv/a:/b`,
    /// `-v /a:/b`; returns how many args it consumed (1, or 2 for a trailing
    /// value-taking flag whose value is the next arg).
    fn consume_short_cluster(&mut self, i: usize, arg: &str) -> Result<usize, String> {
        for (offset, c) in arg.char_indices().skip(1) {
            // Boolean short flags (and unknown ones, which Docker rejects) carry
            // no value - skip them. Only a value-taking short flag consumes an
            // argument, and it is the last one in the cluster.
            if !VALUE_SHORT.contains(&c) {
                continue;
            }
            let rest = &arg[offset + c.len_utf8()..];
            if rest.is_empty() {
                let v = self
                    .args
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| format!("docker run: flag needs an argument: '{c}' in {arg}"))?;
                self.record(short_flag_name(c), v, ValueLoc::Separate { index: i + 1 });
                return Ok(2);
            }
            // pflag accepts both `-vVALUE` and `-v=VALUE`.
            let v = rest.strip_prefix('=').unwrap_or(rest);
            let loc = ValueLoc::Inline {
                index: i,
                prefix: arg[..arg.len() - v.len()].to_string(),
            };
            self.record(short_flag_name(c), v.to_string(), loc);
            return Ok(1);
        }
        Ok(1)
    }

    fn record(&mut self, name: &str, value: String, loc: ValueLoc) {
        // `Option` is an iterator of 0 or 1, so `extend` adds the bind if any.
        self.binds.extend(match name {
            "volume" => parse_volume_spec(&value, loc),
            "mount" => parse_mount_spec(&value, loc),
            _ => None,
        });
    }

    /// Binds that are candidates for remapping.
    pub fn remappable_binds(&self) -> impl Iterator<Item = (usize, &Bind)> {
        self.binds.iter().enumerate().filter(|(_, b)| b.remap)
    }

    /// Produce the `docker run` arguments (the part *after* `run`): a tracking
    /// `--label KEY=id` followed by the user's arguments with bind sources
    /// replaced. `replacements` maps bind index -> new source path; binds
    /// without a replacement keep their source (but still lose the `noremap`
    /// option). The caller prepends the docker binary, any global flags, and
    /// `run`.
    pub fn render(&self, label_value: &str, replacements: &[(usize, PathBuf)]) -> Vec<String> {
        let mut args = self.args.clone();
        for (idx, bind) in self.binds.iter().enumerate() {
            let source = replacements
                .iter()
                .find(|(i, _)| *i == idx)
                .map(|(_, p)| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| bind.source.to_string_lossy().into_owned());
            let value = bind.render_value(&source);
            match &bind.loc {
                ValueLoc::Separate { index } => args[*index] = value,
                ValueLoc::Inline { index, prefix } => args[*index] = format!("{prefix}{value}"),
            }
        }
        let mut out = Vec::with_capacity(args.len() + 2);
        out.push("--label".to_string());
        out.push(format!("{LABEL_KEY}={label_value}"));
        out.extend(args);
        out
    }
}

/// `-v` spec: `src:dst[:options]`. Returns `None` for anonymous/named volumes.
fn parse_volume_spec(spec: &str, loc: ValueLoc) -> Option<Bind> {
    let mut parts = spec.splitn(3, ':');
    let source = parts.next()?;
    let target = parts.next()?;
    if !source.starts_with('/') || target.is_empty() {
        return None;
    }
    let mut remap = true;
    let options: Vec<String> = parts
        .next()
        .map(|o| {
            o.split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
        .into_iter()
        .filter(|o| {
            if o == NOREMAP_OPTION {
                remap = false;
                false
            } else {
                true
            }
        })
        .collect();
    Some(Bind {
        source: PathBuf::from(source),
        target: target.to_string(),
        remap,
        loc,
        syntax: BindSyntax::Volume {
            target: target.to_string(),
            options,
        },
    })
}

/// `--mount` spec: comma-separated `key=value` (or bare `readonly`/`ro`).
/// Returns `None` unless `type=bind` with an absolute source.
fn parse_mount_spec(spec: &str, loc: ValueLoc) -> Option<Bind> {
    let mut remap = true;
    let entries: Vec<String> = spec
        .split(',')
        .filter(|s| !s.is_empty())
        .filter(|e| {
            if *e == NOREMAP_OPTION {
                remap = false;
                false
            } else {
                true
            }
        })
        .map(str::to_string)
        .collect();
    let mut kind = "volume";
    let mut source_index = None;
    let mut target = None;
    for (i, entry) in entries.iter().enumerate() {
        let (key, value) = entry.split_once('=').unwrap_or((entry.as_str(), ""));
        match key {
            "type" => kind = value,
            "source" | "src" => source_index = Some(i),
            "target" | "dst" | "destination" => target = Some(value.to_string()),
            _ => {}
        }
    }
    if kind != "bind" {
        return None;
    }
    let source_index = source_index?;
    let source = entries[source_index].split_once('=').map(|(_, v)| v)?;
    if !source.starts_with('/') {
        return None;
    }
    Some(Bind {
        source: PathBuf::from(source),
        target: target?,
        remap,
        loc,
        syntax: BindSyntax::Mount { entries, source_index },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn docker_invocation_autodetect_and_split() {
        // Auto-detected as docker: program is `docker` and a `run` is present.
        let Invocation::Run(o) =
            parse_invocation(s(&["--id", "me:0", "--", "docker", "run", "-it", "alpine"])).unwrap()
        else {
            panic!()
        };
        assert_eq!(
            o.uid_swaps,
            vec![Swap {
                disk: EndId::Invoker,
                seen: EndId::Num(0)
            }]
        );
        assert_eq!(
            o.gid_swaps,
            vec![Swap {
                disk: EndId::Invoker,
                seen: EndId::Num(0)
            }]
        );
        assert_eq!(o.argv0, "docker");
        assert!(o.global_flags.is_empty());
        assert_eq!(o.run_args, s(&["-it", "alpine"]));

        // `--` is optional; global docker flags are preserved before `run`.
        let Invocation::Run(o) = parse_invocation(s(&[
            "--id",
            "u:1000:0",
            "--id=g:1001:0",
            "/usr/bin/docker",
            "--context",
            "prod",
            "run",
            "--rm",
            "img",
        ]))
        .unwrap() else {
            panic!()
        };
        assert_eq!(
            o.uid_swaps,
            vec![Swap {
                disk: EndId::Num(1000),
                seen: EndId::Num(0)
            }]
        );
        assert_eq!(
            o.gid_swaps,
            vec![Swap {
                disk: EndId::Num(1001),
                seen: EndId::Num(0)
            }]
        );
        assert_eq!(o.argv0, "/usr/bin/docker");
        assert_eq!(o.global_flags, s(&["--context", "prod"]));
        assert_eq!(o.run_args, s(&["--rm", "img"]));

        assert_eq!(parse_invocation(s(&["--help"])).unwrap(), Invocation::Help);
        assert_eq!(parse_invocation(s(&["-V"])).unwrap(), Invocation::Version);
    }

    #[test]
    fn docker_run_detection_finds_the_real_subcommand() {
        // `run` as the actual subcommand -> docker mode.
        assert_eq!(docker_run_index(&s(&["docker", "run", "img"])), Some(1));
        // Value of a value-taking global is skipped, even if it is `run`.
        assert_eq!(
            docker_run_index(&s(&["docker", "--context", "run", "run", "img"])),
            Some(3)
        );
        assert_eq!(
            docker_run_index(&s(&["docker", "-H", "unix:///x", "run", "img"])),
            Some(3)
        );
        assert_eq!(
            docker_run_index(&s(&["docker", "--context=prod", "run", "img"])),
            Some(2)
        );
        // A different subcommand that merely *mentions* run later is NOT docker run.
        assert_eq!(docker_run_index(&s(&["docker", "exec", "c", "run"])), None);
        assert_eq!(docker_run_index(&s(&["docker", "ps"])), None);
        // Non-docker program.
        assert_eq!(docker_run_index(&s(&["podman", "run", "img"])), None);

        // End to end: `docker exec ... run` with --map is a plain command, not docker mode.
        let Invocation::Exec(o) =
            parse_invocation(s(&["--id", "me:0", "--map", "/a", "--", "docker", "exec", "c", "run"])).unwrap()
        else {
            panic!("expected generic mode for `docker exec ... run`")
        };
        assert_eq!(o.command, s(&["docker", "exec", "c", "run"]));
    }

    #[test]
    fn generic_invocation() {
        // Not docker -> generic; --id and --map interleaved; command after a bare token.
        let Invocation::Exec(o) =
            parse_invocation(s(&["--map", "/a", "--id", "0:me", "--map=/b:/mnt/b", "make", "-j4"])).unwrap()
        else {
            panic!()
        };
        // Bare --id maps both uid and gid.
        assert_eq!(
            o.uid_swaps,
            vec![Swap {
                disk: EndId::Num(0),
                seen: EndId::Invoker
            }]
        );
        assert_eq!(
            o.gid_swaps,
            vec![Swap {
                disk: EndId::Num(0),
                seen: EndId::Invoker
            }]
        );
        assert_eq!(
            o.maps,
            vec![
                MapSpec {
                    source: "/a".into(),
                    target: "/a".into()
                },
                MapSpec {
                    source: "/b".into(),
                    target: "/mnt/b".into()
                },
            ]
        );
        assert_eq!(o.command, s(&["make", "-j4"]));

        // Command after `--` may start with a dash; multiple --id accumulate.
        let Invocation::Exec(o) = parse_invocation(s(&[
            "--verbose",
            "--id",
            "u:0:5",
            "--id",
            "u:1:6",
            "--map",
            "/data",
            "--",
            "--weird",
            "arg",
        ]))
        .unwrap() else {
            panic!()
        };
        assert!(o.verbose);
        assert_eq!(
            o.uid_swaps,
            vec![
                Swap {
                    disk: EndId::Num(0),
                    seen: EndId::Num(5)
                },
                Swap {
                    disk: EndId::Num(1),
                    seen: EndId::Num(6)
                },
            ]
        );
        assert!(o.gid_swaps.is_empty());
        assert_eq!(o.command, s(&["--weird", "arg"]));

        // A `docker`-named command that is not `run` is a plain command (needs --map).
        let Invocation::Exec(o) = parse_invocation(s(&["--id", "me:0", "--map", "/a", "--", "docker", "ps"])).unwrap()
        else {
            panic!()
        };
        assert_eq!(o.command, s(&["docker", "ps"]));
    }

    #[test]
    fn invocation_errors() {
        assert!(parse_invocation(s(&[])).is_err()); // no command
        assert!(parse_invocation(s(&["--", "docker", "run", "img"])).is_err()); // no --id
        assert!(parse_invocation(s(&["--id", "me:0", "make"])).is_err()); // not docker, no --map
        assert!(parse_invocation(s(&["--id"])).is_err()); // dangling value
        assert!(parse_invocation(s(&["--id", "bob:0", "--", "docker", "run", "x"])).is_err()); // bad id
        assert!(parse_invocation(s(&["--id", "0", "--", "docker", "run", "x"])).is_err()); // missing SEEN
        assert!(parse_invocation(s(&["--id", "x:0:5", "--", "docker", "run", "x"])).is_err()); // bad column prefix
        assert!(parse_invocation(s(&["--id", "me:0", "--map"])).is_err()); // dangling --map
        assert!(parse_invocation(s(&["--id", "me:0", "--map", "relative", "cmd"])).is_err()); // not absolute
        assert!(parse_invocation(s(&["--id", "me:0", "--unknown", "make"])).is_err()); // unknown option
        // --map with a docker command is rejected (docker mounts come from -v).
        assert!(parse_invocation(s(&["--id", "me:0", "--map", "/a", "--", "docker", "run", "img"])).is_err());
    }

    fn parse(v: &[&str]) -> RunSpec {
        RunSpec::parse(s(v)).unwrap()
    }

    #[test]
    fn finds_image_after_boolean_and_valued_flags() {
        let spec = parse(&[
            "-it", "--rm", "--name", "x", "-e", "A=1", "--gpus", "all", "alpine", "-v",
        ]);
        assert_eq!(spec.image_index, Some(8));
        assert!(
            spec.binds.is_empty(),
            "-v after the image belongs to the container command"
        );
    }

    #[test]
    fn dash_dash_terminates_flags() {
        let spec = parse(&["--rm", "--", "alpine", "-v", "/a:/b"]);
        assert_eq!(spec.image_index, Some(2));
        assert!(spec.binds.is_empty());
    }

    #[test]
    fn volume_syntaxes() {
        let spec = parse(&[
            "-v",
            "/a:/b",
            "--volume",
            "/c:/d:ro",
            "--volume=/e:/f",
            "-itv/g:/h",
            "-v=/i:/j:rw,z",
            "-v",
            "named:/k",
            "-v",
            "/anon",
            "img",
        ]);
        let sources: Vec<_> = spec.binds.iter().map(|b| b.source.to_str().unwrap()).collect();
        assert_eq!(sources, vec!["/a", "/c", "/e", "/g", "/i"]);
        assert_eq!(spec.image_index, Some(11));
        assert_eq!(spec.binds[1].target, "/d");

        let repl: Vec<(usize, PathBuf)> = (0..5).map(|i| (i, PathBuf::from(format!("/run/x/{i}")))).collect();
        assert_eq!(
            spec.render("ID", &repl),
            s(&[
                "--label",
                "docker-bluff.id=ID",
                "-v",
                "/run/x/0:/b",
                "--volume",
                "/run/x/1:/d:ro",
                "--volume=/run/x/2:/f",
                "-itv/run/x/3:/h",
                "-v=/run/x/4:/j:rw,z",
                "-v",
                "named:/k",
                "-v",
                "/anon",
                "img",
            ])
        );
    }

    #[test]
    fn noremap_option_is_stripped_and_disables_remap() {
        let spec = parse(&["-v", "/a:/b:ro,noremap", "-v", "/c:/d:noremap", "img"]);
        assert_eq!(spec.binds.len(), 2);
        assert!(spec.binds.iter().all(|b| !b.remap));
        assert_eq!(spec.remappable_binds().count(), 0);
        assert_eq!(
            spec.render("ID", &[]),
            s(&["--label", "docker-bluff.id=ID", "-v", "/a:/b:ro", "-v", "/c:/d", "img"])
        );
    }

    #[test]
    fn mount_syntax() {
        let spec = parse(&[
            "--mount",
            "type=bind,source=/a,target=/b,readonly",
            "--mount=type=bind,src=/c,dst=/d,bind-propagation=rslave,noremap",
            "--mount",
            "type=volume,source=vol,target=/e",
            "--mount",
            "type=bind,source=relative,target=/f",
            "--mount",
            "source=/g,target=/h",
            "img",
        ]);
        assert_eq!(spec.binds.len(), 2);
        assert_eq!(spec.binds[0].source, PathBuf::from("/a"));
        assert_eq!(spec.binds[0].target, "/b");
        assert!(spec.binds[0].remap);
        assert_eq!(spec.binds[1].source, PathBuf::from("/c"));
        assert!(!spec.binds[1].remap);
        assert_eq!(spec.image_index, Some(9));
        assert_eq!(
            spec.render("ID", &[(0, PathBuf::from("/run/x/0"))]),
            s(&[
                "--label",
                "docker-bluff.id=ID",
                "--mount",
                "type=bind,source=/run/x/0,target=/b,readonly",
                "--mount=type=bind,src=/c,dst=/d,bind-propagation=rslave",
                "--mount",
                "type=volume,source=vol,target=/e",
                "--mount",
                "type=bind,source=relative,target=/f",
                "--mount",
                "source=/g,target=/h",
                "img",
            ])
        );
    }

    #[test]
    fn user_flag_value_is_consumed_not_treated_as_image() {
        // -u/--user still take a value (so the image is found correctly), we
        // just no longer capture it (the id mapping comes from `--id`).
        assert_eq!(parse(&["-u", "1000:1000", "alpine"]).image_index, Some(2));
        assert_eq!(parse(&["--user=33", "alpine"]).image_index, Some(1));
        assert_eq!(parse(&["-itu", "www-data", "alpine"]).image_index, Some(2));
    }

    #[test]
    fn missing_flag_value_is_an_error() {
        assert!(RunSpec::parse(s(&["-v"])).is_err());
        assert!(RunSpec::parse(s(&["--name"])).is_err());
    }

    #[test]
    fn no_arguments_is_fine() {
        let spec = parse(&[]);
        assert_eq!(spec.image_index, None);
        assert_eq!(spec.render("ID", &[]), s(&["--label", "docker-bluff.id=ID"]));
    }
}
