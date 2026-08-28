use std::env;
use std::path::PathBuf;
use std::process::exit;
use std::time::Duration;

pub const DEFAULT_INTERVAL_MS: u64 = 250;

#[derive(Debug)]
pub struct Config {
    pub files: Vec<PathBuf>,
    pub interval: Duration,
    pub to_stdout: bool,
    pub cmd: Vec<String>,
}

pub fn parse_args() -> Result<Config, String> {
    let args_vec: Vec<String> = env::args_os()
        .skip(1)
        .map(|a| a.into_string())
        .collect::<Result<_, _>>()
        .map_err(|_| "Invalid UTF-8 sequence in arguments".to_string())?;

    // Only look for help/version before the `--`: after it, they belong to the command.
    let mut own = args_vec.iter().take_while(|a| a.as_str() != "--").peekable();
    if own.peek().is_none() && args_vec.is_empty() {
        print_help();
        exit(1);
    }
    if own.clone().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        exit(0);
    }
    if own.any(|arg| arg == "--version" || arg == "-V") {
        println!("docker-snitch {}", env!("CARGO_PKG_VERSION"));
        exit(0);
    }

    parse_from(args_vec)
}

fn parse_from<I: IntoIterator<Item = String>>(args: I) -> Result<Config, String> {
    let mut args = args.into_iter();
    let mut files = Vec::new();
    let mut interval = Duration::from_millis(DEFAULT_INTERVAL_MS);
    let mut to_stdout = false;
    let mut cmd = Vec::new();
    let mut seen_separator = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--interval" => {
                let v = args.next().ok_or("Missing value for --interval")?;
                let ms: u64 = v
                    .parse()
                    .map_err(|_| format!("Invalid --interval (milliseconds): '{v}'"))?;
                if ms == 0 {
                    return Err("--interval must be at least 1 millisecond".to_string());
                }
                interval = Duration::from_millis(ms);
            }
            "--stdout" => to_stdout = true,
            "--" => {
                seen_separator = true;
                cmd.extend(args);
                break;
            }
            other if other.starts_with('-') => return Err(format!("Unknown flag: {other}")),
            other => files.push(PathBuf::from(other)),
        }
    }

    if !seen_separator {
        return Err("Missing '--' separator: docker-snitch [options] <file>... -- <command> [args...]".to_string());
    }
    if cmd.is_empty() {
        return Err("Missing command to execute".to_string());
    }
    for f in &files {
        if !f.is_absolute() {
            return Err(format!("Log file paths must be absolute: '{}'", f.display()));
        }
    }

    Ok(Config {
        files,
        interval,
        to_stdout,
        cmd,
    })
}

fn print_help() {
    eprintln!(
        "docker-snitch - Runs a daemon and relays its file-only logs to stderr, removing from the files what was relayed"
    );
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  docker-snitch [options] <file>... -- <command> [args...]");
    eprintln!("  docker-snitch --help");
    eprintln!("  docker-snitch --version");
    eprintln!();
    eprintln!("Each <file> is created if missing (its directory must exist), followed like");
    eprintln!("`tail -F` with its new content copied to stderr, and kept small by dropping the");
    eprintln!("relayed prefix in place, losslessly: fallocate collapse-range where the filesystem");
    eprintln!("supports it (ext4, xfs), punch-hole otherwise (tmpfs, btrfs, zfs; the file turns");
    eprintln!("sparse). A filesystem supporting neither is refused before the command starts.");
    eprintln!("Files are emptied on exit. The command runs as a child: docker-snitch forwards");
    eprintln!("SIGTERM/SIGINT/SIGQUIT/SIGHUP/SIGUSR1/SIGUSR2 to it, reaps orphaned zombies,");
    eprintln!("and exits with the command's exit status (128+signal if it was killed).");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --interval <MS>    Poll interval in milliseconds. Default: {DEFAULT_INTERVAL_MS}");
    eprintln!("  --stdout           Relay to stdout instead of stderr");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn ok(parts: &[&str]) -> Config {
        parse_from(args(parts)).unwrap_or_else(|e| panic!("expected ok, got: {e}"))
    }

    #[test]
    fn parses_files_and_command() {
        let cfg = ok(&[
            "/var/log/a.log",
            "/var/log/b.log",
            "--",
            "mariadbd",
            "--defaults-file=/etc/my.cnf",
        ]);
        assert_eq!(
            cfg.files,
            vec![PathBuf::from("/var/log/a.log"), PathBuf::from("/var/log/b.log")]
        );
        assert_eq!(cfg.cmd, vec!["mariadbd", "--defaults-file=/etc/my.cnf"]);
        assert_eq!(cfg.interval, Duration::from_millis(DEFAULT_INTERVAL_MS));
        assert!(!cfg.to_stdout);
    }

    #[test]
    fn allows_no_files() {
        let cfg = ok(&["--", "sleep", "1"]);
        assert!(cfg.files.is_empty());
        assert_eq!(cfg.cmd, vec!["sleep", "1"]);
    }

    #[test]
    fn parses_options() {
        let cfg = ok(&["--interval", "50", "--stdout", "/x.log", "--", "true"]);
        assert_eq!(cfg.interval, Duration::from_millis(50));
        assert!(cfg.to_stdout);
    }

    #[test]
    fn flags_after_separator_belong_to_command() {
        let cfg = ok(&["/x.log", "--", "cmd", "--interval", "--", "-h"]);
        assert_eq!(cfg.cmd, vec!["cmd", "--interval", "--", "-h"]);
        assert_eq!(cfg.interval, Duration::from_millis(DEFAULT_INTERVAL_MS));
    }

    #[test]
    fn rejects_missing_separator() {
        let err = parse_from(args(&["/x.log", "cmd"])).unwrap_err();
        assert!(err.contains("--"), "{err}");
    }

    #[test]
    fn rejects_missing_command() {
        let err = parse_from(args(&["/x.log", "--"])).unwrap_err();
        assert!(err.contains("Missing command"), "{err}");
    }

    #[test]
    fn rejects_relative_paths() {
        let err = parse_from(args(&["relative.log", "--", "true"])).unwrap_err();
        assert!(err.contains("absolute"), "{err}");
    }

    #[test]
    fn rejects_unknown_flag() {
        let err = parse_from(args(&["--bogus", "--", "true"])).unwrap_err();
        assert!(err.contains("Unknown flag"), "{err}");
    }

    #[test]
    fn rejects_zero_interval() {
        let err = parse_from(args(&["--interval", "0", "--", "true"])).unwrap_err();
        assert!(err.contains("--interval"), "{err}");
    }
}
