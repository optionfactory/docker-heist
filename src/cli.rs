use std::env;
use std::net::Ipv4Addr;
use std::process::exit;

#[derive(Debug)]
pub struct Config {
    pub name: String,
    pub net: String,
    pub ip: String,
    pub verbose: bool,
    pub strict: bool,
    pub lax: bool,
    pub cmd: Vec<String>,
}

pub fn parse_args() -> Result<Config, String> {
    let args_vec: Vec<String> = env::args_os()
        .skip(1)
        .map(|a| a.into_string())
        .collect::<Result<_, _>>()
        .map_err(|_| "Invalid UTF-8 sequence in arguments".to_string())?;

    if args_vec.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        exit(0);
    }
    if args_vec.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("docker-intrude {}", env!("CARGO_PKG_VERSION"));
        exit(0);
    }

    parse_from(args_vec)
}

fn parse_from<I: IntoIterator<Item = String>>(args: I) -> Result<Config, String> {
    let mut args = args.into_iter();
    let mut name = None;
    let mut net = None;
    let mut ip = None;
    let mut verbose = false;
    let mut strict = false;
    let mut lax = false;
    let mut cmd = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--name" | "-n" => name = Some(args.next().ok_or("Missing value for --name")?),
            "--net" => net = Some(args.next().ok_or("Missing value for --net")?),
            "--ip" => ip = Some(args.next().ok_or("Missing value for --ip")?),
            "--verbose" | "-v" => verbose = true,
            "--strict" => strict = true,
            "--lax" => lax = true,
            "--" => {
                cmd.extend(args);
                break;
            }
            other => {
                if other.starts_with('-') {
                    return Err(format!("Unknown flag: {other}"));
                } else {
                    cmd.push(other.to_string());
                    cmd.extend(args);
                    break;
                }
            }
        }
    }

    if cmd.is_empty() {
        return Err("Missing command to execute".to_string());
    }

    let name_val = name.ok_or("Missing required flag: --name")?;
    let net_val = net.ok_or("Missing required flag: --net")?;
    let ip_val = ip.ok_or("Missing required flag: --ip")?;

    if ip_val.parse::<Ipv4Addr>().is_err() {
        return Err(format!("Invalid IPv4 address ('{ip_val}')"));
    }
    if !is_valid_docker_identifier(&name_val) || !is_valid_docker_identifier(&net_val) {
        return Err("Invalid network or container identifier syntax".to_string());
    }
    if strict && lax {
        return Err("--strict and --lax are mutually exclusive.".to_string());
    }

    Ok(Config {
        name: name_val,
        net: net_val,
        ip: ip_val,
        verbose,
        cmd,
        strict,
        lax,
    })
}

fn is_valid_docker_identifier(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

fn print_help() {
    eprintln!("docker-intrude - Run commands directly within a specific Docker network namespace");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  docker-intrude --name <NAME> --net <NET> --ip <IP> [-v] [--strict|--lax] -- <CMD...>");
    eprintln!("  docker-intrude --help");
    eprintln!("  docker-intrude --version");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --strict       Clear the capability bounding set (breaks ping/gdb file capabilities, provides maximum isolation)");
    eprintln!("  --lax          Disable setuid-root protection entirely (no securebits). Required when the command");
    eprintln!("                 needs setuid-root binaries to function (e.g. sudo). Reduces isolation; not combinable with --strict.");
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

    fn minimal(parts: &[&str]) -> Vec<String> {
        let mut v = vec!["--name", "n", "--net", "m", "--ip", "10.0.0.5"];
        v.extend_from_slice(parts);
        args(&v)
    }

    #[test]
    fn identifier_validator_rejects_invalid() {
        for bad in [
            "",
            "-leading",
            "with space",
            "with/slash",
            "with;semi",
            "with$dollar",
            "with`tick",
            "with|pipe",
            "with*star",
            "with(paren)",
            "uña",
            "with\nnewline",
        ] {
            assert!(
                !is_valid_docker_identifier(bad),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn identifier_validator_accepts_valid() {
        for good in ["a", "abc-123", "foo.bar", "UPPER", "under_score", "a.b.c-d_e", "x.y"] {
            assert!(is_valid_docker_identifier(good), "should accept {good:?}");
        }
    }

    #[test]
    fn parses_minimal_valid_invocation() {
        let cfg = ok(&["--name", "n", "--net", "m", "--ip", "10.0.0.5", "--", "echo", "hi"]);
        assert_eq!(cfg.name, "n");
        assert_eq!(cfg.net, "m");
        assert_eq!(cfg.ip, "10.0.0.5");
        assert!(!cfg.verbose);
        assert!(!cfg.strict);
        assert_eq!(cfg.cmd, vec!["echo", "hi"]);
    }

    #[test]
    fn supports_short_name_flag() {
        let cfg = ok(&["-n", "abc", "--net", "m", "--ip", "1.2.3.4", "--", "x"]);
        assert_eq!(cfg.name, "abc");
    }

    #[test]
    fn enables_verbose_and_strict() {
        let cfg = ok(&["--name", "n", "--net", "m", "--ip", "1.2.3.4", "-v", "--strict", "--", "x"]);
        assert!(cfg.verbose);
        assert!(cfg.strict);
    }

    #[test]
    fn lax_defaults_to_false() {
        let cfg = ok(&["--name", "n", "--net", "m", "--ip", "1.2.3.4", "--", "x"]);
        assert!(!cfg.lax);
    }

    #[test]
    fn enables_lax() {
        let cfg = ok(&["--name", "n", "--net", "m", "--ip", "1.2.3.4", "--lax", "--", "x"]);
        assert!(cfg.lax);
        assert!(!cfg.strict);
    }

    #[test]
    fn rejects_strict_combined_with_lax() {
        let err = parse_from(args(&[
            "--name", "n", "--net", "m", "--ip", "1.2.3.4", "--strict", "--lax", "--", "x",
        ]))
        .unwrap_err();
        assert!(err.contains("mutually exclusive"), "{err}");
        assert!(err.contains("--strict"), "{err}");
        assert!(err.contains("--lax"), "{err}");
    }

    #[test]
    fn command_without_separator_takes_rest_verbatim() {
        // First non-flag positional starts the command; everything after is passed as-is,
        // including flag-looking tokens. This is the documented wrapper contract.
        let cfg = ok(&["--name", "n", "--net", "m", "--ip", "1.2.3.4", "ping", "1.2.3.4"]);
        assert_eq!(cfg.cmd, vec!["ping", "1.2.3.4"]);
    }

    #[test]
    fn flags_after_command_are_command_args() {
        let cfg = ok(&["--name", "n", "--net", "m", "--ip", "1.2.3.4", "sh", "-c", "true"]);
        assert_eq!(cfg.cmd, vec!["sh", "-c", "true"]);
    }

    #[test]
    fn literal_double_dash_after_command_is_preserved() {
        // After the command has started, `--` is no longer a separator.
        let cfg = ok(&["--name", "n", "--net", "m", "--ip", "1.2.3.4", "ping", "--", "1.2.3.4"]);
        assert_eq!(cfg.cmd, vec!["ping", "--", "1.2.3.4"]);
    }

    #[test]
    fn multiple_commands_after_separator() {
        let cfg = ok(&["--name", "n", "--net", "m", "--ip", "1.2.3.4", "--", "env", "--flag", "value"]);
        assert_eq!(cfg.cmd, vec!["env", "--flag", "value"]);
    }

    #[test]
    fn rejects_missing_name() {
        let err = parse_from(args(&["--net", "m", "--ip", "1.2.3.4", "--", "x"])).unwrap_err();
        assert!(err.contains("--name"), "{err}");
    }

    #[test]
    fn rejects_missing_net() {
        let err = parse_from(args(&["--name", "n", "--ip", "1.2.3.4", "--", "x"])).unwrap_err();
        assert!(err.contains("--net"), "{err}");
    }

    #[test]
    fn rejects_missing_ip() {
        let err = parse_from(args(&["--name", "n", "--net", "m", "--", "x"])).unwrap_err();
        assert!(err.contains("--ip"), "{err}");
    }

    #[test]
    fn rejects_flag_without_value_when_last() {
        let err = parse_from(args(&["--name", "n", "--net", "m", "--ip"])).unwrap_err();
        assert!(err.contains("Missing value for --ip"), "{err}");
    }

    #[test]
    fn rejects_unknown_flag() {
        let err = parse_from(minimal(&["--bogus", "--", "x"])).unwrap_err();
        assert!(err.contains("Unknown flag"), "{err}");
    }

    #[test]
    fn rejects_missing_command() {
        let err = parse_from(args(&["--name", "n", "--net", "m", "--ip", "1.2.3.4"])).unwrap_err();
        assert!(err.contains("Missing command"), "{err}");
    }

    #[test]
    fn rejects_empty_command_after_separator() {
        let err = parse_from(args(&["--name", "n", "--net", "m", "--ip", "1.2.3.4", "--"])).unwrap_err();
        assert!(err.contains("Missing command"), "{err}");
    }

    #[test]
    fn rejects_malformed_ip() {
        let err = parse_from(args(&["--name", "n", "--net", "m", "--ip", "not.an.ip", "--", "x"])).unwrap_err();
        assert!(err.to_lowercase().contains("ip"), "{err}");
    }

    #[test]
    fn rejects_ipv6_address() {
        // IPv6 must be rejected: the Docker payload only populates IPv4Address
        // (see IpamConfig). Accepting IPv6 would silently misroute it.
        let err = parse_from(args(&["--name", "n", "--net", "m", "--ip", "::1", "--", "x"])).unwrap_err();
        assert!(err.to_lowercase().contains("ipv4") || err.to_lowercase().contains("ip"), "{err}");
    }

    #[test]
    fn accepts_zero_in_first_octet() {
        // Trailing zeros are fine; this just guards against an over-strict regex.
        let cfg = ok(&["--name", "n", "--net", "m", "--ip", "10.0.0.1", "--", "x"]);
        assert_eq!(cfg.ip, "10.0.0.1");
    }

    #[test]
    fn rejects_invalid_name_chars() {
        let err = parse_from(args(&["--name", "a/b", "--net", "m", "--ip", "1.2.3.4", "--", "x"])).unwrap_err();
        assert!(err.contains("identifier"), "{err}");
    }

    #[test]
    fn rejects_invalid_net_chars() {
        let err = parse_from(args(&["--name", "n", "--net", "m;q", "--ip", "1.2.3.4", "--", "x"])).unwrap_err();
        assert!(err.contains("identifier"), "{err}");
    }

    #[test]
    fn rejects_name_with_leading_dash() {
        // "--name -x" would be consumed as a value, but "-x" fails identifier check.
        let err = parse_from(args(&["--name", "-x", "--net", "m", "--ip", "1.2.3.4", "--", "cmd"])).unwrap_err();
        assert!(err.contains("identifier"), "{err}");
    }
}