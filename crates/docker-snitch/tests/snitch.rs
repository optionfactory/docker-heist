//! End-to-end tests against the built binary.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_docker-snitch"))
}

fn temp_dir() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("docker-snitch-e2e-{}-{n}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn relays_appended_content_and_propagates_exit_code() {
    let dir = temp_dir();
    let log = dir.join("app.log");
    let out = bin()
        .args(["--interval", "20", log.to_str().unwrap(), "--", "sh", "-c"])
        .arg(format!(
            "echo hello >> {0}; sleep 0.1; echo world >> {0}; exit 3",
            log.display()
        ))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(String::from_utf8_lossy(&out.stderr), "hello\nworld\n");
    assert!(out.stdout.is_empty());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn provisions_files_before_exec() {
    let dir = temp_dir();
    let a = dir.join("a.log");
    let b = dir.join("b.log");
    let out = bin()
        .args([a.to_str().unwrap(), b.to_str().unwrap(), "--", "sh", "-c"])
        .arg(format!("test -f {} && test -f {}", a.display(), b.display()))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn missing_directory_fails_before_exec() {
    let dir = temp_dir();
    let log = dir.join("no/such/dir/a.log");
    let marker = dir.join("ran");
    let out = bin()
        .args([log.to_str().unwrap(), "--", "touch", marker.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Failed to open"));
    assert!(!marker.exists(), "the command must not run when provisioning fails");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn stdout_option_relays_to_stdout() {
    let dir = temp_dir();
    let log = dir.join("app.log");
    let out = bin()
        .args(["--stdout", "--interval", "20", log.to_str().unwrap(), "--", "sh", "-c"])
        .arg(format!("echo hi >> {}", log.display()))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hi\n");
    assert!(out.stderr.is_empty());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn keeps_file_small_without_losing_output_and_empties_it_on_exit() {
    let dir = temp_dir();
    let log = dir.join("big.log");
    let out = bin()
        .args(["--interval", "5", log.to_str().unwrap(), "--", "sh", "-c"])
        .arg(format!(
            "i=1; while [ $i -le 3000 ]; do echo line-$i >> {0}; i=$((i+1)); done; echo tail >> {0}",
            log.display()
        ))
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stderr);
    let lines: Vec<&str> = text.lines().collect();
    let expected: Vec<String> = (1..=3000)
        .map(|i| format!("line-{i}"))
        .chain(["tail".to_string()])
        .collect();
    assert_eq!(
        lines, expected,
        "every line relayed exactly once, in order, while a flood was being written"
    );
    assert_eq!(
        fs::metadata(&log).unwrap().len(),
        0,
        "file emptied on exit, not removed"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn forwards_sigterm_and_exits_with_child_status() {
    let mut child = bin()
        .args(["--", "sh", "-c", "trap 'exit 7' TERM; while :; do sleep 0.05; done"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    sleep(Duration::from_millis(300));
    // SAFETY: signalling the process we just spawned.
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(7));
}

#[test]
fn child_killed_by_signal_maps_to_128_plus_signal() {
    let out = bin().args(["--", "sh", "-c", "kill -9 $$"]).output().unwrap();
    assert_eq!(out.status.code(), Some(137));
}

#[test]
fn reaps_orphaned_grandchildren() {
    // The grandchild outlives its parent and gets reparented to docker-snitch,
    // which must reap it: the child then verifies no zombie is left behind.
    let script = "sh -c 'sleep 0.1' & \
                  sleep 0.5; \
                  for p in /proc/[0-9]*; do \
                    grep -q '^PPid:\\s*'\"$PPID\"'$' $p/status 2>/dev/null || continue; \
                    grep -q '^State:\\s*Z' $p/status && exit 9; \
                  done; exit 0";
    let out = bin().args(["--", "sh", "-c", script]).output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "zombie left behind: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn exec_failure_is_reported() {
    let out = bin().args(["--", "/nonexistent/binary"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Failed to exec"));
}

#[test]
fn drains_output_written_right_before_exit() {
    // No sleep after the write: the final pump after the child exits must catch it.
    let dir = temp_dir();
    let log = dir.join("late.log");
    let start = Instant::now();
    let out = bin()
        .args(["--interval", "1000", log.to_str().unwrap(), "--", "sh", "-c"])
        .arg(format!("echo last-words >> {}", log.display()))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stderr), "last-words\n");
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "exit is not delayed by the interval more than once"
    );
    fs::remove_dir_all(dir).unwrap();
}
