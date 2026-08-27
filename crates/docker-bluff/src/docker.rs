use std::path::Path;

use dockersock::Socket;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerState {
    Created,
    Running,
    Restarting,
    Paused,
    Exited,
    Dead,
    Removing,
    Other(String),
}

impl ContainerState {
    fn parse(s: &str) -> Self {
        match s {
            "created" => Self::Created,
            "running" => Self::Running,
            "restarting" => Self::Restarting,
            "paused" => Self::Paused,
            "exited" => Self::Exited,
            "dead" => Self::Dead,
            "removing" => Self::Removing,
            other => Self::Other(other.to_string()),
        }
    }

    /// The container's rootfs has been assembled and its init started: runc
    /// has already bind-mounted our idmapped tree into the container's mount
    /// namespace, so the host-side mount point is no longer needed.
    pub fn has_started(&self) -> bool {
        matches!(self, Self::Running | Self::Restarting | Self::Paused)
    }

    /// The container will never (again) need the host-side mount point.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Exited | Self::Dead | Self::Removing)
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Created => "created",
            Self::Running => "running",
            Self::Restarting => "restarting",
            Self::Paused => "paused",
            Self::Exited => "exited",
            Self::Dead => "dead",
            Self::Removing => "removing",
            Self::Other(s) => s,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ContainerSummary {
    pub id: String,
    pub state: ContainerState,
}

pub struct DockerClient {
    socket: Socket,
}

impl DockerClient {
    /// Honour `DOCKER_HOST=unix://...`; default to `/var/run/docker.sock`.
    /// Remote daemons are rejected: the daemon must run on this host to see the
    /// mount we create for it.
    pub fn from_env() -> Result<Self, String> {
        Ok(Self {
            socket: Socket::from_env()?,
        })
    }

    pub fn socket_path(&self) -> &Path {
        self.socket.path()
    }

    pub fn ping(&self) -> Result<(), String> {
        let r = self.socket.request("GET", "/_ping", None)?;
        if r.status != 200 {
            return Err(format!(
                "Docker daemon returned HTTP {} to /_ping: {}",
                r.status,
                r.body.trim()
            ));
        }
        Ok(())
    }

    /// Find the (single) container labelled `key=value`, in any state.
    pub fn find_by_label(&self, key: &str, value: &str) -> Result<Option<ContainerSummary>, String> {
        let filters = format!("{{\"label\":[\"{key}={value}\"]}}");
        let path = format!(
            "/containers/json?all=true&filters={}",
            dockersock::percent_encode(&filters)
        );
        let r = self.socket.request("GET", &path, None)?;
        if r.status != 200 {
            return Err(format!(
                "container listing failed with HTTP {}: {}",
                r.status,
                r.body.trim()
            ));
        }
        let json: Value = serde_json::from_str(&r.body).map_err(|e| format!("invalid JSON from Docker: {e}"))?;
        Ok(parse_summary(&json))
    }

    /// PID of the container's init process on the host (0 if not running).
    pub fn inspect_pid(&self, id: &str) -> Result<i32, String> {
        let r = self.socket.request("GET", &format!("/containers/{id}/json"), None)?;
        if r.status != 200 {
            return Err(format!(
                "container inspect failed with HTTP {}: {}",
                r.status,
                r.body.trim()
            ));
        }
        let json: Value = serde_json::from_str(&r.body).map_err(|e| format!("invalid JSON from Docker: {e}"))?;
        Ok(json["State"]["Pid"].as_i64().unwrap_or(0) as i32)
    }
}

fn parse_summary(json: &Value) -> Option<ContainerSummary> {
    let first = json.as_array()?.first()?;
    Some(ContainerSummary {
        id: first["Id"].as_str()?.to_string(),
        state: ContainerState::parse(first["State"].as_str().unwrap_or("")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_summary_reads_id_and_state() {
        let json: Value = serde_json::from_str(r#"[{"Id":"abc","State":"running"}]"#).unwrap();
        let summary = parse_summary(&json).unwrap();
        assert_eq!(summary.id, "abc");
        assert_eq!(summary.state, ContainerState::Running);
    }

    #[test]
    fn empty_listing_is_none() {
        assert!(parse_summary(&serde_json::json!([])).is_none());
        assert!(parse_summary(&serde_json::json!({})).is_none());
    }

    #[test]
    fn state_classification() {
        assert!(ContainerState::parse("running").has_started());
        assert!(ContainerState::parse("paused").has_started());
        assert!(!ContainerState::parse("created").has_started());
        assert!(!ContainerState::parse("created").is_terminal());
        assert!(ContainerState::parse("exited").is_terminal());
        assert!(ContainerState::parse("dead").is_terminal());
        assert_eq!(ContainerState::parse("weird"), ContainerState::Other("weird".into()));
    }
}
