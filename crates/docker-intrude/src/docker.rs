use std::collections::HashMap;

use dockersock::Socket;

//pinned to optionfactory/sloth:235
const SLOTH_IMAGE: &str =
    "optionfactory/sloth:235@sha256:112c8d8b4fff453dbbf2fbc4950d339bccd3662dcdbe59fa5563c67f5ec89ccd";
const SLOTH_IMAGE_ENCODED: &str =
    "optionfactory%2Fsloth%3A235%40sha256%3A112c8d8b4fff453dbbf2fbc4950d339bccd3662dcdbe59fa5563c67f5ec89ccd";

#[derive(serde::Serialize)]
struct HostConfig {
    #[serde(rename = "NetworkMode")]
    network_mode: String,
}

#[derive(serde::Serialize)]
struct IpamConfig {
    #[serde(rename = "IPv4Address")]
    ipv4_address: String,
}

#[derive(serde::Serialize)]
struct EndpointConfig {
    #[serde(rename = "IPAMConfig")]
    ipam_config: IpamConfig,
}

#[derive(serde::Serialize)]
struct NetworkingConfig {
    #[serde(rename = "EndpointsConfig")]
    endpoints_config: HashMap<String, EndpointConfig>,
}

#[derive(serde::Serialize)]
struct CreateContainerPayload {
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "HostConfig")]
    host_config: HostConfig,
    #[serde(rename = "NetworkingConfig")]
    networking_config: NetworkingConfig,
}

#[derive(serde::Deserialize)]
struct ContainerState {
    #[serde(rename = "Pid")]
    pid: i32,
}

#[derive(serde::Deserialize)]
struct InspectResponse {
    #[serde(rename = "State")]
    state: ContainerState,
}

pub struct ContainerGuard<'a> {
    pub name: String,
    client: &'a DockerClient,
}

impl<'a> Drop for ContainerGuard<'a> {
    fn drop(&mut self) {
        let _ = self
            .client
            .query("DELETE", &format!("/containers/{}?force=true", self.name), None);
    }
}

pub struct DockerClient {
    socket: Socket,
    pub socket_uid: u32,
    verbose: bool,
}

impl DockerClient {
    pub fn new(verbose: bool) -> Result<Self, String> {
        let socket = Socket::from_env()?;
        let real_uid = unsafe { libc::getuid() };
        let socket_uid = socket
            .owner_uid()
            .map_err(|_| format!("Socket not found at {}", socket.path().display()))?;
        if socket_uid != 0 && socket_uid != real_uid {
            return Err("Socket owner mismatch.".to_string());
        }
        Ok(Self {
            socket,
            socket_uid,
            verbose,
        })
    }

    /// Send a request and return `(status, body)`.
    fn query(&self, method: &str, path: &str, json_body: Option<&str>) -> Result<(u16, String), String> {
        let r = self.socket.request(method, path, json_body)?;
        Ok((r.status, r.body))
    }

    pub fn ping(&self) -> Result<(), String> {
        let (status, _) = self.query("GET", "/_ping", None)?;
        if status != 200 {
            return Err("Docker daemon is not responding over the socket.".to_string());
        }
        Ok(())
    }

    fn ensure_image_exists(&self) -> Result<(), String> {
        let (status, _) = self.query("GET", &format!("/images/{}/json", SLOTH_IMAGE), None)?;
        if status == 200 {
            return Ok(());
        }
        if self.verbose {
            println!(
                ":: Image '{}' not found locally. Pulling from registry... ::",
                SLOTH_IMAGE
            );
        }

        let (pull_status, pull_body) = self.query(
            "POST",
            &format!("/images/create?fromImage={}", SLOTH_IMAGE_ENCODED),
            None,
        )?;

        if pull_status != 200 {
            return Err(format!("Failed to pull Docker image '{}': {}", SLOTH_IMAGE, pull_body));
        }

        Ok(())
    }

    pub fn provision_network_holder(&self, name: &str, net: &str, ip: &str) -> Result<ContainerGuard<'_>, String> {
        self.ensure_image_exists()?;
        let _ = self.query("DELETE", &format!("/containers/{name}?force=true"), None);

        let mut endpoints_map = HashMap::new();
        endpoints_map.insert(
            net.to_string(),
            EndpointConfig {
                ipam_config: IpamConfig {
                    ipv4_address: ip.to_string(),
                },
            },
        );

        let create_payload = CreateContainerPayload {
            image: SLOTH_IMAGE.to_string(),
            host_config: HostConfig {
                network_mode: net.to_string(),
            },
            networking_config: NetworkingConfig {
                endpoints_config: endpoints_map,
            },
        };

        let serialized_body = serde_json::to_string(&create_payload).map_err(|e| e.to_string())?;
        let (create_status, create_body) = self.query(
            "POST",
            &format!("/containers/create?name={name}"),
            Some(&serialized_body),
        )?;

        if create_status != 201 {
            return Err(format!("Docker allocation failure: {create_body}"));
        }

        let (start_status, start_body) = self.query("POST", &format!("/containers/{name}/start"), None)?;
        if start_status != 204 {
            return Err(format!("Docker start failure: {start_body}"));
        }

        Ok(ContainerGuard {
            name: name.to_string(),
            client: self,
        })
    }

    pub fn get_container_pid(&self, name: &str) -> Result<i32, String> {
        let (status, body) = self.query("GET", &format!("/containers/{name}/json"), None)?;
        if status != 200 {
            return Err(format!("Docker state inspection failure: {body}"));
        }

        let inspect_data: InspectResponse = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        if inspect_data.state.pid <= 0 {
            return Err("Container holder is not running. Ensure the image is valid and try again.".to_string());
        }
        Ok(inspect_data.state.pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_payload_serializes_to_docker_field_names() {
        let mut endpoints = HashMap::new();
        endpoints.insert(
            "devnet".to_string(),
            EndpointConfig {
                ipam_config: IpamConfig {
                    ipv4_address: "172.18.0.22".to_string(),
                },
            },
        );
        let payload = CreateContainerPayload {
            image: "img".to_string(),
            host_config: HostConfig {
                network_mode: "devnet".to_string(),
            },
            networking_config: NetworkingConfig {
                endpoints_config: endpoints,
            },
        };
        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["Image"], "img");
        assert_eq!(json["HostConfig"]["NetworkMode"], "devnet");
        assert_eq!(
            json["NetworkingConfig"]["EndpointsConfig"]["devnet"]["IPAMConfig"]["IPv4Address"],
            "172.18.0.22"
        );
    }

    #[test]
    fn sloth_image_encoded_stays_in_sync_with_raw() {
        let expected: String = SLOTH_IMAGE
            .chars()
            .map(|c| match c {
                '/' => "%2F".to_string(),
                ':' => "%3A".to_string(),
                '@' => "%40".to_string(),
                c => c.to_string(),
            })
            .collect();
        assert_eq!(
            SLOTH_IMAGE_ENCODED, expected,
            "SLOTH_IMAGE_ENCODED must be the percent-encoded form of SLOTH_IMAGE; \
             regenerate it when SLOTH_IMAGE is updated."
        );
    }
}
