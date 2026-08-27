use std::collections::BTreeMap;

use crate::ProxyError;

/// HTTP methods admitted by the closed Docker route parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerMethod {
    /// GET.
    Get,
    /// HEAD.
    Head,
    /// POST.
    Post,
    /// PUT.
    Put,
    /// DELETE.
    Delete,
}

impl DockerMethod {
    /// Parse an exact uppercase method. Unknown methods fail closed.
    pub fn parse(value: &str) -> Result<Self, ProxyError> {
        match value {
            "GET" => Ok(Self::Get),
            "HEAD" => Ok(Self::Head),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "DELETE" => Ok(Self::Delete),
            _ => Err(ProxyError::RouteRefused("unknown HTTP method".into())),
        }
    }
}

/// Every Docker-compatible operation recognized by the Phase-1 proxy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DockerRoute {
    /// Engine ping.
    Ping,
    /// Filtered version response.
    Version,
    /// Filtered engine info response.
    Info,
    /// Attempt-owned container list.
    ContainerList,
    /// Digest-pinned image inspection.
    ImageInspect {
        /// Requested image identifier.
        image: String,
    },
    /// Attempt-local empty volume inventory used by pinned `act` cleanup.
    VolumeList,
    /// Container create.
    ContainerCreate,
    /// Container inspect.
    ContainerInspect {
        /// Requested container identifier.
        id: String,
    },
    /// Attach/hijack.
    ContainerAttach {
        /// Requested container identifier.
        id: String,
    },
    /// Pre-start gated start.
    ContainerStart {
        /// Requested container identifier.
        id: String,
    },
    /// Wait for a terminal container state.
    ContainerWait {
        /// Requested container identifier.
        id: String,
    },
    /// Bounded logs.
    ContainerLogs {
        /// Requested container identifier.
        id: String,
    },
    /// Remove an owned container.
    ContainerDelete {
        /// Requested container identifier.
        id: String,
    },
    /// Create an exec in an owned container.
    ExecCreate {
        /// Parent container identifier.
        container_id: String,
    },
    /// Start/hijack an owned exec.
    ExecStart {
        /// Requested exec identifier.
        exec_id: String,
    },
    /// Inspect an owned exec.
    ExecInspect {
        /// Requested exec identifier.
        exec_id: String,
    },
    /// Bounded archive upload/download for an owned container.
    Archive {
        /// Requested container identifier.
        id: String,
        /// Exact normalized absolute path inside the container.
        path: String,
    },
    /// Runtime image pull. Phase 1 denies it.
    ImagePull,
    /// Runtime build. Phase 1 denies it.
    Build,
    /// Network/volume/Libpod and every other recognized unsafe family.
    ForbiddenFamily,
}

/// A classified Docker route and the sole normalized target permitted to reach
/// the upstream runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalRoute {
    /// Classified operation.
    pub route: DockerRoute,
    /// Unversioned, normalized origin-form target with canonical query order.
    pub target: String,
}

impl DockerRoute {
    /// Parse a versioned or unversioned origin-form Docker request target.
    pub fn parse(method: DockerMethod, target: &str) -> Result<Self, ProxyError> {
        Ok(Self::parse_canonical(method, target)?.route)
    }

    /// Parse a request and rebuild the only target which may be forwarded.
    pub fn parse_canonical(
        method: DockerMethod,
        target: &str,
    ) -> Result<CanonicalRoute, ProxyError> {
        let (raw_path, query) = target.split_once('?').unwrap_or((target, ""));
        let lower = raw_path.to_ascii_lowercase();
        if !target.starts_with('/')
            || target.starts_with("//")
            || raw_path[1..].contains("//")
            || (raw_path.len() > 1 && raw_path.ends_with('/'))
            || lower.replace("%3a", "").contains('%')
            || raw_path.contains('\\')
            || target.contains("/../")
            || target.contains("/./")
            || target.contains('#')
        {
            return Err(ProxyError::RouteRefused(
                "request target is not a normalized origin-form path".into(),
            ));
        }
        let path = strip_version(raw_path)?;
        let segments = path.trim_start_matches('/').split('/').collect::<Vec<_>>();
        let mut route = match (method, segments.as_slice()) {
            (DockerMethod::Get | DockerMethod::Head, ["_ping"]) => Self::Ping,
            (DockerMethod::Get, ["version"]) => Self::Version,
            (DockerMethod::Get, ["info"]) => Self::Info,
            (DockerMethod::Get, ["containers", "json"]) => Self::ContainerList,
            (DockerMethod::Get, ["images", image, "json"]) => Self::ImageInspect {
                image: image.to_ascii_lowercase().replace("%3a", ":"),
            },
            (DockerMethod::Get, ["volumes"]) => Self::VolumeList,
            (DockerMethod::Post, ["containers", "create"]) => Self::ContainerCreate,
            (DockerMethod::Get, ["containers", id, "json"]) => Self::ContainerInspect {
                id: validate_id(id)?,
            },
            (DockerMethod::Post, ["containers", id, "attach"]) => Self::ContainerAttach {
                id: validate_id(id)?,
            },
            (DockerMethod::Post, ["containers", id, "start"]) => Self::ContainerStart {
                id: validate_id(id)?,
            },
            (DockerMethod::Post, ["containers", id, "wait"]) => Self::ContainerWait {
                id: validate_id(id)?,
            },
            (DockerMethod::Get, ["containers", id, "logs"]) => Self::ContainerLogs {
                id: validate_id(id)?,
            },
            (DockerMethod::Delete, ["containers", id]) => Self::ContainerDelete {
                id: validate_id(id)?,
            },
            (DockerMethod::Post, ["containers", id, "exec"]) => Self::ExecCreate {
                container_id: validate_id(id)?,
            },
            (DockerMethod::Post, ["exec", id, "start"]) => Self::ExecStart {
                exec_id: validate_id(id)?,
            },
            (DockerMethod::Get, ["exec", id, "json"]) => Self::ExecInspect {
                exec_id: validate_id(id)?,
            },
            (DockerMethod::Get | DockerMethod::Put, ["containers", id, "archive"]) => {
                Self::Archive {
                    id: validate_id(id)?,
                    path: String::new(),
                }
            }
            (DockerMethod::Post, ["images", "create"]) => Self::ImagePull,
            (DockerMethod::Post, ["build"]) => Self::Build,
            (_, [family, ..])
                if matches!(
                    *family,
                    "libpod"
                        | "auth"
                        | "commit"
                        | "plugins"
                        | "secrets"
                        | "swarm"
                        | "services"
                        | "events"
                        | "system"
                        | "debug"
                        | "networks"
                        | "volumes"
                ) =>
            {
                Self::ForbiddenFamily
            }
            _ => {
                return Err(ProxyError::RouteRefused(
                    "method/path is not in the closed route table".into(),
                ));
            }
        };
        let canonical_query = canonical_query(&route, query)?;
        if let DockerRoute::Archive { path, .. } = &mut route {
            *path = url::form_urlencoded::parse(canonical_query.as_bytes())
                .find_map(|(key, value)| (key == "path").then(|| value.into_owned()))
                .ok_or_else(|| ProxyError::RouteRefused("archive path is required".into()))?;
        }
        let canonical_path = match &route {
            DockerRoute::ImageInspect { image } => {
                format!("/images/{}/json", image.replace(':', "%3A"))
            }
            _ => path.to_string(),
        };
        let target = if canonical_query.is_empty() {
            canonical_path
        } else {
            format!("{canonical_path}?{canonical_query}")
        };
        Ok(CanonicalRoute { route, target })
    }
}

fn strip_version(path: &str) -> Result<&str, ProxyError> {
    let Some(rest) = path.strip_prefix("/v") else {
        return Ok(path);
    };
    if !rest
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_digit())
    {
        return Ok(path);
    }
    let Some((version, remainder)) = rest.split_once('/') else {
        return Err(ProxyError::RouteRefused("malformed API version".into()));
    };
    let mut parts = version.split('.');
    let valid = parts
        .next()
        .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && parts.next().is_none();
    if !valid {
        return Err(ProxyError::RouteRefused("malformed API version".into()));
    }
    Ok(&path[path.len() - remainder.len() - 1..])
}

fn canonical_query(route: &DockerRoute, query: &str) -> Result<String, ProxyError> {
    let mut values = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if key.is_empty()
            || key.len() > 64
            || value.len() > 4096
            || values
                .insert(key.into_owned(), value.into_owned())
                .is_some()
            || values.len() > 32
        {
            return Err(ProxyError::RouteRefused(
                "query contains an invalid, duplicate, or oversized field".into(),
            ));
        }
    }
    let allowed: &[&str] = match route {
        DockerRoute::Ping | DockerRoute::Version | DockerRoute::Info => &[],
        DockerRoute::ContainerList => &["all", "before", "filters", "limit", "since", "size"],
        DockerRoute::ImageInspect { .. } | DockerRoute::VolumeList => &[],
        DockerRoute::ContainerCreate => &["name"],
        DockerRoute::ContainerInspect { .. } => &["size"],
        DockerRoute::ContainerAttach { .. } => {
            &["detachKeys", "logs", "stderr", "stdin", "stdout", "stream"]
        }
        DockerRoute::ContainerStart { .. } => &["detachKeys"],
        DockerRoute::ContainerWait { .. } => &["condition"],
        DockerRoute::ContainerLogs { .. } => &[
            "follow",
            "since",
            "stderr",
            "stdout",
            "tail",
            "timestamps",
            "until",
        ],
        DockerRoute::ContainerDelete { .. } => &["force", "link", "v"],
        DockerRoute::ExecCreate { .. } | DockerRoute::ExecStart { .. } => &["detachKeys"],
        DockerRoute::ExecInspect { .. } => &[],
        DockerRoute::Archive { .. } => &["path"],
        // These operations are always denied by policy. Parse their queries
        // only for duplicate/bounds safety so the denial is explicit.
        DockerRoute::ImagePull | DockerRoute::Build | DockerRoute::ForbiddenFamily => {
            return Ok(String::new());
        }
    };
    if values.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(ProxyError::RouteRefused(
            "query field is not admitted for this route".into(),
        ));
    }
    if matches!(route, DockerRoute::Archive { .. }) {
        if values.len() != 1 {
            return Err(ProxyError::RouteRefused(
                "archive requests require exactly one path".into(),
            ));
        }
        let path = values
            .get_mut("path")
            .ok_or_else(|| ProxyError::RouteRefused("archive path is required".into()))?;
        *path = normalize_archive_path(path)?;
    }
    for (key, value) in &values {
        match key.as_str() {
            "all" | "force" | "link" | "logs" | "size" | "stderr" | "stdin" | "stdout"
            | "stream" | "timestamps" | "v"
                if !matches!(value.as_str(), "0" | "1" | "false" | "true") =>
            {
                return Err(ProxyError::RouteRefused(format!(
                    "query field {key} must be boolean"
                )));
            }
            "condition" if value != "not-running" => {
                return Err(ProxyError::RouteRefused(
                    "only the stopped-state wait condition is supported".into(),
                ));
            }
            "follow" if !matches!(value.as_str(), "0" | "false") => {
                return Err(ProxyError::RouteRefused(
                    "unbounded log following is disabled".into(),
                ));
            }
            "tail" if value.parse::<u32>().map_or(true, |tail| tail > 10_000) => {
                return Err(ProxyError::RouteRefused(
                    "log tail exceeds the bounded maximum".into(),
                ));
            }
            "since" | "until" if value.parse::<i64>().is_err() => {
                return Err(ProxyError::RouteRefused(format!(
                    "query field {key} must be an integer timestamp"
                )));
            }
            "name" if validate_id(value).is_err() => {
                return Err(ProxyError::RouteRefused(
                    "container name is not canonical".into(),
                ));
            }
            _ => {}
        }
    }
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.extend_pairs(values.iter());
    Ok(serializer.finish())
}

fn normalize_archive_path(value: &str) -> Result<String, ProxyError> {
    use std::path::Component;

    if value.len() > 4096
        || value.contains('\\')
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(ProxyError::RouteRefused(
            "archive path is oversized or contains unsafe bytes".into(),
        ));
    }
    let path = std::path::Path::new(value);
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(ProxyError::RouteRefused(
            "archive path must be absolute".into(),
        ));
    }
    let mut normalized = String::new();
    for component in components {
        let Component::Normal(component) = component else {
            return Err(ProxyError::RouteRefused(
                "archive path must be canonical".into(),
            ));
        };
        let component = component
            .to_str()
            .ok_or_else(|| ProxyError::RouteRefused("archive path must be valid UTF-8".into()))?;
        normalized.push('/');
        normalized.push_str(component);
    }
    if normalized.is_empty() {
        normalized.push('/');
    }
    Ok(normalized)
}

fn validate_id(value: &str) -> Result<String, ProxyError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(ProxyError::RouteRefused("invalid object identifier".into()));
    }
    Ok(value.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versioned_and_unversioned_routes_are_identical() {
        let plain = DockerRoute::parse(DockerMethod::Post, "/containers/id/start").unwrap();
        let versioned =
            DockerRoute::parse(DockerMethod::Post, "/v1.47/containers/id/start").unwrap();
        assert_eq!(plain, versioned);
    }

    #[test]
    fn encoded_and_duplicate_query_bypasses_fail_closed() {
        for (method, target) in [
            (DockerMethod::Post, "/containers/a%2fstart"),
            (DockerMethod::Post, "/containers/a/../start"),
            (DockerMethod::Post, "/containers//a/start"),
            (DockerMethod::Get, "/containers/a/archive?path=/a&%70ath=/b"),
            (DockerMethod::Get, "http://docker/containers/json"),
        ] {
            assert!(
                DockerRoute::parse(method, target).is_err(),
                "accepted {target}"
            );
        }
    }

    #[test]
    fn forwarded_target_is_canonical_and_queries_are_bounded() {
        let parsed = DockerRoute::parse_canonical(
            DockerMethod::Get,
            "/v1.47/containers/id/logs?tail=10&stdout=true&follow=false",
        )
        .unwrap();
        assert_eq!(
            parsed.target,
            "/containers/id/logs?follow=false&stdout=true&tail=10"
        );
        assert!(
            DockerRoute::parse(DockerMethod::Get, "/containers/id/logs?follow=true&tail=10")
                .is_err()
        );
        assert!(DockerRoute::parse(
            DockerMethod::Get,
            "/containers/id/logs?follow=false&tail=all"
        )
        .is_err());
    }

    #[test]
    fn digest_image_inspect_allows_only_canonical_colon_encoding() {
        let digest = format!("sha256%3A{}", "a".repeat(64));
        let parsed = DockerRoute::parse_canonical(
            DockerMethod::Get,
            &format!("/v1.47/images/{digest}/json"),
        )
        .unwrap();
        assert_eq!(
            parsed.route,
            DockerRoute::ImageInspect {
                image: format!("sha256:{}", "a".repeat(64))
            }
        );
        assert_eq!(parsed.target, format!("/images/{digest}/json"));
        assert!(DockerRoute::parse(DockerMethod::Get, "/images/name%2Flatest/json").is_err());
    }

    #[test]
    fn unsafe_families_are_classified_not_forwarded_as_unknown() {
        for path in ["/libpod/images/json", "/networks/create", "/volumes/create"] {
            assert_eq!(
                DockerRoute::parse(DockerMethod::Post, path).unwrap(),
                DockerRoute::ForbiddenFamily
            );
        }
    }

    #[test]
    fn pinned_act_route_census_has_the_expected_closed_routes() {
        let census: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/act-v0.2.89-minimal-shell-routes.json"
        ))
        .unwrap();
        assert_eq!(census["act_version"], "v0.2.89");
        assert_eq!(census["source_audit_only"], true);

        let routes = census["routes"].as_array().unwrap();
        assert_eq!(routes.len(), 13);
        for route in routes {
            let method = DockerMethod::parse(route["method"].as_str().unwrap()).unwrap();
            let target = route["target"]
                .as_str()
                .unwrap()
                .replace("{digest}", &"c".repeat(64))
                .replace("{name}", "act-name")
                .replace("{container_id}", "container-one")
                .replace("{exec_id}", "exec-one")
                .replace("{path}", "%2Fworkspace");
            assert!(
                DockerRoute::parse(method, &target).is_ok(),
                "census route is missing from the closed parser: {method:?} {target}"
            );
        }

        assert_eq!(
            DockerRoute::parse(DockerMethod::Get, "/volumes").unwrap(),
            DockerRoute::VolumeList
        );
        assert_eq!(
            DockerRoute::parse(DockerMethod::Post, "/images/create").unwrap(),
            DockerRoute::ImagePull
        );
    }
}
