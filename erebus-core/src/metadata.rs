//! Metadata structures for .erebus files.
//!
//! Contains configuration for embedded runtimes, build caching, and health checks.
//!
//! NOTE: the on-disk artifact metadata JSON is produced by
//! `crate::assembly::build_meta_json` as a raw `serde_json::Value`; the types
//! here are the shared config/build-time structures, not the artifact format.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub port: u16,
    pub endpoint: String,
    pub enabled: bool,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            port: 0,
            endpoint: "/health".to_string(),
            enabled: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::derivable_impls)]
pub struct BuildCacheConfig {
    pub enabled: bool,
    pub max_entries: usize,
    pub ttl_hours: Option<u64>,
}

#[allow(clippy::derivable_impls)]
impl Default for BuildCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 50,
            ttl_hours: Some(24),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EmbeddedRuntimeConfig {
    pub interpreter: Option<EmbeddedInterpreter>,
    pub interpreter_path: Option<String>,
    pub runtime_cache: Option<String>,
    pub runtime_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::derivable_impls)]
pub struct BunFeatures {
    pub embedded_runtime: EmbeddedRuntimeConfig,
    pub build_cache: BuildCacheConfig,
    pub health_check: HealthCheck,
    pub cross_compile_targets: Vec<String>,
}

#[allow(clippy::derivable_impls)]
impl Default for BunFeatures {
    fn default() -> Self {
        Self {
            embedded_runtime: EmbeddedRuntimeConfig::default(),
            build_cache: BuildCacheConfig::default(),
            health_check: HealthCheck::default(),
            cross_compile_targets: Vec::new(),
        }
    }
}

impl BunFeatures {
    #[must_use]
    pub fn with_embedded_runtime(mut self, interpreter: EmbeddedInterpreter) -> Self {
        self.embedded_runtime.interpreter = Some(interpreter);
        self
    }

    #[must_use]
    pub fn with_health_check(mut self, port: u16, endpoint: Option<String>) -> Self {
        self.health_check.enabled = true;
        self.health_check.port = port;
        if let Some(ep) = endpoint {
            self.health_check.endpoint = ep;
        }
        self
    }

    #[must_use]
    pub fn with_cross_compile(mut self, targets: Vec<String>) -> Self {
        self.cross_compile_targets = targets;
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        if let Some(EmbeddedInterpreter::Custom(path)) = &self.embedded_runtime.interpreter {
            if path.is_empty() {
                return Err("Custom interpreter path cannot be empty".to_string());
            }
            let path = std::path::Path::new(path);
            if path.exists() && !std::fs::metadata(path).map(|m| m.is_file()).unwrap_or(true) {
                return Err(format!(
                    "Custom interpreter path is not a file: {}",
                    path.display()
                ));
            }
        }

        if self.health_check.enabled {
            if self.health_check.port == 0 {
                return Err(
                    "Health check port cannot be 0 - specify a valid port (1-65535)".to_string(),
                );
            }
            if self.health_check.endpoint.is_empty() {
                return Err("Health check endpoint cannot be empty".to_string());
            }
            if !self.health_check.endpoint.starts_with('/') {
                return Err(format!(
                    "Health check endpoint must start with '/': {}",
                    self.health_check.endpoint
                ));
            }
        }

        if self.build_cache.enabled && self.build_cache.max_entries > 1000 {
            return Err(format!("Build cache max_entries {} is too high - use 1000 or less to prevent memory issues", self.build_cache.max_entries));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EmbeddedInterpreter {
    Python3,
    Custom(String),
}

impl std::fmt::Display for EmbeddedInterpreter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmbeddedInterpreter::Python3 => write!(f, "python3"),
            EmbeddedInterpreter::Custom(p) => write!(f, "{p}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CryptoMeta {
    pub nonce_hex: String,
    pub tag_offset: usize,
    pub encryption_key_hex: String,
    pub encryption_salt_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum ArtifactState {
    #[default]
    Acquired,
    Quarantined,
    Trusted,
    Revoked,
    Deleted,
}

impl std::fmt::Display for ArtifactState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Acquired => "Acquired",
            Self::Quarantined => "Quarantined",
            Self::Trusted => "Trusted",
            Self::Revoked => "Revoked",
            Self::Deleted => "Deleted",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArtifactPolicy {
    pub allow_untrusted: bool,
    pub require_signature: bool,
    pub max_retries: u32,
}

impl ArtifactState {
    /**
     * `can_transition` - validate a lifecycle state transition
     * @next: the state the artifact is attempting to move to
     *
     * Description: enforces the closed state machine:
     * `Acquired -> Quarantined -> Trusted -> Revoked`, with `Deleted`
     * terminal. Once an artifact is `Revoked` it can only be `Deleted`;
     * a `Deleted` artifact can never change again.
     *
     * Return: true iff the transition from self to `next` is allowed.
     */
    #[must_use]
    pub fn can_transition(&self, next: &ArtifactState) -> bool {
        match self {
            ArtifactState::Acquired => matches!(
                next,
                ArtifactState::Quarantined
                    | ArtifactState::Trusted
                    | ArtifactState::Revoked
                    | ArtifactState::Deleted
            ),
            ArtifactState::Quarantined => matches!(
                next,
                ArtifactState::Trusted | ArtifactState::Revoked | ArtifactState::Deleted
            ),
            ArtifactState::Trusted => matches!(
                next,
                ArtifactState::Revoked | ArtifactState::Quarantined | ArtifactState::Deleted
            ),
            ArtifactState::Revoked => matches!(next, ArtifactState::Deleted),
            ArtifactState::Deleted => false,
        }
    }

    /**
     * `is_servable` - whether an artifact in this state may be served/executed
     *
     * Description: only `Acquired` and `Trusted` artifacts may leave the
     * registry or be run by the stub. `Quarantined`, `Revoked` and `Deleted`
     * are refused.
     *
     * Return: true iff the state is `Acquired` or `Trusted`.
     */
    #[must_use]
    pub fn is_servable(&self) -> bool {
        matches!(self, ArtifactState::Acquired | ArtifactState::Trusted)
    }

    /**
     * `is_terminal` - whether this state is permanently unrecoverable
     *
     * Description: only `Deleted` is terminal. A terminal artifact cannot
     * undergo any further state change.
     *
     * Return: true iff the state is `Deleted`.
     */
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, ArtifactState::Deleted)
    }
}

/// Errors that can occur during lifecycle state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleError {
    InvalidTransition,
    AlreadyInState,
    TerminalState,
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTransition => write!(f, "invalid lifecycle state transition"),
            Self::AlreadyInState => write!(f, "artifact is already in the requested state"),
            Self::TerminalState => write!(f, "artifact is in a terminal state and cannot change"),
        }
    }
}

impl std::error::Error for LifecycleError {}

/**
 * transition - perform a lifecycle state transition
 * @current: the artifact's present state
 * @target: the requested destination state
 * @_policy: owning artifact policy (reserved; auth is enforced by the
 *           CLI/registry layers)
 *
 * Description: returns the new state when the transition is legal, enforcing
 * only the closed state machine. Authorization — who is allowed to revoke or
 * delete — is a separate concern handled by the caller's policy layer, not by
 * retry budgets or this function.
 *
 * Return: `Ok(new_state)` on success; `LifecycleError::AlreadyInState` if
 * `current == target`, `LifecycleError::TerminalState` if `current` is
 * `Deleted`, `LifecycleError::InvalidTransition` if the move is illegal.
 */
pub fn transition(
    current: &ArtifactState,
    target: &ArtifactState,
    _policy: &ArtifactPolicy,
) -> Result<ArtifactState, LifecycleError> {
    if current == target {
        return Err(LifecycleError::AlreadyInState);
    }
    if current.is_terminal() {
        return Err(LifecycleError::TerminalState);
    }
    if !current.can_transition(target) {
        return Err(LifecycleError::InvalidTransition);
    }
    Ok(target.clone())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub command: Vec<String>,
    pub env: std::collections::BTreeMap<String, String>,
    pub health_check: Option<HealthCheck>,
    pub restart: RestartPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum RestartPolicy {
    #[default]
    Never,
    OnFailure,
    Always,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_interpreter_display() {
        assert_eq!(EmbeddedInterpreter::Python3.to_string(), "python3");
        assert_eq!(
            EmbeddedInterpreter::Custom("/path/to/bin".into()).to_string(),
            "/path/to/bin"
        );
    }

    #[test]
    fn health_check_defaults() {
        let hc = HealthCheck::default();
        assert_eq!(hc.port, 0);
        assert_eq!(hc.endpoint, "/health");
        assert!(!hc.enabled);
    }

    #[test]
    fn build_cache_defaults() {
        let bc = BuildCacheConfig::default();
        assert!(bc.enabled);
        assert_eq!(bc.max_entries, 50);
        assert_eq!(bc.ttl_hours, Some(24));
    }

    #[test]
    fn artifact_state_transitions_are_valid() {
        assert!(ArtifactState::Acquired.can_transition(&ArtifactState::Quarantined));
        assert!(ArtifactState::Acquired.can_transition(&ArtifactState::Trusted));
        assert!(ArtifactState::Acquired.can_transition(&ArtifactState::Revoked));
        assert!(ArtifactState::Acquired.can_transition(&ArtifactState::Deleted));
        assert!(ArtifactState::Quarantined.can_transition(&ArtifactState::Trusted));
        assert!(ArtifactState::Quarantined.can_transition(&ArtifactState::Revoked));
        assert!(ArtifactState::Trusted.can_transition(&ArtifactState::Revoked));
        assert!(ArtifactState::Trusted.can_transition(&ArtifactState::Quarantined));
        assert!(ArtifactState::Revoked.can_transition(&ArtifactState::Deleted));
    }

    #[test]
    fn artifact_state_invalid_transitions_are_rejected() {
        assert!(!ArtifactState::Revoked.can_transition(&ArtifactState::Trusted));
        assert!(!ArtifactState::Deleted.can_transition(&ArtifactState::Acquired));
        assert!(!ArtifactState::Deleted.can_transition(&ArtifactState::Trusted));
        assert!(!ArtifactState::Deleted.can_transition(&ArtifactState::Quarantined));
    }

    #[test]
    fn artifact_state_servable() {
        assert!(ArtifactState::Acquired.is_servable());
        assert!(ArtifactState::Trusted.is_servable());
        assert!(!ArtifactState::Quarantined.is_servable());
        assert!(!ArtifactState::Revoked.is_servable());
        assert!(!ArtifactState::Deleted.is_servable());
    }

    #[test]
    fn artifact_state_terminal() {
        assert!(ArtifactState::Deleted.is_terminal());
        assert!(!ArtifactState::Acquired.is_terminal());
        assert!(!ArtifactState::Trusted.is_terminal());
        assert!(!ArtifactState::Revoked.is_terminal());
    }

    #[test]
    fn transition_acquired_to_trusted_ok() {
        let policy = ArtifactPolicy::default();
        let state = transition(&ArtifactState::Acquired, &ArtifactState::Trusted, &policy).unwrap();
        assert_eq!(state, ArtifactState::Trusted);
    }

    #[test]
    fn transition_quarantine_to_trusted_ok() {
        let policy = ArtifactPolicy::default();
        let state = transition(
            &ArtifactState::Quarantined,
            &ArtifactState::Trusted,
            &policy,
        )
        .unwrap();
        assert_eq!(state, ArtifactState::Trusted);
    }

    #[test]
    fn transition_trusted_to_revoked_ok() {
        let policy = ArtifactPolicy::default();
        let state = transition(&ArtifactState::Trusted, &ArtifactState::Revoked, &policy).unwrap();
        assert_eq!(state, ArtifactState::Revoked);
    }

    #[test]
    fn transition_revoked_to_trusted_fails_closed() {
        let policy = ArtifactPolicy::default();
        let err =
            transition(&ArtifactState::Revoked, &ArtifactState::Trusted, &policy).unwrap_err();
        assert_eq!(err, LifecycleError::InvalidTransition);
    }

    #[test]
    fn transition_same_state_fails() {
        let policy = ArtifactPolicy::default();
        let err =
            transition(&ArtifactState::Trusted, &ArtifactState::Trusted, &policy).unwrap_err();
        assert_eq!(err, LifecycleError::AlreadyInState);
    }

    #[test]
    fn transition_terminal_state_fails() {
        let policy = ArtifactPolicy::default();
        let err =
            transition(&ArtifactState::Deleted, &ArtifactState::Acquired, &policy).unwrap_err();
        assert_eq!(err, LifecycleError::TerminalState);
    }

    #[test]
    fn transition_to_deleted_ok() {
        let policy = ArtifactPolicy::default();
        let state = transition(&ArtifactState::Trusted, &ArtifactState::Deleted, &policy).unwrap();
        assert_eq!(state, ArtifactState::Deleted);
    }

    #[test]
    fn lifecycle_error_display() {
        assert_eq!(
            LifecycleError::InvalidTransition.to_string(),
            "invalid lifecycle state transition"
        );
        assert_eq!(
            LifecycleError::AlreadyInState.to_string(),
            "artifact is already in the requested state"
        );
        assert_eq!(
            LifecycleError::TerminalState.to_string(),
            "artifact is in a terminal state and cannot change"
        );
    }
}
