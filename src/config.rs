use crate::error::{LinterError, Result};
use crate::rules::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Configuration options for the linter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// List of rule IDs to ignore (e.g. `["COST003", "SEC004"]`)
    #[serde(default)]
    pub ignore_rules: Vec<String>,

    /// Minimum finding severity threshold to report
    #[serde(default = "default_min_severity")]
    pub min_severity: Severity,

    /// Minimum passing score (0-100). If total score drops below this, exit failure.
    pub min_score: Option<u32>,

    /// Severity threshold to trigger a non-zero exit code (e.g. "high")
    pub fail_on: Option<Severity>,

    /// When true, non-root USER enforcement is only checked for the final stage
    #[serde(default = "default_allow_root_build_stages")]
    pub allow_root_in_build_stages: bool,

    /// Whitelisted base images or prefixes that should not be flagged as bloated
    #[serde(default)]
    pub allowed_base_images: Vec<String>,
}

fn default_min_severity() -> Severity {
    Severity::Low
}

fn default_allow_root_build_stages() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ignore_rules: Vec::new(),
            min_severity: Severity::Low,
            min_score: None,
            fail_on: None,
            allow_root_in_build_stages: true,
            allowed_base_images: Vec::new(),
        }
    }
}

impl Config {
    /// Loads configuration from a TOML file.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let p = path.as_ref();
        let content = std::fs::read_to_string(p).map_err(|e| LinterError::Config {
            path: p.to_path_buf(),
            message: format!("Could not read config file: {}", e),
        })?;

        toml::from_str(&content).map_err(|e| LinterError::Config {
            path: p.to_path_buf(),
            message: format!("Invalid TOML format: {}", e),
        })
    }

    /// Automatically discovers `.dockerlint.toml` in the current directory or workspace.
    pub fn discover() -> Self {
        let candidate = PathBuf::from(".dockerlint.toml");
        if candidate.exists() {
            Self::load_from_file(&candidate).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    /// Checks if a given rule ID is ignored.
    pub fn is_rule_ignored(&self, rule_id: &str) -> bool {
        let set: HashSet<String> = self
            .ignore_rules
            .iter()
            .map(|r| r.trim().to_uppercase())
            .collect();
        set.contains(&rule_id.to_uppercase())
    }
}
