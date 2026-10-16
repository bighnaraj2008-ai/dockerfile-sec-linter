pub mod cost;
pub mod security;

use crate::ast::Dockerfile;
use crate::config::Config;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Category of linter rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Security,
    CostEfficiency,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Category::Security => write!(f, "Security"),
            Category::CostEfficiency => write!(f, "Cost Efficiency"),
        }
    }
}

/// Severity level of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl Severity {
    pub fn parse_str(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "low" => Some(Severity::Low),
            "medium" | "med" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" | "crit" => Some(Severity::Critical),
            _ => None,
        }
    }

    pub fn deduction(&self) -> u32 {
        match self {
            Severity::Low => 3,
            Severity::Medium => 8,
            Severity::High => 15,
            Severity::Critical => 25,
        }
    }
}

/// Static metadata describing a linter rule.
#[derive(Debug, Clone)]
pub struct RuleMetadata {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub category: Category,
    pub severity: Severity,
    pub remediation: &'static str,
}

/// A violation detected by a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub category: Category,
    pub severity: Severity,
    pub line_number: usize,
    pub message: String,
    pub remediation: String,
    pub code_snippet: Option<String>,
    pub stage_index: usize,
}

/// Interface that every linter rule must implement.
pub trait Rule: Send + Sync {
    /// Returns static metadata for the rule.
    fn metadata(&self) -> &RuleMetadata;

    /// Evaluates the rule against a parsed Dockerfile.
    fn check(&self, dockerfile: &Dockerfile, config: &Config) -> Vec<Finding>;
}

/// Returns a vector of all available rules.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        // Cloud Security rules
        Box::new(security::Sec001NonRootUser::new()),
        Box::new(security::Sec002PinnedBaseImage::new()),
        Box::new(security::Sec003HardcodedSecrets::new()),
        Box::new(security::Sec004AvoidAdd::new()),
        Box::new(security::Sec005NoSudo::new()),
        // Cloud Cost & Size optimization rules
        Box::new(cost::Cost001BloatedBaseImage::new()),
        Box::new(cost::Cost002CleanPackageCache::new()),
        Box::new(cost::Cost003ChainRunLayers::new()),
    ]
}
