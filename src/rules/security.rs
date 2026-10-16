use crate::ast::{Dockerfile, Instruction};
use crate::config::Config;
use crate::rules::{Category, Finding, Rule, RuleMetadata, Severity};
use regex::Regex;

/// SEC001: Missing USER instruction or final USER set to root
pub struct Sec001NonRootUser {
    meta: RuleMetadata,
}

impl Sec001NonRootUser {
    pub fn new() -> Self {
        Self {
            meta: RuleMetadata {
                id: "SEC001",
                name: "Container running as root user",
                category: Category::Security,
                severity: Severity::High,
                description: "Running containers as root grants attackers elevated host or container privileges if compromised.",
                remediation: "Define and switch to a non-root USER (e.g., `USER appuser` or `USER 10001:10001`) in the final build stage.",
            },
        }
    }
}

impl Default for Sec001NonRootUser {
    fn default() -> Self {
        Self::new()
    }
}
