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
impl Rule for Sec001NonRootUser {
    fn metadata(&self) -> &RuleMetadata {
        &self.meta
    }

    fn check(&self, dockerfile: &Dockerfile, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        if dockerfile.stages.is_empty() {
            return findings;
        }

        let stages_to_check: Vec<(usize, &crate::ast::Stage)> = if config.allow_root_in_build_stages {
            if let Some(final_stage) = dockerfile.final_stage() {
                vec![(dockerfile.stages.len() - 1, final_stage)]
            } else {
                vec![]
            }
        } else {
            dockerfile.stages.iter().enumerate().collect()
        };

        for (stage_idx, stage) in stages_to_check {
            let last_user = stage.last_user();
            match last_user {
                None => {
                    let line_number = stage.from.line_number;
                    findings.push(Finding {
                        rule_id: self.meta.id.to_string(),
                        rule_name: self.meta.name.to_string(),
                        category: self.meta.category,
                        severity: self.meta.severity,
                        line_number,
                        message: format!(
                            "Build stage {} (base image '{}') does not specify a non-root USER instruction",
                            stage.alias.as_deref().unwrap_or("<runtime>"),
                            stage.from.image_name
                        ),
                        remediation: self.meta.remediation.to_string(),
                        code_snippet: Some(stage.from.raw.clone()),
                        stage_index: stage_idx,
                    });
                }
                Some(user_inst) if user_inst.is_root() => {
                    findings.push(Finding {
                        rule_id: self.meta.id.to_string(),
                        rule_name: self.meta.name.to_string(),
                        category: self.meta.category,
                        severity: self.meta.severity,
                        line_number: user_inst.line_number,
                        message: format!(
                            "USER instruction explicitly specifies root user ('{}')",
                            user_inst.user
                        ),
                        remediation: self.meta.remediation.to_string(),
                        code_snippet: Some(user_inst.raw.clone()),
                        stage_index: stage_idx,
                    });
                }
                _ => {}
            }
        }

        findings
    }
}
/// SEC002: Unpinned base image tag (:latest or untagged)
pub struct Sec002PinnedBaseImage {
    meta: RuleMetadata,
}

impl Sec002PinnedBaseImage {
    pub fn new() -> Self {
        Self {
            meta: RuleMetadata {
                id: "SEC002",
                name: "Unpinned base image tag",
                category: Category::Security,
                severity: Severity::High,
                description: "Using ':latest' or omitting base image tags produces non-deterministic builds and risks supply chain vulnerabilities.",
                remediation: "Pin base image tag to an immutable sha256 digest or a specific release version (e.g. 'node:20.11-alpine').",
            },
        }
    }
}

impl Default for Sec002PinnedBaseImage {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for Sec002PinnedBaseImage {
    fn metadata(&self) -> &RuleMetadata {
        &self.meta
    }

    fn check(&self, dockerfile: &Dockerfile, _config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (stage_idx, stage) in dockerfile.stages.iter().enumerate() {
            let prev_aliases: Vec<String> = dockerfile.stages[..stage_idx]
                .iter()
                .filter_map(|s| s.alias.clone().or_else(|| s.from.alias.clone()))
                .collect();

            if prev_aliases.contains(&stage.from.image_name) {
                continue;
            }

            if stage.from.image_name == "scratch" {
                continue;
            }

            if !stage.from.is_pinned() {
                findings.push(Finding {
                    rule_id: self.meta.id.to_string(),
                    rule_name: self.meta.name.to_string(),
                    category: self.meta.category,
                    severity: self.meta.severity,
                    line_number: stage.from.line_number,
                    message: format!(
                        "Base image '{}' is unpinned (missing tag or using ':latest')",
                        stage.from.full_image
                    ),
                    remediation: self.meta.remediation.to_string(),
                    code_snippet: Some(stage.from.raw.clone()),
                    stage_index: stage_idx,
                });
            }
        }

        findings
    }
}
