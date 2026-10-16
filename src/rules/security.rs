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
/// SEC003: Hardcoded secrets or sensitive credentials in ENV or ARG
pub struct Sec003HardcodedSecrets {
    meta: RuleMetadata,
    sensitive_key_regex: Regex,
    value_secret_regex: Regex,
}

impl Sec003HardcodedSecrets {
    pub fn new() -> Self {
        Self {
            meta: RuleMetadata {
                id: "SEC003",
                name: "Hardcoded secret or credential",
                category: Category::Security,
                severity: Severity::Critical,
                description: "Hardcoded secrets in ENV or ARG instructions are permanently baked into container image layer metadata.",
                remediation: "Use BuildKit secrets mount (`RUN --mount=type=secret`) or inject environment variables at container runtime.",
            },
            sensitive_key_regex: Regex::new(
                r"(?i)(secret|password|passwd|api_key|apikey|auth_token|access_token|private_key|aws_access_key|aws_secret|client_secret|db_pass|ssh_key)"
            ).expect("Valid regex"),
            value_secret_regex: Regex::new(
                r"(?i)(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|xox[baprs]-[0-9a-zA-Z]{10,48}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
            ).expect("Valid regex"),
        }
    }

    fn is_placeholder(val: &str) -> bool {
        let trimmed = val.trim().trim_matches('"').trim_matches('\'');
        if trimmed.is_empty() {
            return true;
        }
        if trimmed.starts_with('$') || (trimmed.starts_with("${") && trimmed.ends_with('}')) {
            return true;
        }
        let lower = trimmed.to_lowercase();
        lower == "changeme"
            || lower == "dummy"
            || lower == "placeholder"
            || lower == "test"
            || lower == "todo"
            || lower == "none"
            || lower == "null"
            || lower == "false"
            || lower == "true"
            || lower == "example"
    }
}

impl Default for Sec003HardcodedSecrets {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for Sec003HardcodedSecrets {
    fn metadata(&self) -> &RuleMetadata {
        &self.meta
    }

    fn check(&self, dockerfile: &Dockerfile, _config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();

        for arg in &dockerfile.global_args {
            if let Some(default_val) = &arg.default_value {
                let key_matches = self.sensitive_key_regex.is_match(&arg.name);
                let val_matches = self.value_secret_regex.is_match(default_val);

                if (key_matches && !Self::is_placeholder(default_val)) || val_matches {
                    findings.push(Finding {
                        rule_id: self.meta.id.to_string(),
                        rule_name: self.meta.name.to_string(),
                        category: self.meta.category,
                        severity: self.meta.severity,
                        line_number: arg.line_number,
                        message: format!(
                            "Potentially hardcoded secret detected in global ARG '{}'",
                            arg.name
                        ),
                        remediation: self.meta.remediation.to_string(),
                        code_snippet: Some(arg.raw.clone()),
                        stage_index: 0,
                    });
                }
            }
        }

        for (stage_idx, stage) in dockerfile.stages.iter().enumerate() {
            for inst in &stage.instructions {
                match inst {
                    Instruction::Arg(arg) => {
                        if let Some(default_val) = &arg.default_value {
                            let key_matches = self.sensitive_key_regex.is_match(&arg.name);
                            let val_matches = self.value_secret_regex.is_match(default_val);

                            if (key_matches && !Self::is_placeholder(default_val)) || val_matches {
                                findings.push(Finding {
                                    rule_id: self.meta.id.to_string(),
                                    rule_name: self.meta.name.to_string(),
                                    category: self.meta.category,
                                    severity: self.meta.severity,
                                    line_number: arg.line_number,
                                    message: format!(
                                        "Potentially hardcoded secret detected in ARG '{}'",
                                        arg.name
                                    ),
                                    remediation: self.meta.remediation.to_string(),
                                    code_snippet: Some(arg.raw.clone()),
                                    stage_index: stage_idx,
                                });
                            }
                        }
                    }
                    Instruction::Env(env) => {
                        for (key, val) in &env.vars {
                            let key_matches = self.sensitive_key_regex.is_match(key);
                            let val_matches = self.value_secret_regex.is_match(val);

                            if (key_matches && !Self::is_placeholder(val)) || val_matches {
                                findings.push(Finding {
                                    rule_id: self.meta.id.to_string(),
                                    rule_name: self.meta.name.to_string(),
                                    category: self.meta.category,
                                    severity: self.meta.severity,
                                    line_number: env.line_number,
                                    message: format!(
                                        "Hardcoded sensitive secret or credential found in ENV variable '{}'",
                                        key
                                    ),
                                    remediation: self.meta.remediation.to_string(),
                                    code_snippet: Some(env.raw.clone()),
                                    stage_index: stage_idx,
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        findings
    }
}
