use crate::ast::{Dockerfile, Instruction};
use crate::config::Config;
use crate::rules::{Category, Finding, Rule, RuleMetadata, Severity};
use regex::Regex;

/// COST001: Bloated base images in the final runtime stage
pub struct Cost001BloatedBaseImage {
    meta: RuleMetadata,
    bloated_regex: Regex,
    lean_regex: Regex,
}

impl Cost001BloatedBaseImage {
    pub fn new() -> Self {
        Self {
            meta: RuleMetadata {
                id: "COST001",
                name: "Bloated base image in runtime stage",
                category: Category::CostEfficiency,
                severity: Severity::Medium,
                description: "Full OS base images bloat container images by hundreds of megabytes, increasing network transfer, registry storage fees, and cold start latency.",
                remediation: "Switch the final runtime base image to a lean variant such as '-slim', '-alpine', or GoogleContainerTools 'distroless'.",
            },
            bloated_regex: Regex::new(
                r"(?i)(?:^|/)(ubuntu|debian|node|python|golang|openjdk|rust|amazonlinux|centos|fedora)(?::|$)"
            ).expect("Valid regex"),
            lean_regex: Regex::new(
                r"(?i)(slim|alpine|distroless|busybox|scratch|wolfi)"
            ).expect("Valid regex"),
        }
    }
}

impl Default for Cost001BloatedBaseImage {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for Cost001BloatedBaseImage {
    fn metadata(&self) -> &RuleMetadata {
        &self.meta
    }

    fn check(&self, dockerfile: &Dockerfile, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        let final_stage = match dockerfile.final_stage() {
            Some(s) => s,
            None => return findings,
        };
        let final_idx = dockerfile.stages.len() - 1;

        let prev_aliases: Vec<String> = dockerfile.stages[..final_idx]
            .iter()
            .filter_map(|s| s.alias.clone().or_else(|| s.from.alias.clone()))
            .collect();

        if prev_aliases.contains(&final_stage.from.image_name) {
            return findings;
        }

        if config
            .allowed_base_images
            .iter()
            .any(|allowed| final_stage.from.full_image.contains(allowed))
        {
            return findings;
        }

        if final_stage.from.image_name == "scratch" {
            return findings;
        }

        let full_img = &final_stage.from.full_image;
        let is_bloated_candidate = self.bloated_regex.is_match(full_img);
        let has_lean_tag = self.lean_regex.is_match(full_img);

        if is_bloated_candidate && !has_lean_tag {
            findings.push(Finding {
                rule_id: self.meta.id.to_string(),
                rule_name: self.meta.name.to_string(),
                category: self.meta.category,
                severity: self.meta.severity,
                line_number: final_stage.from.line_number,
                message: format!(
                    "Runtime stage uses heavyweight base image '{}' instead of a lightweight variant",
                    full_img
                ),
                remediation: self.meta.remediation.to_string(),
                code_snippet: Some(final_stage.from.raw.clone()),
                stage_index: final_idx,
            });
        }

        findings
    }
}
