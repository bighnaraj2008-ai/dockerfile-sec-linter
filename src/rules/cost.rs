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

        // Stage alias exemption: check if final stage is built from an earlier stage
        let prev_aliases: Vec<String> = dockerfile.stages[..final_idx]
            .iter()
            .filter_map(|s| s.alias.clone().or_else(|| s.from.alias.clone()))
            .collect();

        if prev_aliases.contains(&final_stage.from.image_name) {
            return findings;
        }

        // Whitelisted images
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

/// COST002: Package manager cache not cleaned in the same RUN layer
pub struct Cost002CleanPackageCache {
    meta: RuleMetadata,
    apt_install_regex: Regex,
    apt_clean_regex: Regex,
    apt_no_recommends_regex: Regex,
    apk_add_regex: Regex,
    apk_clean_regex: Regex,
    pip_install_regex: Regex,
    pip_cache_regex: Regex,
    yum_install_regex: Regex,
    yum_clean_regex: Regex,
}

impl Cost002CleanPackageCache {
    pub fn new() -> Self {
        Self {
            meta: RuleMetadata {
                id: "COST002",
                name: "Package manager cache not cleaned",
                category: Category::CostEfficiency,
                severity: Severity::Medium,
                description: "Package manager index files and downloaded archives remain inside image layers, wasting storage and bandwidth.",
                remediation: "Add cache cleanup in the same RUN layer (e.g. `&& rm -rf /var/lib/apt/lists/*`, `--no-cache`, or `--no-cache-dir`).",
            },
            apt_install_regex: Regex::new(r"(?i)\b(apt-get|apt)\s+install\b").expect("Valid regex"),
            apt_clean_regex: Regex::new(r"(?i)rm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+/var/lib/apt/lists").expect("Valid regex"),
            apt_no_recommends_regex: Regex::new(r"(?i)--no-install-recommends").expect("Valid regex"),

            apk_add_regex: Regex::new(r"(?i)\bapk\s+add\b").expect("Valid regex"),
            apk_clean_regex: Regex::new(r"(?i)(--no-cache|rm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+/var/cache/apk)").expect("Valid regex"),

            pip_install_regex: Regex::new(r"(?i)\b(pip|pip3)\s+install\b").expect("Valid regex"),
            pip_cache_regex: Regex::new(r"(?i)--no-cache-dir").expect("Valid regex"),

            yum_install_regex: Regex::new(r"(?i)\b(yum|dnf)\s+install\b").expect("Valid regex"),
            yum_clean_regex: Regex::new(r"(?i)(yum|dnf)\s+clean\s+all").expect("Valid regex"),
        }
    }
}

impl Default for Cost002CleanPackageCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for Cost002CleanPackageCache {
    fn metadata(&self) -> &RuleMetadata {
        &self.meta
    }

    fn check(&self, dockerfile: &Dockerfile, _config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (stage_idx, stage) in dockerfile.stages.iter().enumerate() {
            for inst in &stage.instructions {
                if let Instruction::Run(run) = inst {
                    let cmd = &run.command;

                    // Check APT
                    if self.apt_install_regex.is_match(cmd) {
                        let has_clean = self.apt_clean_regex.is_match(cmd);
                        let has_no_recommends = self.apt_no_recommends_regex.is_match(cmd);

                        if !has_clean || !has_no_recommends {
                            let mut issues = Vec::new();
                            if !has_no_recommends {
                                issues.push("missing '--no-install-recommends'");
                            }
                            if !has_clean {
                                issues.push("missing cache cleanup 'rm -rf /var/lib/apt/lists/*'");
                            }

                            findings.push(Finding {
                                rule_id: self.meta.id.to_string(),
                                rule_name: self.meta.name.to_string(),
                                category: self.meta.category,
                                severity: self.meta.severity,
                                line_number: run.line_number,
                                message: format!("apt-get install in RUN layer: {}", issues.join(" and ")),
                                remediation: "Add '--no-install-recommends' and chain '&& rm -rf /var/lib/apt/lists/*' to prevent caching apt indexes in image layers.".to_string(),
                                code_snippet: Some(run.raw.clone()),
                                stage_index: stage_idx,
                            });
                        }
                    }

                    // Check APK
                    if self.apk_add_regex.is_match(cmd) && !self.apk_clean_regex.is_match(cmd) {
                        findings.push(Finding {
                            rule_id: self.meta.id.to_string(),
                            rule_name: self.meta.name.to_string(),
                            category: self.meta.category,
                            severity: self.meta.severity,
                            line_number: run.line_number,
                            message: "apk add missing '--no-cache' flag".to_string(),
                            remediation: "Use 'apk add --no-cache <packages>' to avoid persisting the package index on disk.".to_string(),
                            code_snippet: Some(run.raw.clone()),
                            stage_index: stage_idx,
                        });
                    }

                    // Check PIP
                    if self.pip_install_regex.is_match(cmd) && !self.pip_cache_regex.is_match(cmd) {
                        findings.push(Finding {
                            rule_id: self.meta.id.to_string(),
                            rule_name: self.meta.name.to_string(),
                            category: self.meta.category,
                            severity: self.meta.severity,
                            line_number: run.line_number,
                            message: "pip install missing '--no-cache-dir' flag".to_string(),
                            remediation: "Use 'pip install --no-cache-dir ...' to prevent wheel and tarball caching in Docker layers.".to_string(),
                            code_snippet: Some(run.raw.clone()),
                            stage_index: stage_idx,
                        });
                    }

                    // Check YUM / DNF
                    if self.yum_install_regex.is_match(cmd) && !self.yum_clean_regex.is_match(cmd) {
                        findings.push(Finding {
                            rule_id: self.meta.id.to_string(),
                            rule_name: self.meta.name.to_string(),
                            category: self.meta.category,
                            severity: self.meta.severity,
                            line_number: run.line_number,
                            message: "yum/dnf install without 'clean all'".to_string(),
                            remediation: "Chain '&& yum clean all && rm -rf /var/cache/yum' in the same RUN layer.".to_string(),
                            code_snippet: Some(run.raw.clone()),
                            stage_index: stage_idx,
                        });
                    }
                }
            }
        }

        findings
    }
}

/// COST003: Consecutive RUN instructions that should be combined with &&
pub struct Cost003ChainRunLayers {
    meta: RuleMetadata,
}

impl Cost003ChainRunLayers {
    pub fn new() -> Self {
        Self {
            meta: RuleMetadata {
                id: "COST003",
                name: "Consecutive RUN instructions not chained",
                category: Category::CostEfficiency,
                severity: Severity::Low,
                description: "Consecutive RUN instructions generate separate image layers and disk write operations, increasing total image size.",
                remediation: "Combine consecutive RUN instructions into a single RUN layer using '&& \\'.",
            },
        }
    }
}

impl Default for Cost003ChainRunLayers {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for Cost003ChainRunLayers {
    fn metadata(&self) -> &RuleMetadata {
        &self.meta
    }

    fn check(&self, dockerfile: &Dockerfile, _config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (stage_idx, stage) in dockerfile.stages.iter().enumerate() {
            let mut previous_was_run = false;

            for inst in &stage.instructions {
                match inst {
                    Instruction::Run(run) => {
                        if previous_was_run {
                            findings.push(Finding {
                                rule_id: self.meta.id.to_string(),
                                rule_name: self.meta.name.to_string(),
                                category: self.meta.category,
                                severity: self.meta.severity,
                                line_number: run.line_number,
                                message: "Consecutive RUN instruction creates an unnecessary filesystem layer".to_string(),
                                remediation: self.meta.remediation.to_string(),
                                code_snippet: Some(run.raw.clone()),
                                stage_index: stage_idx,
                            });
                        }
                        previous_was_run = true;
                    }
                    _ => {
                        previous_was_run = false;
                    }
                }
            }
        }

        findings
    }
}
