use dockerfile_sec_linter::config::Config;
use dockerfile_sec_linter::engine::LinterEngine;
use dockerfile_sec_linter::parser::DockerfileParser;
use dockerfile_sec_linter::rules::cost::*;
use dockerfile_sec_linter::rules::Rule;
use std::collections::HashSet;
use std::path::PathBuf;

#[test]
fn test_cost001_bloated_base_image_flagged() {
    let dockerfile = DockerfileParser::parse_str(
        r#"
FROM ubuntu:22.04
CMD ["bash"]
"#,
    )
    .unwrap();

    let rule = Cost001BloatedBaseImage::new();
    let config = Config::default();
    let findings = rule.check(&dockerfile, &config);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "COST001");
}

#[test]
fn test_cost001_lean_base_image_passes() {
    let dockerfile = DockerfileParser::parse_str(
        r#"
FROM python:3.11-slim
CMD ["python"]
"#,
    )
    .unwrap();

    let rule = Cost001BloatedBaseImage::new();
    let config = Config::default();
    let findings = rule.check(&dockerfile, &config);

    assert!(findings.is_empty());
}

#[test]
fn test_cost001_multistage_builder_exempt() {
    let dockerfile = DockerfileParser::parse_str(
        r#"
# Heavyweight image in builder stage is permitted
FROM golang:1.22 AS builder
RUN go build -o /app

# Final stage uses lean alpine
FROM alpine:3.19
COPY --from=builder /app /app
CMD ["/app"]
"#,
    )
    .unwrap();

    let rule = Cost001BloatedBaseImage::new();
    let config = Config::default();
    let findings = rule.check(&dockerfile, &config);

    assert!(findings.is_empty());
}

#[test]
fn test_cost002_uncleaned_package_cache_flagged() {
    let dockerfile = DockerfileParser::parse_str(
        r#"
FROM alpine:3.19
RUN apt-get update && apt-get install -y curl
RUN apk add git
RUN pip install flask
"#,
    )
    .unwrap();

    let rule = Cost002CleanPackageCache::new();
    let config = Config::default();
    let findings = rule.check(&dockerfile, &config);

    assert_eq!(findings.len(), 3);
    for f in &findings {
        assert_eq!(f.rule_id, "COST002");
    }
}

#[test]
fn test_cost002_cleaned_package_cache_passes() {
    let dockerfile = DockerfileParser::parse_str(
        r#"
FROM alpine:3.19
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
RUN apk add --no-cache git
RUN pip install --no-cache-dir flask
"#,
    )
    .unwrap();

    let rule = Cost002CleanPackageCache::new();
    let config = Config::default();
    let findings = rule.check(&dockerfile, &config);

    assert!(findings.is_empty());
}

#[test]
fn test_cost003_consecutive_run_layers() {
    let dockerfile = DockerfileParser::parse_str(
        r#"
FROM alpine:3.19
RUN echo "one"
RUN echo "two"
RUN echo "three"
WORKDIR /app
RUN echo "four"
"#,
    )
    .unwrap();

    let rule = Cost003ChainRunLayers::new();
    let config = Config::default();
    let findings = rule.check(&dockerfile, &config);

    // echo "two" and echo "three" are consecutive RUNs
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].rule_id, "COST003");
    assert_eq!(findings[1].rule_id, "COST003");
}

#[test]
fn test_fixture_vulnerable_triggers_all_rules() {
    let fixture_path = PathBuf::from("tests/fixtures/Dockerfile.vulnerable");
    let config = Config::default();
    let engine = LinterEngine::new();

    let result = engine
        .lint_file(&fixture_path, &config)
        .expect("Lint file must succeed");

    let rule_ids: HashSet<String> = result.findings.iter().map(|f| f.rule_id.clone()).collect();

    // Verify all required security and cost rules are triggered
    assert!(rule_ids.contains("SEC001"), "SEC001 must be triggered");
    assert!(rule_ids.contains("SEC002"), "SEC002 must be triggered");
    assert!(rule_ids.contains("SEC003"), "SEC003 must be triggered");
    assert!(rule_ids.contains("SEC004"), "SEC004 must be triggered");
    assert!(rule_ids.contains("SEC005"), "SEC005 must be triggered");
    assert!(rule_ids.contains("COST001"), "COST001 must be triggered");
    assert!(rule_ids.contains("COST002"), "COST002 must be triggered");
    assert!(rule_ids.contains("COST003"), "COST003 must be triggered");

    assert!(
        result.score.total_score < 50,
        "Vulnerable score must be low"
    );
    assert_eq!(result.score.grade, "F");
}

#[test]
fn test_fixture_optimized_scores_100() {
    let fixture_path = PathBuf::from("tests/fixtures/Dockerfile.optimized");
    let config = Config::default();
    let engine = LinterEngine::new();

    let result = engine
        .lint_file(&fixture_path, &config)
        .expect("Lint file must succeed");

    assert!(
        result.findings.is_empty(),
        "Optimized Dockerfile should have 0 findings, got: {:?}",
        result
            .findings
            .iter()
            .map(|f| (&f.rule_id, &f.message))
            .collect::<Vec<_>>()
    );

    assert_eq!(result.score.total_score, 100);
    assert_eq!(result.score.security_score, 100);
    assert_eq!(result.score.cost_score, 100);
    assert_eq!(result.score.grade, "A+");
    assert!(!result.has_failure);
}
