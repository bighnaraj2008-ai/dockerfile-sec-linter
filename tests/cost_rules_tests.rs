use dockerfile_sec_linter::config::Config;
use dockerfile_sec_linter::parser::DockerfileParser;
use dockerfile_sec_linter::rules::cost::*;
use dockerfile_sec_linter::rules::Rule;

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
FROM golang:1.22 AS builder
RUN go build -o /app

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
