use dockerfile_sec_linter::config::Config;
use dockerfile_sec_linter::parser::DockerfileParser;
use dockerfile_sec_linter::rules::security::*;
use dockerfile_sec_linter::rules::Rule;

#[test]
fn test_sec001_missing_user_flagged() {
    let dockerfile = DockerfileParser::parse_str(
        r#"
FROM alpine:3.19
RUN apk add --no-cache curl
CMD ["sh"]
"#,
    )
    .unwrap();

    let rule = Sec001NonRootUser::new();
    let config = Config::default();
    let findings = rule.check(&dockerfile, &config);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "SEC001");
}

#[test]
fn test_sec001_explicit_root_flagged() {
    let dockerfile = DockerfileParser::parse_str(
        r#"
FROM alpine:3.19
USER root
CMD ["sh"]
"#,
    )
    .unwrap();

    let rule = Sec001NonRootUser::new();
    let config = Config::default();
    let findings = rule.check(&dockerfile, &config);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "SEC001");
    assert!(findings[0].message.contains("root"));
}

#[test]
fn test_sec001_non_root_user_passes() {
    let dockerfile = DockerfileParser::parse_str(
        r#"
FROM alpine:3.19
USER 10001:10001
CMD ["sh"]
"#,
    )
    .unwrap();

    let rule = Sec001NonRootUser::new();
    let config = Config::default();
    let findings = rule.check(&dockerfile, &config);

    assert!(findings.is_empty());
}

#[test]
fn test_sec002_unpinned_tags_flagged() {
    let dockerfile = DockerfileParser::parse_str(
        r#"
FROM ubuntu:latest
CMD ["bash"]
"#,
    )
    .unwrap();

    let rule = Sec002PinnedBaseImage::new();
    let config = Config::default();
    let findings = rule.check(&dockerfile, &config);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "SEC002");
}

#[test]
fn test_sec002_pinned_tags_pass() {
    let dockerfile = DockerfileParser::parse_str(
        r#"
FROM python:3.11.8-slim
CMD ["python"]
"#,
    )
    .unwrap();

    let rule = Sec002PinnedBaseImage::new();
    let config = Config::default();
    let findings = rule.check(&dockerfile, &config);

    assert!(findings.is_empty());
}

#[test]
fn test_sec002_multi_stage_alias_passes() {
    let dockerfile = DockerfileParser::parse_str(
        r#"
FROM golang:1.22-alpine AS builder
RUN go build -o /app

FROM builder AS tester
RUN /app test

FROM alpine:3.19
COPY --from=builder /app /app
USER appuser
CMD ["/app"]
"#,
    )
    .unwrap();

    let rule = Sec002PinnedBaseImage::new();
    let config = Config::default();
    let findings = rule.check(&dockerfile, &config);

    // Only real images are evaluated, builder stage alias is not flagged as unpinned
    assert!(findings.is_empty());
}

#[test]
fn test_sec003_hardcoded_secrets_flagged() {
    let dockerfile = DockerfileParser::parse_str(
        r#"
FROM alpine:3.19
ARG DB_PASSWORD="SuperSecretPassword123"
ENV API_KEY="mock_production_api_token_value_99887766"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
"#,
    )
    .unwrap();

    let rule = Sec003HardcodedSecrets::new();
    let config = Config::default();
    let findings = rule.check(&dockerfile, &config);

    assert_eq!(findings.len(), 3);
    for f in &findings {
        assert_eq!(f.rule_id, "SEC003");
    }
}

#[test]
fn test_sec003_placeholders_and_env_expansions_allowed() {
    let dockerfile = DockerfileParser::parse_str(
        r#"
FROM alpine:3.19
ARG DB_PASSWORD=""
ENV API_KEY="${APP_API_KEY}"
ARG SECRET_KEY="changeme"
"#,
    )
    .unwrap();

    let rule = Sec003HardcodedSecrets::new();
    let config = Config::default();
    let findings = rule.check(&dockerfile, &config);

    assert!(findings.is_empty());
}

#[test]
fn test_sec004_add_vs_copy() {
    let dockerfile = DockerfileParser::parse_str(
        r#"
FROM alpine:3.19
ADD script.py /app/script.py
ADD https://example.com/binary /usr/local/bin/binary
ADD bundle.tar.gz /app/
"#,
    )
    .unwrap();

    let rule = Sec004AvoidAdd::new();
    let config = Config::default();
    let findings = rule.check(&dockerfile, &config);

    // script.py (local file) and https:// (unverified remote) are flagged, bundle.tar.gz is allowed
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].rule_id, "SEC004");
    assert_eq!(findings[1].rule_id, "SEC004");
}

#[test]
fn test_sec005_sudo_usage() {
    let dockerfile = DockerfileParser::parse_str(
        r#"
FROM ubuntu:22.04
RUN sudo apt-get update && sudo apt-get install -y curl
"#,
    )
    .unwrap();

    let rule = Sec005NoSudo::new();
    let config = Config::default();
    let findings = rule.check(&dockerfile, &config);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "SEC005");
}
