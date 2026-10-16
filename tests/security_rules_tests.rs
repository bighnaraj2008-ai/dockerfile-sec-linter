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
