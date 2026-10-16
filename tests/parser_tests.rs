use dockerfile_sec_linter::ast::Instruction;
use dockerfile_sec_linter::parser::DockerfileParser;

#[test]
fn test_parse_multiline_continuation() {
    let dockerfile_content = r#"
FROM alpine:3.19
RUN apk update && \
    apk add --no-cache \
    curl \
    git
CMD ["sh"]
"#;

    let df = DockerfileParser::parse_str(dockerfile_content).expect("Valid Dockerfile");
    assert_eq!(df.stages.len(), 1);

    let stage = &df.stages[0];
    let run_inst = stage
        .instructions
        .iter()
        .find_map(|i| match i {
            Instruction::Run(r) => Some(r),
            _ => None,
        })
        .expect("RUN instruction present");

    assert_eq!(run_inst.line_number, 3);
    assert!(run_inst.command.contains("apk update"));
    assert!(run_inst.command.contains("curl"));
    assert!(run_inst.command.contains("git"));
}

#[test]
fn test_parse_comments_and_empty_lines() {
    let dockerfile_content = r#"
# Header comment
# Another comment

FROM python:3.11-slim

# Inline comment
WORKDIR /app

# Final comment
CMD ["python", "app.py"]
"#;

    let df = DockerfileParser::parse_str(dockerfile_content).expect("Valid Dockerfile");
    assert_eq!(df.stages.len(), 1);

    let stage = &df.stages[0];
    assert_eq!(stage.from.image_name, "python");
    assert_eq!(stage.from.tag.as_deref(), Some("3.11-slim"));
    assert_eq!(stage.from.line_number, 5);
}

#[test]
fn test_parse_multi_stage_and_aliases() {
    let dockerfile_content = r#"
ARG GLOBAL_VER=1.20
FROM golang:1.22-alpine AS builder
WORKDIR /src
RUN go build -o /app

FROM alpine:3.19 AS runner
COPY --from=builder /app /app
USER 1000:1000
ENTRYPOINT ["/app"]
"#;

    let df = DockerfileParser::parse_str(dockerfile_content).expect("Valid Dockerfile");
    assert_eq!(df.global_args.len(), 1);
    assert_eq!(df.global_args[0].name, "GLOBAL_VER");
    assert_eq!(df.global_args[0].default_value.as_deref(), Some("1.20"));

    assert_eq!(df.stages.len(), 2);
    assert_eq!(df.stages[0].alias.as_deref(), Some("builder"));
    assert_eq!(df.stages[1].alias.as_deref(), Some("runner"));

    assert_eq!(df.stage_aliases(), vec!["builder", "runner"]);
    assert!(df.is_multi_stage());
}

#[test]
fn test_parse_copy_and_add_flags() {
    let dockerfile_content = r#"
FROM alpine:3.19
COPY --from=build --chown=user:group --chmod=755 src.txt /dest.txt
ADD --chown=user:group archive.tar.gz /dest/
"#;

    let df = DockerfileParser::parse_str(dockerfile_content).expect("Valid Dockerfile");
    let stage = &df.stages[0];

    let copy_inst = stage
        .instructions
        .iter()
        .find_map(|i| match i {
            Instruction::Copy(c) => Some(c),
            _ => None,
        })
        .expect("COPY instruction found");

    assert_eq!(copy_inst.from_stage.as_deref(), Some("build"));
    assert_eq!(copy_inst.chown.as_deref(), Some("user:group"));
    assert_eq!(copy_inst.chmod.as_deref(), Some("755"));
    assert_eq!(copy_inst.sources, vec!["src.txt"]);
    assert_eq!(copy_inst.destination, "/dest.txt");

    let add_inst = stage
        .instructions
        .iter()
        .find_map(|i| match i {
            Instruction::Add(a) => Some(a),
            _ => None,
        })
        .expect("ADD instruction found");

    assert!(add_inst.is_archive_extraction());
    assert!(!add_inst.has_remote_url());
}

#[test]
fn test_parse_healthcheck() {
    let dockerfile_content = r#"
FROM alpine:3.19
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD curl -f http://localhost:8080/health || exit 1
"#;

    let df = DockerfileParser::parse_str(dockerfile_content).expect("Valid Dockerfile");
    let stage = &df.stages[0];

    let health_inst = stage
        .instructions
        .iter()
        .find_map(|i| match i {
            Instruction::Healthcheck(h) => Some(h),
            _ => None,
        })
        .expect("HEALTHCHECK instruction found");

    assert!(!health_inst.is_none);
    assert_eq!(health_inst.interval.as_deref(), Some("10s"));
    assert_eq!(health_inst.timeout.as_deref(), Some("3s"));
    assert_eq!(health_inst.retries.as_deref(), Some("5"));
    assert!(health_inst.command.as_ref().unwrap().contains("curl -f"));
}
