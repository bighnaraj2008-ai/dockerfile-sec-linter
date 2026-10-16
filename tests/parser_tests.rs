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
