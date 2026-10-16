use crate::ast::*;
use crate::error::{LinterError, Result};
use std::path::Path;

/// Parser for Dockerfile syntax.
pub struct DockerfileParser;

#[derive(Debug, Clone)]
struct LogicalLine {
    start_line: usize,
    raw_content: String,
    normalized: String,
}

impl DockerfileParser {
    fn split_keyword(line: &str) -> (&str, &str) {
        let trimmed = line.trim();
        if let Some(pos) = trimmed.find(|c: char| c.is_whitespace()) {
            let (kw, rest) = trimmed.split_at(pos);
            (kw.trim(), rest.trim())
        } else {
            (trimmed, "")
        }
    }
}
