use crate::ast::*;
use crate::error::{LinterError, Result};
use std::path::Path;

/// Parser for Dockerfile syntax.
pub struct DockerfileParser;

/// Intermediate representation of a logical line spanning one or more physical lines.
#[derive(Debug, Clone)]
struct LogicalLine {
    start_line: usize,
    raw_content: String,
    normalized: String,
}

impl DockerfileParser {
    /// Parses Dockerfile content from a string.
    pub fn parse_str(content: &str) -> Result<Dockerfile> {
        let logical_lines = Self::extract_logical_lines(content);
        Self::build_ast(logical_lines)
    }

    /// Reads and parses a Dockerfile from a filesystem path.
    pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<Dockerfile> {
        let p = path.as_ref();
        let content = std::fs::read_to_string(p).map_err(|e| LinterError::Io {
            path: p.to_path_buf(),
            source: e,
        })?;
        Self::parse_str(&content)
    }

    /// Groups physical lines into logical instructions respecting multi-line backslash continuations.
    fn extract_logical_lines(content: &str) -> Vec<LogicalLine> {
        let mut logical_lines = Vec::new();
        let mut current_buf = String::new();
        let mut raw_buf = String::new();
        let mut start_line = 1;
        let mut in_continuation = false;

        for (idx, line) in content.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = line.trim();

            // Handle pure comment or empty lines when not in continuation
            if !in_continuation {
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                start_line = line_num;
                current_buf.clear();
                raw_buf.clear();
            }

            // Append to raw buffer
            if !raw_buf.is_empty() {
                raw_buf.push('\n');
            }
            raw_buf.push_str(line);

            // Check if line ends with backslash continuation
            if let Some(without_slash) = trimmed.strip_suffix('\\') {
                in_continuation = true;
                if !current_buf.is_empty() {
                    current_buf.push(' ');
                }
                current_buf.push_str(without_slash.trim_end());
            } else {
                in_continuation = false;
                if !current_buf.is_empty() {
                    current_buf.push(' ');
                }
                current_buf.push_str(trimmed);

                logical_lines.push(LogicalLine {
                    start_line,
                    raw_content: raw_buf.clone(),
                    normalized: current_buf.trim().to_string(),
                });

                current_buf.clear();
                raw_buf.clear();
            }
        }

        // Flush dangling continuation if file ended with a backslash
        if !current_buf.is_empty() {
            logical_lines.push(LogicalLine {
                start_line,
                raw_content: raw_buf,
                normalized: current_buf.trim().to_string(),
            });
        }

        logical_lines
    }

    /// Converts logical lines into the structured Dockerfile AST.
    fn build_ast(lines: Vec<LogicalLine>) -> Result<Dockerfile> {
        let mut global_args = Vec::new();
        let mut stages = Vec::new();
        let mut current_stage: Option<Stage> = None;

        for line in lines {
            let (keyword, rest) = Self::split_keyword(&line.normalized);
            let keyword_upper = keyword.to_uppercase();

            if keyword_upper == "FROM" {
                // Finalize previous stage if any
                if let Some(prev) = current_stage.take() {
                    stages.push(prev);
                }

                let from_inst = Self::parse_from(rest, line.start_line, &line.raw_content)?;
                let stage_idx = stages.len();
                let stage_alias = from_inst.alias.clone();

                let mut new_stage = Stage {
                    index: stage_idx,
                    from: from_inst.clone(),
                    alias: stage_alias,
                    instructions: Vec::new(),
                };
                // Include FROM in the instruction list for uniform traversal
                new_stage.instructions.push(Instruction::From(from_inst));
                current_stage = Some(new_stage);
                continue;
            }

            let instruction = match keyword_upper.as_str() {
                "RUN" => {
                    Instruction::Run(Self::parse_run(rest, line.start_line, &line.raw_content))
                }
                "USER" => {
                    Instruction::User(Self::parse_user(rest, line.start_line, &line.raw_content))
                }
                "ENV" => {
                    Instruction::Env(Self::parse_env(rest, line.start_line, &line.raw_content))
                }
                "ARG" => {
                    Instruction::Arg(Self::parse_arg(rest, line.start_line, &line.raw_content))
                }
                "COPY" => {
                    Instruction::Copy(Self::parse_copy(rest, line.start_line, &line.raw_content))
                }
                "ADD" => {
                    Instruction::Add(Self::parse_add(rest, line.start_line, &line.raw_content))
                }
                "EXPOSE" => Instruction::Expose(Self::parse_expose(
                    rest,
                    line.start_line,
                    &line.raw_content,
                )),
                "WORKDIR" => Instruction::Workdir(Self::parse_workdir(
                    rest,
                    line.start_line,
                    &line.raw_content,
                )),
                "ENTRYPOINT" => Instruction::Entrypoint(Self::parse_entrypoint(
                    rest,
                    line.start_line,
                    &line.raw_content,
                )),
                "CMD" => {
                    Instruction::Cmd(Self::parse_cmd(rest, line.start_line, &line.raw_content))
                }
                "HEALTHCHECK" => Instruction::Healthcheck(Self::parse_healthcheck(
                    rest,
                    line.start_line,
                    &line.raw_content,
                )),
                _ => Instruction::Other(OtherInstruction {
                    name: keyword.to_string(),
                    arguments: rest.to_string(),
                    line_number: line.start_line,
                    raw: line.raw_content.clone(),
                }),
            };

            // If we haven't encountered a FROM yet and it's an ARG, it's a global ARG
            if current_stage.is_none() {
                if let Instruction::Arg(arg) = instruction {
                    global_args.push(arg);
                }
            } else if let Some(ref mut stage) = current_stage {
                stage.instructions.push(instruction);
            }
        }

        if let Some(last_stage) = current_stage {
            stages.push(last_stage);
        }

        Ok(Dockerfile {
            global_args,
            stages,
        })
    }

    fn split_keyword(line: &str) -> (&str, &str) {
        let trimmed = line.trim();
        if let Some(pos) = trimmed.find(|c: char| c.is_whitespace()) {
            let (kw, rest) = trimmed.split_at(pos);
            (kw.trim(), rest.trim())
        } else {
            (trimmed, "")
        }
    }

    /// Parses `FROM [--platform=<platform>] <image>[:<tag>][@<digest>] [AS <alias>]`
    fn parse_from(rest: &str, line_number: usize, raw: &str) -> Result<FromInstruction> {
        let tokens = Self::tokenize_whitespace(rest);
        if tokens.is_empty() {
            return Err(LinterError::Parse {
                line: line_number,
                message: "FROM instruction missing base image target".to_string(),
            });
        }

        let mut platform = None;
        let mut image_token_idx = 0;

        for (i, tok) in tokens.iter().enumerate() {
            if let Some(p) = tok.strip_prefix("--platform=") {
                platform = Some(p.to_string());
                image_token_idx = i + 1;
            } else {
                break;
            }
        }

        if image_token_idx >= tokens.len() {
            return Err(LinterError::Parse {
                line: line_number,
                message: "FROM instruction missing base image target after flags".to_string(),
            });
        }

        let full_image = tokens[image_token_idx].clone();

        // Check for `AS <alias>` (case insensitive)
        let mut alias = None;
        for i in (image_token_idx + 1)..tokens.len() {
            if tokens[i].eq_ignore_ascii_case("AS") && i + 1 < tokens.len() {
                alias = Some(tokens[i + 1].clone());
                break;
            }
        }

        // Deconstruct full_image into repository, tag, and digest
        // e.g. "ubuntu:22.04@sha256:abcd" or "node:18-alpine" or "python@sha256:..."
        let (image_name, tag, digest) = Self::parse_image_components(&full_image);

        Ok(FromInstruction {
            full_image,
            image_name,
            tag,
            digest,
            alias,
            platform,
            line_number,
            raw: raw.to_string(),
        })
    }

    fn parse_image_components(full: &str) -> (String, Option<String>, Option<String>) {
        let mut digest = None;
        let mut remainder = full;

        if let Some(pos) = full.find('@') {
            digest = Some(full[pos + 1..].to_string());
            remainder = &full[..pos];
        }

        // Now split repository and tag
        // Note: handle registry host with port like "localhost:5000/my-image:tag"
        let mut tag = None;
        let mut repo = remainder.to_string();

        if let Some(last_colon) = remainder.rfind(':') {
            // Ensure this colon is after any slash (so it's not a port in host:port/repo)
            let last_slash = remainder.rfind('/');
            let is_tag_colon = match last_slash {
                Some(slash_pos) => last_colon > slash_pos,
                None => true,
            };

            if is_tag_colon {
                tag = Some(remainder[last_colon + 1..].to_string());
                repo = remainder[..last_colon].to_string();
            }
        }

        (repo, tag, digest)
    }

    /// Parses `RUN <command>` (exec form vs shell form)
    fn parse_run(rest: &str, line_number: usize, raw: &str) -> RunInstruction {
        let trimmed = rest.trim();
        let is_exec_form = trimmed.starts_with('[') && trimmed.ends_with(']');
        RunInstruction {
            command: trimmed.to_string(),
            is_exec_form,
            line_number,
            raw: raw.to_string(),
        }
    }

    /// Parses `USER <user>[:<group>]`
    fn parse_user(rest: &str, line_number: usize, raw: &str) -> UserInstruction {
        let trimmed = rest.trim();
        let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
        let user = parts[0].trim().to_string();
        let group = if parts.len() > 1 {
            Some(parts[1].trim().to_string())
        } else {
            None
        };

        UserInstruction {
            user,
            group,
            line_number,
            raw: raw.to_string(),
        }
    }

    /// Parses `ENV` supporting both `ENV KEY=VAL KEY2=VAL2` and `ENV KEY VAL`
    fn parse_env(rest: &str, line_number: usize, raw: &str) -> EnvInstruction {
        let trimmed = rest.trim();
        let mut vars = Vec::new();

        if trimmed.contains('=') {
            // Key=Value form
            // Tokenize while respecting quotes
            let tokens = Self::tokenize_key_values(trimmed);
            for (k, v) in tokens {
                vars.push((k, v));
            }
        } else {
            // Legacy space-delimited form: `ENV KEY VALUE`
            let tokens = Self::tokenize_whitespace(trimmed);
            if !tokens.is_empty() {
                let key = tokens[0].clone();
                let val = if tokens.len() > 1 {
                    tokens[1..].join(" ")
                } else {
                    String::new()
                };
                vars.push((key, val));
            }
        }

        EnvInstruction {
            vars,
            line_number,
            raw: raw.to_string(),
        }
    }

    /// Parses `ARG <name>[=<default>]`
    fn parse_arg(rest: &str, line_number: usize, raw: &str) -> ArgInstruction {
        let trimmed = rest.trim();
        if let Some(pos) = trimmed.find('=') {
            let (k, v) = trimmed.split_at(pos);
            ArgInstruction {
                name: k.trim().to_string(),
                default_value: Some(
                    v[1..]
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string(),
                ),
                line_number,
                raw: raw.to_string(),
            }
        } else {
            ArgInstruction {
                name: trimmed.to_string(),
                default_value: None,
                line_number,
                raw: raw.to_string(),
            }
        }
    }

    /// Parses `COPY [--from=<stage>] [--chown=...] <src>... <dest>`
    fn parse_copy(rest: &str, line_number: usize, raw: &str) -> CopyInstruction {
        let tokens = Self::tokenize_whitespace(rest);
        let mut from_stage = None;
        let mut chown = None;
        let mut chmod = None;
        let mut paths = Vec::new();

        for tok in tokens {
            if let Some(s) = tok.strip_prefix("--from=") {
                from_stage = Some(s.to_string());
            } else if let Some(c) = tok.strip_prefix("--chown=") {
                chown = Some(c.to_string());
            } else if let Some(m) = tok.strip_prefix("--chmod=") {
                chmod = Some(m.to_string());
            } else {
                paths.push(tok);
            }
        }

        let destination = paths.pop().unwrap_or_default();
        let sources = paths;

        CopyInstruction {
            from_stage,
            chown,
            chmod,
            sources,
            destination,
            line_number,
            raw: raw.to_string(),
        }
    }

    /// Parses `ADD [--chown=...] <src>... <dest>`
    fn parse_add(rest: &str, line_number: usize, raw: &str) -> AddInstruction {
        let tokens = Self::tokenize_whitespace(rest);
        let mut chown = None;
        let mut chmod = None;
        let mut paths = Vec::new();

        for tok in tokens {
            if let Some(c) = tok.strip_prefix("--chown=") {
                chown = Some(c.to_string());
            } else if let Some(m) = tok.strip_prefix("--chmod=") {
                chmod = Some(m.to_string());
            } else {
                paths.push(tok);
            }
        }

        let destination = paths.pop().unwrap_or_default();
        let sources = paths;

        AddInstruction {
            chown,
            chmod,
            sources,
            destination,
            line_number,
            raw: raw.to_string(),
        }
    }

    /// Parses `EXPOSE <port>...`
    fn parse_expose(rest: &str, line_number: usize, raw: &str) -> ExposeInstruction {
        let ports = Self::tokenize_whitespace(rest);
        ExposeInstruction {
            ports,
            line_number,
            raw: raw.to_string(),
        }
    }

    /// Parses `WORKDIR <path>`
    fn parse_workdir(rest: &str, line_number: usize, raw: &str) -> WorkdirInstruction {
        WorkdirInstruction {
            path: rest.trim().to_string(),
            line_number,
            raw: raw.to_string(),
        }
    }

    /// Parses `ENTRYPOINT` command
    fn parse_entrypoint(rest: &str, line_number: usize, raw: &str) -> EntrypointInstruction {
        let trimmed = rest.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let parsed_exec = Self::parse_json_array(trimmed);
            EntrypointInstruction {
                command: parsed_exec,
                is_exec_form: true,
                line_number,
                raw: raw.to_string(),
            }
        } else {
            EntrypointInstruction {
                command: vec![trimmed.to_string()],
                is_exec_form: false,
                line_number,
                raw: raw.to_string(),
            }
        }
    }

    /// Parses `CMD` command
    fn parse_cmd(rest: &str, line_number: usize, raw: &str) -> CmdInstruction {
        let trimmed = rest.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let parsed_exec = Self::parse_json_array(trimmed);
            CmdInstruction {
                command: parsed_exec,
                is_exec_form: true,
                line_number,
                raw: raw.to_string(),
            }
        } else {
            CmdInstruction {
                command: vec![trimmed.to_string()],
                is_exec_form: false,
                line_number,
                raw: raw.to_string(),
            }
        }
    }

    /// Parses `HEALTHCHECK` instruction
    fn parse_healthcheck(rest: &str, line_number: usize, raw: &str) -> HealthcheckInstruction {
        let trimmed = rest.trim();
        if trimmed.eq_ignore_ascii_case("NONE") {
            return HealthcheckInstruction {
                is_none: true,
                command: None,
                interval: None,
                timeout: None,
                start_period: None,
                retries: None,
                line_number,
                raw: raw.to_string(),
            };
        }

        let mut interval = None;
        let mut timeout = None;
        let mut start_period = None;
        let mut retries = None;
        let mut command = None;

        let tokens = Self::tokenize_whitespace(trimmed);
        let mut i = 0;
        while i < tokens.len() {
            let tok = &tokens[i];
            if let Some(val) = tok.strip_prefix("--interval=") {
                interval = Some(val.to_string());
            } else if let Some(val) = tok.strip_prefix("--timeout=") {
                timeout = Some(val.to_string());
            } else if let Some(val) = tok.strip_prefix("--start-period=") {
                start_period = Some(val.to_string());
            } else if let Some(val) = tok.strip_prefix("--retries=") {
                retries = Some(val.to_string());
            } else if tok.eq_ignore_ascii_case("CMD") {
                // Remainder is the test command
                command = Some(tokens[i + 1..].join(" "));
                break;
            }
            i += 1;
        }

        HealthcheckInstruction {
            is_none: false,
            command,
            interval,
            timeout,
            start_period,
            retries,
            line_number,
            raw: raw.to_string(),
        }
    }

    // Helper tokenizers
    fn tokenize_whitespace(s: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut cur = String::new();
        let mut in_quotes = false;
        let mut quote_char = ' ';

        for c in s.chars() {
            if (c == '"' || c == '\'') && !in_quotes {
                in_quotes = true;
                quote_char = c;
            } else if in_quotes && c == quote_char {
                in_quotes = false;
            } else if c.is_whitespace() && !in_quotes {
                if !cur.is_empty() {
                    tokens.push(cur.clone());
                    cur.clear();
                }
                continue;
            }
            cur.push(c);
        }

        if !cur.is_empty() {
            tokens.push(cur);
        }

        tokens
    }

    fn tokenize_key_values(s: &str) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        let mut cur = String::new();
        let mut in_quotes = false;
        let mut quote_char = ' ';

        for c in s.chars() {
            if (c == '"' || c == '\'') && !in_quotes {
                in_quotes = true;
                quote_char = c;
            } else if in_quotes && c == quote_char {
                in_quotes = false;
            } else if c.is_whitespace() && !in_quotes {
                if !cur.is_empty() {
                    if let Some(kv) = Self::split_kv(&cur) {
                        pairs.push(kv);
                    }
                    cur.clear();
                }
                continue;
            }
            cur.push(c);
        }

        if !cur.is_empty() {
            if let Some(kv) = Self::split_kv(&cur) {
                pairs.push(kv);
            }
        }

        pairs
    }

    fn split_kv(token: &str) -> Option<(String, String)> {
        if let Some(pos) = token.find('=') {
            let (k, v) = token.split_at(pos);
            let val = v[1..].trim_matches('"').trim_matches('\'');
            Some((k.trim().to_string(), val.to_string()))
        } else {
            None
        }
    }

    fn parse_json_array(s: &str) -> Vec<String> {
        if let Ok(arr) = serde_json::from_str::<Vec<String>>(s) {
            arr
        } else {
            // Fallback manual parse
            let inner = s.trim_matches(|c| c == '[' || c == ']');
            inner
                .split(',')
                .map(|p| p.trim().trim_matches('"').trim_matches('\'').to_string())
                .filter(|p| !p.is_empty())
                .collect()
        }
    }
}
