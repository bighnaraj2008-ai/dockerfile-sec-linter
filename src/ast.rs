use serde::{Deserialize, Serialize};

/// Represents a base image declaration in a `FROM` instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FromInstruction {
    /// Full image reference (e.g. "ubuntu", "node:18-alpine", "python@sha256:...")
    pub full_image: String,
    /// Image repository/name (e.g. "ubuntu", "python", "golang")
    pub image_name: String,
    /// Image tag if present (e.g. "latest", "3.11-slim")
    pub tag: Option<String>,
    /// SHA256 digest if present (e.g. "sha256:abc123...")
    pub digest: Option<String>,
    /// Target build stage alias (e.g. `FROM ... AS builder`)
    pub alias: Option<String>,
    /// Optional platform specification (e.g. `--platform=linux/amd64`)
    pub platform: Option<String>,
    /// Line number in the Dockerfile where instruction starts (1-indexed)
    pub line_number: usize,
    /// Raw unparsed instruction text
    pub raw: String,
}

impl FromInstruction {
    /// Returns true if this base image is pinned to an explicit version tag or digest.
    pub fn is_pinned(&self) -> bool {
        // "scratch" is considered pinned (empty image)
        if self.image_name == "scratch" {
            return true;
        }

        // Having an explicit digest is the most secure pinning
        if self.digest.is_some() {
            return true;
        }

        // If no tag is provided, it defaults to :latest (unpinned)
        match &self.tag {
            Some(tag) => tag != "latest" && !tag.is_empty(),
            None => false,
        }
    }
}

/// Represents a `RUN` instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunInstruction {
    pub command: String,
    pub is_exec_form: bool,
    pub line_number: usize,
    pub raw: String,
}

/// Represents a `USER` instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInstruction {
    pub user: String,
    pub group: Option<String>,
    pub line_number: usize,
    pub raw: String,
}

impl UserInstruction {
    /// Returns true if this instruction switches to the root user.
    pub fn is_root(&self) -> bool {
        let u = self.user.trim().to_lowercase();
        u == "root" || u == "0"
    }
}

/// Represents an `ENV` instruction defining key-value pairs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvInstruction {
    pub vars: Vec<(String, String)>,
    pub line_number: usize,
    pub raw: String,
}

/// Represents an `ARG` instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgInstruction {
    pub name: String,
    pub default_value: Option<String>,
    pub line_number: usize,
    pub raw: String,
}

/// Represents a `COPY` instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyInstruction {
    pub from_stage: Option<String>,
    pub chown: Option<String>,
    pub chmod: Option<String>,
    pub sources: Vec<String>,
    pub destination: String,
    pub line_number: usize,
    pub raw: String,
}

/// Represents an `ADD` instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddInstruction {
    pub chown: Option<String>,
    pub chmod: Option<String>,
    pub sources: Vec<String>,
    pub destination: String,
    pub line_number: usize,
    pub raw: String,
}

impl AddInstruction {
    /// Returns true if any source looks like an archive that Docker automatically unpacks.
    pub fn is_archive_extraction(&self) -> bool {
        self.sources.iter().any(|src| {
            let s = src.to_lowercase();
            s.ends_with(".tar")
                || s.ends_with(".tar.gz")
                || s.ends_with(".tgz")
                || s.ends_with(".tar.bz2")
                || s.ends_with(".tbz2")
                || s.ends_with(".tar.xz")
                || s.ends_with(".txz")
        })
    }

    /// Returns true if any source is an HTTP or HTTPS remote URL.
    pub fn has_remote_url(&self) -> bool {
        self.sources.iter().any(|src| {
            let s = src.to_lowercase();
            s.starts_with("http://") || s.starts_with("https://")
        })
    }
}

/// Represents an `EXPOSE` instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposeInstruction {
    pub ports: Vec<String>,
    pub line_number: usize,
    pub raw: String,
}

/// Represents a `WORKDIR` instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkdirInstruction {
    pub path: String,
    pub line_number: usize,
    pub raw: String,
}

/// Represents an `ENTRYPOINT` instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntrypointInstruction {
    pub command: Vec<String>,
    pub is_exec_form: bool,
    pub line_number: usize,
    pub raw: String,
}

/// Represents a `CMD` instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CmdInstruction {
    pub command: Vec<String>,
    pub is_exec_form: bool,
    pub line_number: usize,
    pub raw: String,
}

/// Represents a `HEALTHCHECK` instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthcheckInstruction {
    pub is_none: bool,
    pub command: Option<String>,
    pub interval: Option<String>,
    pub timeout: Option<String>,
    pub start_period: Option<String>,
    pub retries: Option<String>,
    pub line_number: usize,
    pub raw: String,
}

/// Represents any other instruction (e.g. `LABEL`, `VOLUME`, `STOPSIGNAL`, `SHELL`, `ONBUILD`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtherInstruction {
    pub name: String,
    pub arguments: String,
    pub line_number: usize,
    pub raw: String,
}

/// Unified Dockerfile instruction enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instruction {
    From(FromInstruction),
    Run(RunInstruction),
    User(UserInstruction),
    Env(EnvInstruction),
    Arg(ArgInstruction),
    Copy(CopyInstruction),
    Add(AddInstruction),
    Expose(ExposeInstruction),
    Workdir(WorkdirInstruction),
    Entrypoint(EntrypointInstruction),
    Cmd(CmdInstruction),
    Healthcheck(HealthcheckInstruction),
    Other(OtherInstruction),
}

impl Instruction {
    pub fn line_number(&self) -> usize {
        match self {
            Instruction::From(i) => i.line_number,
            Instruction::Run(i) => i.line_number,
            Instruction::User(i) => i.line_number,
            Instruction::Env(i) => i.line_number,
            Instruction::Arg(i) => i.line_number,
            Instruction::Copy(i) => i.line_number,
            Instruction::Add(i) => i.line_number,
            Instruction::Expose(i) => i.line_number,
            Instruction::Workdir(i) => i.line_number,
            Instruction::Entrypoint(i) => i.line_number,
            Instruction::Cmd(i) => i.line_number,
            Instruction::Healthcheck(i) => i.line_number,
            Instruction::Other(i) => i.line_number,
        }
    }

    pub fn raw(&self) -> &str {
        match self {
            Instruction::From(i) => &i.raw,
            Instruction::Run(i) => &i.raw,
            Instruction::User(i) => &i.raw,
            Instruction::Env(i) => &i.raw,
            Instruction::Arg(i) => &i.raw,
            Instruction::Copy(i) => &i.raw,
            Instruction::Add(i) => &i.raw,
            Instruction::Expose(i) => &i.raw,
            Instruction::Workdir(i) => &i.raw,
            Instruction::Entrypoint(i) => &i.raw,
            Instruction::Cmd(i) => &i.raw,
            Instruction::Healthcheck(i) => &i.raw,
            Instruction::Other(i) => &i.raw,
        }
    }

    pub fn instruction_name(&self) -> &'static str {
        match self {
            Instruction::From(_) => "FROM",
            Instruction::Run(_) => "RUN",
            Instruction::User(_) => "USER",
            Instruction::Env(_) => "ENV",
            Instruction::Arg(_) => "ARG",
            Instruction::Copy(_) => "COPY",
            Instruction::Add(_) => "ADD",
            Instruction::Expose(_) => "EXPOSE",
            Instruction::Workdir(_) => "WORKDIR",
            Instruction::Entrypoint(_) => "ENTRYPOINT",
            Instruction::Cmd(_) => "CMD",
            Instruction::Healthcheck(_) => "HEALTHCHECK",
            Instruction::Other(_) => "OTHER",
        }
    }
}

/// Represents a distinct build stage in a multi-stage Dockerfile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage {
    pub index: usize,
    pub from: FromInstruction,
    pub alias: Option<String>,
    pub instructions: Vec<Instruction>,
}

impl Stage {
    /// Returns the last specified `USER` instruction in this stage, if any.
    pub fn last_user(&self) -> Option<&UserInstruction> {
        self.instructions.iter().rev().find_map(|inst| match inst {
            Instruction::User(u) => Some(u),
            _ => None,
        })
    }

    /// Returns all `RUN` instructions in this stage.
    pub fn run_instructions(&self) -> Vec<&RunInstruction> {
        self.instructions
            .iter()
            .filter_map(|inst| match inst {
                Instruction::Run(r) => Some(r),
                _ => None,
            })
            .collect()
    }
}

/// Represents an entire parsed Dockerfile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dockerfile {
    /// Global `ARG` directives defined before the initial `FROM` stage.
    pub global_args: Vec<ArgInstruction>,
    /// All build stages parsed in order.
    pub stages: Vec<Stage>,
}

impl Dockerfile {
    /// Returns true if the Dockerfile contains more than one build stage.
    pub fn is_multi_stage(&self) -> bool {
        self.stages.len() > 1
    }

    /// Returns a reference to the final build stage (the runtime target image).
    pub fn final_stage(&self) -> Option<&Stage> {
        self.stages.last()
    }

    /// Collects all stage aliases declared across all stages.
    pub fn stage_aliases(&self) -> Vec<String> {
        self.stages
            .iter()
            .filter_map(|s| s.alias.clone().or_else(|| s.from.alias.clone()))
            .collect()
    }

    /// Returns all instructions across all stages.
    pub fn all_instructions(&self) -> Vec<&Instruction> {
        let mut list = Vec::new();
        for stage in &self.stages {
            for inst in &stage.instructions {
                list.push(inst);
            }
        }
        list
    }
}
