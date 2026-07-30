// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

use std::path::PathBuf;

use agentfw::Config;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "agentfw", about = "Agent firewall daemon and tooling")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Summarize an audit log: what would this policy have done?
    Replay {
        /// Path to the audit log (defaults to ~/.agentfw/audit.jsonl).
        #[arg(long)]
        log: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Replay { log } => {
            let home = Config::home()?;
            let path = log.unwrap_or_else(|| home.join("audit.jsonl"));
            let body = std::fs::read_to_string(&path)?;
            print!("{}", agentfw::replay::summarize(&body).render());
            Ok(())
        }
    }
}
