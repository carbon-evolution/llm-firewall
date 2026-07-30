// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use agentfw::audit::AuditSink;
use agentfw::handlers::{AppState, Sessions};
use agentfw::{app, Config};
use clap::{Parser, Subcommand};
use llm_firewall_agent::{AgentFirewall, AgentPolicySet, DEFAULT_TAINT_CAP};

#[derive(Parser)]
#[command(name = "agentfw", about = "Agent firewall daemon and tooling")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon.
    Serve,
    /// Summarize an audit log: what would this policy have done?
    Replay {
        /// Path to the audit log (defaults to ~/.agentfw/audit.jsonl).
        #[arg(long)]
        log: Option<PathBuf>,
    },
    /// Print the settings.json hook block and setup instructions.
    Install,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve => {
            tracing_subscriber::fmt().json().init();
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(serve())
        }
        Cmd::Replay { log } => {
            let home = Config::home()?;
            let path = log.unwrap_or_else(|| home.join("audit.jsonl"));
            let body = std::fs::read_to_string(&path)?;
            print!("{}", agentfw::replay::summarize(&body).render());
            Ok(())
        }
        Cmd::Install => {
            let home = Config::home()?;
            let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
                Ok(s) => Config::from_yaml(&s)?,
                Err(_) => Config::default(),
            };
            agentfw::token::load_or_create(&home.join("token"))?;
            println!(
                "{}",
                agentfw::install::instructions(cfg.port, &home.join("token"))
            );
            Ok(())
        }
    }
}

async fn serve() -> anyhow::Result<()> {
    let home = Config::home()?;
    let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
        Ok(s) => Config::from_yaml(&s)?,
        Err(_) => Config::default(),
    };

    let firewall = match &cfg.policy {
        Some(p) => AgentFirewall::new(
            AgentPolicySet::from_yaml(&std::fs::read_to_string(p)?)?,
            DEFAULT_TAINT_CAP,
        ),
        None => AgentFirewall::with_default_policy(),
    };

    let token = agentfw::token::load_or_create(&home.join("token"))?;
    let audit_path = cfg
        .audit
        .clone()
        .unwrap_or_else(|| home.join("audit.jsonl"));
    let state: agentfw::Shared = Arc::new(AppState {
        firewall: Mutex::new(firewall),
        sessions: Sessions::default(),
        audit: AuditSink::open(&audit_path)?,
        spans: agentfw::spans::SpanCache::new(64, cfg.judge.max_span_bytes),
        judge: agentfw::judge::Judge::new(cfg.judge.clone()),
        config: cfg.clone(),
        token,
    });

    let addr = format!("{}:{}", cfg.bind, cfg.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(
        addr = %addr,
        enforce = cfg.enforce,
        "agentfw listening ({})",
        if cfg.enforce { "ENFORCING" } else { "shadow mode" }
    );
    axum::serve(listener, app(state)).await?;
    Ok(())
}
