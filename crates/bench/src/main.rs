mod dataset;
mod evaluate;
mod metrics;
mod rivals;
mod scorecard;

use clap::Parser;
use llm_firewall_core::{Firewall, InjectionDetector, PiiDetector, PolicySet, SecretDetector};

use crate::evaluate::{evaluate, CoreGuard, EvalResult, Guard};
use crate::rivals::SubprocessGuard;

#[derive(Parser)]
#[command(name = "llm-firewall-bench")]
struct Cli {
    /// One or more dataset .jsonl files.
    #[arg(long, required = true, num_args = 1..)]
    dataset: Vec<String>,
    /// Risk-score threshold for CoreGuard.
    #[arg(long, default_value_t = 50)]
    threshold: u8,
    /// Optional rival: "name=program arg arg" (protocol: text on stdin -> 0/1 on stdout).
    #[arg(long)]
    rival: Vec<String>,
    /// Write results.json here.
    #[arg(long, default_value = "results.json")]
    out: String,
}

fn core_guard(threshold: u8) -> CoreGuard {
    let policy = PolicySet::from_yaml(
        "policies:\n  - name: b\n    when: { detector: injection, min_severity: high }\n    action: block\ndefault: allow\n",
    )
    .expect("builtin policy");
    // With the `ml` feature, attach the DeBERTa Stage-C classifier when its asset is
    // present; fall back to regex+heuristics (with a warning) if the model is missing.
    #[cfg(feature = "ml")]
    let injection = match llm_firewall_core::MlClassifier::load("models/injection") {
        Ok(clf) => {
            eprintln!("ML stage: loaded models/injection (DeBERTa Stage C active)");
            InjectionDetector::new().with_ml(clf)
        }
        Err(e) => {
            eprintln!("ML stage: model unavailable ({e}); using regex+heuristics only");
            InjectionDetector::new()
        }
    };
    #[cfg(not(feature = "ml"))]
    let injection = InjectionDetector::new();

    CoreGuard {
        firewall: Firewall::new(
            vec![
                Box::new(injection),
                Box::new(SecretDetector::new()),
                Box::new(PiiDetector::new()),
            ],
            policy,
        ),
        threshold,
    }
}

fn parse_rival(spec: &str) -> Option<SubprocessGuard> {
    let (name, cmd) = spec.split_once('=')?;
    let mut parts = cmd.split_whitespace();
    let program = parts.next()?.to_string();
    let args = parts.map(String::from).collect();
    Some(SubprocessGuard {
        name: name.to_string(),
        program,
        args,
    })
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Merge all datasets.
    let mut data = Vec::new();
    for p in &cli.dataset {
        data.extend(dataset::load_jsonl(p)?);
    }
    eprintln!("loaded {} examples", data.len());

    let mut results: Vec<EvalResult> = Vec::new();
    let core = core_guard(cli.threshold);
    results.push(evaluate(&core, &data));

    for spec in &cli.rival {
        match parse_rival(spec) {
            Some(g) => {
                let name = g.name();
                results.push(evaluate(&g as &dyn Guard, &data));
                eprintln!("evaluated rival {name}");
            }
            None => {
                eprintln!("skipping malformed --rival (expected \"name=program args\"): {spec}")
            }
        }
    }

    std::fs::write(
        &cli.out,
        serde_json::to_string_pretty(&scorecard::to_json(&results))?,
    )?;
    println!("{}", scorecard::to_markdown(&results));
    eprintln!("wrote {}", cli.out);
    Ok(())
}
