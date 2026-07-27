mod dataset;
mod evaluate;
mod metrics;
mod report;
mod rivals;
mod scorecard;

use clap::Parser;
use llm_firewall_core::{
    Firewall, InjectionDetector, OutputDetector, PiiDetector, PolicySet, SecretDetector,
};

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
    /// Diagnostic (ml feature only): dump per-example {label, cheap_score, cheap_block,
    /// ml_p} to this JSONL path in a single ML pass, for offline threshold sweeps.
    #[arg(long)]
    dump_features: Option<String>,
    /// Write an OWASP LLM Top 10 (2025) coverage/risk report (Markdown) to this path.
    #[arg(long)]
    report: Option<String>,
}

fn core_guard(threshold: u8) -> CoreGuard {
    let policy = PolicySet::from_yaml(
        "policies:\n  - name: block-injection-high\n    when: { detector: injection, min_severity: high }\n    action: block\n  - name: block-ml-positive\n    when: { detector: injection.ml }\n    action: block\ndefault: allow\n",
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
                Box::new(OutputDetector::new()),
            ],
            policy,
        ),
        threshold,
    }
}

/// Dump per-example features in one ML pass: the cheap-stage (regex+heuristics) score
/// and block flag, plus the raw DeBERTa P(injection). Lets us sweep both the score
/// threshold and the ML cutoff offline without re-running the model each time.
#[cfg(feature = "ml")]
fn dump_features(data: &[dataset::Example], path: &str) -> anyhow::Result<()> {
    use llm_firewall_core::{Action, Direction, MlClassifier};
    use std::io::Write;

    let policy = PolicySet::from_yaml(
        "policies:\n  - name: b\n    when: { detector: injection, min_severity: high }\n    action: block\ndefault: allow\n",
    )?;
    // Cheap firewall = regex + heuristics only (no ML), so cheap_score isolates the
    // rule stages; ml_p is the model's raw probability.
    let cheap = Firewall::new(
        vec![
            Box::new(InjectionDetector::new()),
            Box::new(SecretDetector::new()),
            Box::new(PiiDetector::new()),
        ],
        policy,
    );
    let clf = MlClassifier::load("models/injection")?;

    let mut f = std::fs::File::create(path)?;
    for ex in data {
        let out = cheap.run(&ex.text, Direction::Input);
        let ml_p = clf.predict(&ex.text).unwrap_or(0.0);
        let rec = serde_json::json!({
            "label": ex.label,
            "cheap_score": out.score.score,
            "cheap_block": out.decision.action == Action::Block,
            "ml_p": ml_p,
        });
        writeln!(f, "{rec}")?;
    }
    Ok(())
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

    // Diagnostic feature dump (single ML pass) for offline threshold sweeps.
    if let Some(path) = &cli.dump_features {
        #[cfg(feature = "ml")]
        {
            dump_features(&data, path)?;
            eprintln!("wrote features to {path}");
            return Ok(());
        }
        #[cfg(not(feature = "ml"))]
        {
            let _ = path;
            anyhow::bail!("--dump-features requires the `ml` feature");
        }
    }

    let mut results: Vec<EvalResult> = Vec::new();
    let core = core_guard(cli.threshold);

    if let Some(path) = &cli.report {
        std::fs::write(path, report::build_report(&core.firewall, &data))?;
        eprintln!("wrote compliance report to {path}");
    }

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
