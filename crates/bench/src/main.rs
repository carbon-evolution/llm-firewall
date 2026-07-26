#[allow(dead_code)] // metrics consumed by evaluate/scorecard/CLI in later tasks
mod metrics;

#[allow(dead_code)] // load_jsonl consumed by the CLI in Task 5
mod dataset;

#[allow(dead_code)] // evaluate/Guard/CoreGuard consumed by the CLI in Task 5
mod evaluate;

fn main() {
    println!("llm-firewall-bench (CLI wired in Task 5)");
}
