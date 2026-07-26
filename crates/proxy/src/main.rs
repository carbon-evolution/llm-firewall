// Config is exercised by unit tests now and wired into the bootstrap in Task 5.
#[allow(dead_code)]
mod config;

#[allow(dead_code)] // ChatRequest consumed by pipeline/handlers in Tasks 4–5
mod openai;

#[allow(dead_code)] // AuditRecord emitted by handlers in Task 5
mod audit;

fn main() -> anyhow::Result<()> {
    // Full bootstrap wired in Task 5.
    println!("llm-firewall (bootstrap pending)");
    Ok(())
}
