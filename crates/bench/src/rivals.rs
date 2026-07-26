//! Run an external (e.g. Python) guard as a subprocess. Protocol: we send the text on
//! stdin; the process prints "1" (malicious) or "0" (benign) on stdout.

use std::io::Write;
use std::process::{Command, Stdio};

use crate::evaluate::Guard;

pub struct SubprocessGuard {
    pub name: String,
    pub program: String,
    pub args: Vec<String>,
}

impl Guard for SubprocessGuard {
    fn name(&self) -> String {
        self.name.clone()
    }
    fn predict(&self, text: &str) -> bool {
        let mut child = match Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return false, // rival unavailable -> counted as benign prediction
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
        }
        let out = match child.wait_with_output() {
            Ok(o) => o,
            Err(_) => return false,
        };
        String::from_utf8_lossy(&out.stdout).trim().starts_with('1')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_subprocess_verdict() {
        // Cross-platform stand-in for a rival: echo 1 => malicious.
        let g = SubprocessGuard {
            name: "echo-1".into(),
            program: "sh".into(),
            args: vec!["-c".into(), "cat >/dev/null; echo 1".into()],
        };
        assert!(g.predict("anything"));

        let g0 = SubprocessGuard {
            name: "echo-0".into(),
            program: "sh".into(),
            args: vec!["-c".into(), "cat >/dev/null; echo 0".into()],
        };
        assert!(!g0.predict("anything"));
    }
}
