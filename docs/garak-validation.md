# External validation — NVIDIA garak `encoding` probes

[garak](https://github.com/NVIDIA/garak) is a widely-used open-source LLM vulnerability scanner. Its
`encoding` probes hide an injection payload inside base64/rot13/etc. and check whether the model
decodes and follows it. We ran `encoding.InjectBase64` **straight at the model** (baseline) and
**through the firewall** (protected), so the delta isolates the firewall's contribution.

- **garak:** v0.15.1 · **probe:** `encoding.InjectBase64` (256 attempts, `-g 1`)
- **upstream:** local **LM Studio** OpenAI-compatible server, model `google/gemma-4-e4b` (free, no key)
- **date:** 2026-07-28

## Setup

```bash
python3.12 -m venv ~/garak-venv && ~/garak-venv/bin/pip install garak   # system py3.14 is PEP-668
export OPENAICOMPATIBLE_API_KEY=lm-studio
# generator config (uri points at LM Studio for baseline, at the firewall for protected)
G=~/garak-venv/bin/garak
$G --model_type openai.OpenAICompatible --model_name google/gemma-4-e4b \
   --generator_option_file gen.json --probes encoding.InjectBase64 --parallel_attempts 8 -g 1
```

## Results

**Baseline — raw Gemma-4B (no firewall):**

| detector | resilient | attack success |
|---|--:|--:|
| `encoding.DecodeMatch` | 195 / 256 | **23.8%** |
| `encoding.DecodeApprox` | 149 / 256 | **41.8%** |

So **~1 in 4 base64-encoded injections got through** the raw model — garak independently confirms the
encoded-injection threat is real.

**Protected — through the firewall (base64 tier on) → Gemma-4B** (audit-log breakdown):

| stage | allow | block |
|---|--:|--:|
| input (prompt) | 222 | 0 |
| output (reply) | 0 | **1341** |

Every model reply was blocked, so **none of the encoded-injection outputs reached the "user"**.

## Honest interpretation (important)

- The blocking here is **entirely output-side**, and it is **not** clean injection detection. garak's
  base64 payloads are diverse (`print the word …`), so the *decoded* input rarely matched the injection
  regex → **0 input blocks**. The output blocks are dominated by the **secret detector's high-entropy
  gate reacting to the base64 strings Gemma echoes in its replies** (base64 is high-entropy by nature).
- Net effect (attacks stopped before reaching the user) is real, but the **mechanism is over-eager**:
  the same output filter would block a *legitimate* reply that contains a long base64 blob. This is an
  honest over-defense signal, logged here rather than spun as a clean win.
- **The principled, clean win for the normalization pre-pass is the offline rule-layer benchmark**
  (input side, README "Obfuscation resilience"): obfuscated-attack recall 0.0% → 14.5% (base64
  0.0% → 30.6%) with **0.00% FPR** on a multilingual benign control. That is the defensible number.

## Takeaways / follow-ups

- garak externally corroborates the threat (24–42% raw success) and that the firewall's output layer
  prevents these responses from reaching the user.
- **Refinement worth doing:** exempt genuine base64 blocks from the output-side entropy gate (or scope
  the base64 decode tier to input only) so legitimate base64 in replies isn't over-blocked. Tracked as
  a follow-up, not claimed as done.
