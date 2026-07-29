# Gemini prompt — agent firewall data-flow diagram

Paste this into Gemini (browser chat) to generate a PNG matching the style of the existing
`docs/img/*.png` diagrams. Save the result as `docs/img/agent-dataflow.png`, then replace the
```mermaid block in the README's "How the agent firewall works" section with:

```html
<p align="center">
  <img src="docs/img/agent-dataflow.png" alt="Agent firewall data flow: collectors (Claude Code hooks, API proxy, MCP proxy) emit one AgentEvent schema; facet projection sends tool arguments as Output and tool results as Input into the reused core detectors; dedupe and noisy-OR risk score; agent signals (taint, action class, egress hosts, authority) join at the policy engine, which returns Allow, Ask, or Deny" width="900">
</p>
```

Keep the Mermaid block in git history — it stays readable in diffs even after the PNG lands.

---

## The prompt

> Create a professional technical architecture diagram, clean engineering-infographic style, flat
> vector look, no photorealism, no 3D, no drop shadows. Landscape 16:9, generous whitespace, thin
> connector lines with small arrowheads.
>
> **Render all text EXACTLY as written below — do not alter spelling, casing, or wording.**
>
> Title at top: **Agent Firewall — Data Flow**
> Subtitle, smaller, muted grey: **Inspecting what an agent does, not just what it says**
>
> Lay out five horizontal bands, top to bottom, connected by downward arrows:
>
> **Band 1 — "COLLECTORS (phase 09+)"** — draw this band with a DASHED border and slightly faded
> colours to show it is not yet built. Three equal boxes side by side:
> - `Claude Code hooks` / smaller line beneath: `PreToolUse · PostToolUse`
> - `API proxy` / smaller line beneath: `tool_use · tool_result blocks`
> - `MCP proxy` / smaller line beneath: `manifests · args · results`
>
> All three arrow down into:
>
> **Band 2 — one wide blue box**, the visual anchor of the diagram:
> `AgentEvent` in bold, with a smaller line beneath: `one schema for all collectors`
> and a third, smallest line: `ToolCall · ToolResult · SubagentSpawn · SubagentReport · ManifestSeen`
>
> **Band 3 — splits into two parallel paths.** Draw them side by side with a clear gap between.
>
> Left path, green, labelled `DETECTION (reused, no new detector code)`:
> - A box `Facet projection` with two labelled arrows leaving it:
>   - arrow labelled `tool ARGS → Direction::Output` going into the detector box
>   - arrow labelled `tool RESULTS → Direction::Input` going into the same detector box
> - The detector box: `core detectors` bold, beneath it `injection · secret · pii · output`
> - Below it: `Dedupe + risk score` with a smaller line `collapse repeats, then noisy-OR`
>
> Right path, amber/orange, labelled `AGENT SIGNALS`, four small stacked boxes:
> - `Taint` / `fingerprints + literals`
> - `Action class` / `ReadOnly → Destructive`
> - `Egress hosts` / `URLs · scp · IPv6`
> - `Authority` / `parent ⊇ child tools`
>
> **Band 4 — both paths converge** into one wide purple box:
> `Policy engine` bold, beneath it `flat, first-match YAML · denies before asks`
>
> **Band 5 — three outcome boxes** side by side, colour-coded:
> - GREEN: `Allow` / beneath: `proceed`
> - AMBER: `Ask` / beneath: `pause for the human`
> - RED: `Deny` / beneath: `block before it runs`
>
> Bottom-left corner, small muted footnote text:
> `Three of four threat classes reuse detectors that already existed.`
>
> Colour palette: white background, dark slate text, blue #1f6feb for the event schema, green #238636
> for detection and Allow, amber #9e6a03 for signals and Ask, red #da3633 for Deny, purple #8250df
> for the policy engine. Use monospace font for all code-like identifiers (`AgentEvent`,
> `Direction::Output`, `ToolCall`, detector names). Sans-serif for prose labels.
>
> Render the text exactly as given — do not alter spelling.
