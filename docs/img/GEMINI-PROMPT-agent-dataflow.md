# Agent data-flow diagram — how it was generated

`docs/img/agent-dataflow.png` (1024×572) was generated with Google Gemini and is embedded in the
README's "How the agent firewall works" section. This file records the prompt so the diagram can be
regenerated or amended without starting from scratch.

Three passes were needed. The first produced a correct diagram but leaked the layout instructions
into it as literal `BAND 1`…`BAND 5` labels; the second removed four of five; the third removed the
last one and cleaned a gradient artifact over the policy bar.

**Known imperfection:** there is no arrow drawn between the `core detectors` box and the
`Dedupe + risk score` box, despite being asked for twice. The boxes are adjacent and the flow reads
correctly without it, so it was left rather than risk regressing the text rendering, which is
otherwise accurate.

---

## Pass 1 — the base prompt

> Generate an image: a professional technical architecture diagram in a clean engineering-infographic
> style. Flat vector look, no photorealism, no 3D, no drop shadows. Landscape 16:9, white background,
> generous whitespace, thin connector lines with small arrowheads. IMPORTANT: render all text EXACTLY
> as written below, do not alter spelling, casing, or wording.
>
> Title at top: "Agent Firewall - Data Flow". Subtitle in smaller muted grey: "Inspecting what an
> agent does, not just what it says".
>
> Lay out five horizontal bands top to bottom, connected by downward arrows.
>
> BAND 1, drawn with a DASHED border and slightly faded colours to show it is not yet built, labelled
> "COLLECTORS - PHASE 09+, NOT YET BUILT", containing three equal boxes side by side: box 1 "Claude
> Code hooks" with smaller line beneath "PreToolUse / PostToolUse"; box 2 "API proxy" with smaller
> line "tool_use / tool_result"; box 3 "MCP proxy" with smaller line "manifests / args / results".
>
> All three arrow down into BAND 2: one wide BLUE box, the visual anchor, containing "AgentEvent" in
> bold monospace, beneath it "one schema for every collector", and a third smallest line "ToolCall /
> ToolResult / SubagentSpawn / SubagentReport / ManifestSeen".
>
> BAND 3 splits into two parallel columns with a clear gap. LEFT column in GREEN, labelled "DETECTION
> - REUSED, NO NEW DETECTOR CODE", containing a box "Facet projection" with two labelled arrows
> leaving it, one labelled "tool ARGS to Output" and one labelled "results to Input", both entering a
> solid green box "core detectors" with beneath it "injection / secret / pii / output", and below
> that a box "Dedupe + risk score" with smaller line "collapse repeats, then noisy-OR". RIGHT column
> in AMBER, labelled "AGENT SIGNALS - WHAT TEXT ALONE CANNOT SEE", containing four stacked boxes:
> "Taint" with "fingerprints + literals - did this come from untrusted content?"; "Action class" with
> "ReadOnly to Destructive - how much harm can this do?"; "Egress hosts" with "URLs / scp / IPv6 -
> where is the data going?"; "Authority" with "parent contains child tools - is the subagent
> overreaching?".
>
> Both columns converge with arrows into BAND 4: one wide PURPLE box "Policy engine" with beneath it
> "flat, first-match YAML - denies before asks".
>
> BAND 5: three outcome boxes side by side, colour-coded: GREEN "Allow" with "proceed"; AMBER "Ask"
> with "pause for the human"; RED "Deny" with "block before it runs".
>
> Small muted footnote at bottom left: "Three of the four threat classes reuse detectors that already
> existed - only taint tracking and action classification are new code."
>
> Colour palette: white background, dark slate text, blue #1f6feb, green #238636, amber #9e6a03, red
> #da3633, purple #8250df. Use a monospace font for code-like identifiers and sans-serif for prose.
> Render the text exactly as given, do not alter spelling.

## Pass 2 and 3 — corrections

> Delete the "BAND 1, " prefix so the header reads exactly "COLLECTORS - PHASE 09+, NOT YET BUILT".
> No occurrence of the word BAND should appear anywhere in the image. […] The purple bar must be a
> flat solid uniform rectangle of a single colour with crisp straight edges, and the surrounding
> background must be pure flat white with no gradient, glow, shading or texture anywhere in the
> image.

---

## Notes for regenerating

- **Say "BAND" only if you strip it later.** The word is useful for describing vertical layout and
  the renderer will happily print it as a label. Prefer "row" or describe position without a keyword.
- **Repeat the exact-text instruction at both the start and the end.** Text fidelity was accurate in
  every pass with it present; this is the failure mode these renderers are worst at.
- **Ask for corrections one small list at a time.** Broad re-prompts regenerate everything and can
  regress details that were already right.
- **Avoid `→`, `·`, `⊇` and em-dashes in the prompt.** They were replaced with `to`, `/` and `-`
  before submission; the renderer handles plain ASCII more reliably.
