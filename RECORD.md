# ProofTrace — recording kit

Everything you need to record the <90s demo. Record each segment separately and
stitch — it removes the risk of one live hang. The two moments that must land
cleanly are the **live proof** (the PR comment) and the **cost-to-recall chart**;
give each a half-second of silence to breathe. End on the closing line and cut.

**Key assets / URLs**
- Portfolio repo: https://github.com/4yru5/prooftrace
- Demo-target PR (the live proof): https://github.com/4yru5/prooftrace-target/pull/1
- Posted VERIFIED finding: https://github.com/4yru5/prooftrace-target/pull/1#issuecomment-6036104438
- Temporal Web UI: http://localhost:8233
- Cost chart: `artifacts/cost_to_recall.png`
- Reachability graph: `artifacts/graph_proven.svg`
- Pre-recorded terminal demo (b-roll): `demo/prooftrace.gif` / `.mp4`

---

## Pre-record checklist

- [ ] Ollama up with models pulled: `ollama list` shows `qwen2.5-coder:7b` (and `:14b`).
      *(If the pull hasn't finished, the terminal demo still runs on the deterministic
      investigator — see the honesty note on the cost line below.)*
- [ ] `make chart` run **after** models are pulled, so `artifacts/cost_to_recall.png`
      is from real runs. Then the cost-line script below is literally true.
- [ ] `make temporal` running; http://localhost:8233 open on the workflow history
      (trigger one run so there's a completed `ProofTraceWorkflow` with activities).
- [ ] The PR page open and scrolled to the ProofTrace comment:
      https://github.com/4yru5/prooftrace-target/pull/1
- [ ] `artifacts/cost_to_recall.png` open full-screen in an image viewer.
- [ ] Terminal sized ~120×40, dark theme, font ≥14pt. Warm the demo once so it's cached.
- [ ] Screen recorder set to 1080p; mic tested; notifications silenced.

---

## Shot list (in order)

| # | Source on screen | Command / URL |
|---|---|---|
| 1 | Terminal — title + PR diff + live TUI | `make demo` (or play `demo/prooftrace.gif`) |
| 2 | Browser — Temporal workflow history | http://localhost:8233 → latest `ProofTraceWorkflow` |
| 3 | Browser — the posted finding on the PR | PR comment URL above |
| 4 | Image viewer — convergence chart | `artifacts/cost_to_recall.png` |
| 5 | Terminal — closing card | tail of `make demo` (the "fewer findings" panel) |

> Segments 1 and 5 both come from `make demo`; shoot the full `make demo` once and
> lift the opening (title→TUI) and the ending (closing card) from it. Shoot 2/3/4 as
> their own short clips and stitch in order.

---

## Locked voiceover script (~88s)

Narration is ~2 words/second, so each line is already near its spoken length.

| Time | On screen | You say |
|---|---|---|
| 0:00–0:08 | Title card (`make demo` opening) | "I built a security reviewer that doesn't stop at suspicion — it proves a vulnerability is reachable and exploitable before it says a word. All local, no API key." |
| 0:08–0:16 | PR diff | "Here's a pull request adding an invoice endpoint. It's authenticated, and the query is parameterized — so a scanner sees nothing." |
| 0:16–0:30 | tree-sitter graph + candidate lighting up | "ProofTrace parses the change with tree-sitter and builds a source-to-sink graph. The path parameter is attacker-controlled and reaches a database read — with no ownership check on the way." |
| 0:30–0:42 | LangGraph nodes advancing | "A LangGraph investigation takes over. The model isn't asked for a verdict — each node has a job: form a hypothesis, prove reachability, plan an exploit. The graph decides what's real, not the model." |
| 0:42–0:50 | Temporal Web UI (history + a retry) | "It runs on Temporal, so the investigation is durable — the expensive validation step retries on its own instead of restarting the whole agent." |
| 0:50–1:04 | **The PR comment on GitHub** *(peak 1 — half-second of silence first)* | "Then it proves it. In a sandbox, user A's token fetches user B's invoice — a live two-hundred OK, flag and all. That's not a guess. It's a reproduced exploit, posted straight to the PR." |
| 1:04–1:20 | **Cost-to-recall chart** *(peak 2 — half-second of silence first)* | "Then I did what your Mythos post argues: run a small model many times instead of a big one once. Looped, it converges on the same proven finding — recall you buy with compute, not money." |
| 1:20–1:28 | Closing card | "The goal isn't more findings. It's fewer findings we can actually prove." |

**Total: ~88s.** If you run long, trim the Temporal segment to 6s ("durable —
retries on its own") — never cut the live proof or the cost chart.

### Honesty note on the cost line (0:04 segment)
The committed chart is currently **illustrative** (deterministic investigator),
because the Ollama model pull was throttled. Two options, both honest:
- **After** `make pull-models && make chart`: say the line as written ("I ran a
  small model many times…") — it's now from your own runs.
- **Before** that: say instead — *"This is the shape your Mythos argument predicts;
  the chart regenerates from real local runs with one command."* Do **not** claim
  real numbers until the chart is real.

---

## Recording tips
- Pre-run everything so Temporal and the sandbox are warm — you're capturing a
  known-good run, not debugging live.
- Record segments separately and stitch; re-record a clean take rather than
  shipping one where something stalls.
- Optional fully-local voiceover: generate narration with Piper TTS from the
  script text and mux with `ffmpeg` — no cloud, no key.
