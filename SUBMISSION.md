# ProofTrace — Hacktron submission

**What I built:** an exploitability-first security review agent. It takes a pull
request, builds a source→sink reachability graph for the changed code with
tree-sitter, runs a LangGraph investigation over that graph, and validates the
exploit against a live instance in Docker before reporting anything — orchestrated
durably on Temporal. A finding is reported only once there is a proof.

**The one line:** I didn't just make an agent find a bug — I rebuilt a faithful
miniature of your pipeline (statically-built reachability, LLM-as-investigator, a
validation gate) and measured **cost-to-recall** across local models the way
*Why Mythos doesn't matter* does. 100% local, no API key.

## See it

| | link |
|---|---|
| 90-second demo (GIF) | [`demo/prooftrace.gif`](demo/prooftrace.gif) |
| Live VERIFIED finding on a real PR | https://github.com/4yru5/prooftrace-target/pull/1#issuecomment-6036104438 |
| The PR it reviewed | https://github.com/4yru5/prooftrace-target/pull/1 |
| Reachability graph (proven path in red) | [`artifacts/graph_proven.svg`](artifacts/graph_proven.svg) |
| Cost-to-recall convergence chart | [`artifacts/cost_to_recall.png`](artifacts/cost_to_recall.png) |

## JD requirement → proof

| Hacktron JD signal | Where it's demonstrated (not just claimed) |
|---|---|
| **Python** | the whole engine: [`prooftrace/`](prooftrace/) |
| **Temporal** (durable execution) | [`prooftrace/workflow.py`](prooftrace/workflow.py) — `ProofTraceWorkflow` (per-stage retries + cost ledger) and `CostToRecallWorkflow` (durable fan-out of N cheap runs); worker [`prooftrace/worker.py`](prooftrace/worker.py); run it: `make temporal` (Web UI :8233) |
| **LangGraph** (agent state machines) | [`prooftrace/investigation.py`](prooftrace/investigation.py) — explicit nodes: context → hypothesis → reachability-checker → exploit-planner → validator → evidence/re-analyze, with a gate that rejects hallucinated targets |
| **tree-sitter** | [`prooftrace/extract.py`](prooftrace/extract.py) — real AST walk recovering routes, sources, sinks, sanitizers, call edges |
| **Docker** | [`prooftrace/validator.py`](prooftrace/validator.py) builds + runs the target container and exploits it live; [`target_app/Dockerfile`](target_app/Dockerfile), [`docker-compose.yml`](docker-compose.yml) |
| **Reachability / compilers** | [`prooftrace/reachability.py`](prooftrace/reachability.py) — source→sink with ownership-guard detection; precision contrast renders in [`artifacts/graph_proven.svg`](artifacts/graph_proven.svg) |
| **Web-app vuln knowledge** | BOLA / IDOR (CWE-639) — semantic, not syntactic: [`target_app/app/main.py`](target_app/app/main.py). A same-shape ownership-filtered endpoint is correctly **cleared** (precision) |
| **Automated testing** | [`tests/`](tests/) — 14 tests incl. `test_graph_rejects_hallucinated_target` (a lying model can't manufacture a VERIFIED finding) and live exploit reproduction |
| **CI/CD** | [`.github/workflows/security.yml`](.github/workflows/security.yml) — runs the review + tests; executable locally with `act` (no token); `make watch` re-runs the gate on every change |
| **Distributed / systems thinking** | Temporal fan-out + cost ledger is the *honest* motivation for durability — the cost-to-recall thesis made executable; recall/precision split mirrors the published pipeline |
| **Nice-to-have: HackBench familiarity** | [`target_app/challenge.json`](target_app/challenge.json) — the target is built in HackBench's format (Dockerized target + planted flag) and ProofTrace solves it end to end |

## Honest notes

- **Cost-to-recall chart is currently illustrative** (generated from the
  deterministic offline investigator). The local Ollama model pull
  (`qwen2.5-coder:7b`) was throttled at record time (~0.3 MB/s). Regenerate from
  real local runs with `make pull-models && make chart`; the pipeline and logging
  are identical — only the model provider changes.
- **The live proof is real.** The VERIFIED finding on the PR comes from the
  validator running the exploit against the app in Docker — user A reading user
  B's invoice, with the planted flag — not from an LLM opinion.
- Reachability-first + LLM-as-investigator is **Hacktron's published
  architecture**, rebuilt faithfully for fluency, not claimed as novel.
- This nails **variant analysis** of a known class (BOLA) — the bulk of real web
  vulns and Hacktron's current focus — and is honest that that is what it is.

Repos: portfolio https://github.com/4yru5/prooftrace · demo target
https://github.com/4yru5/prooftrace-target
