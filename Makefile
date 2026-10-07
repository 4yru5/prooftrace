.DEFAULT_GOAL := help
UV := uv run
export PROOFTRACE_SANDBOX ?= auto
export PROOFTRACE_LLM ?= auto

.PHONY: help setup pull-models demo demo-fast record analyze graph cost watch \
        test target-up target-down temporal clean

help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n",$$1,$$2}'

setup: ## install python deps + docker config
	uv sync
	@test -f .docker-clean/config.json || (mkdir -p .docker-clean && cp -R $$HOME/.docker/* .docker-clean/ 2>/dev/null; \
	  $(UV) python -c "import json;p='.docker-clean/config.json';d=json.load(open(p));d.pop('credsStore',None);d.pop('credHelpers',None);json.dump(d,open(p,'w'))" 2>/dev/null || echo '{}' > .docker-clean/config.json)
	@echo "setup done. Optional: 'make pull-models' for the real local LLM."

pull-models: ## pull local Ollama models (optional; demo works without them)
	ollama pull qwen2.5-coder:7b
	ollama pull qwen2.5-coder:1.5b

demo: ## the self-running demo (uses Ollama if present, else deterministic stub)
	$(UV) prooftrace demo --runs 14

demo-fast: ## quick demo (compressed timing, for iteration)
	PROOFTRACE_FAST=1 $(UV) prooftrace --llm stub --backend subprocess demo --runs 12

demo-record: ## deterministic, paced demo used by the VHS recording
	PROOFTRACE_LLM=stub PROOFTRACE_SANDBOX=subprocess PROOFTRACE_PACE=2.3 \
	  $(UV) prooftrace demo --runs 14

record: ## record the demo to a GIF/MP4 with VHS (deterministic, no stall)
	vhs demo/demo.tape
	@echo "recorded -> demo/prooftrace.gif (+ .mp4)"

analyze: ## run the investigation on the PR, write artifacts + PR comment
	$(UV) prooftrace analyze

graph: ## render the reachability graph (DOT + SVG)
	$(UV) prooftrace graph

cost: ## run the cost-to-recall experiment and plot the convergence curve
	$(UV) prooftrace cost-to-recall --runs 20

chart: ## regenerate the cost-to-recall chart (alias of cost; uses Ollama if present)
	$(UV) prooftrace cost-to-recall --runs 24

watch: ## continuous review: re-run the gate on every change to the target
	$(UV) prooftrace watch

test: ## run the back-to-back test suite
	$(UV) pytest -q

target-up: ## run the vulnerable target app in Docker (docker compose up)
	DOCKER_CONFIG=$(PWD)/.docker-clean docker compose up --build

target-down: ## stop the target container
	DOCKER_CONFIG=$(PWD)/.docker-clean docker compose down

temporal: ## run the investigation through Temporal (needs dev server + worker)
	@bash scripts/temporal_demo.sh

clean: ## remove generated artifacts
	rm -rf artifacts/*.png artifacts/*.svg artifacts/*.dot artifacts/*.json \
	       demo/prooftrace.gif demo/prooftrace.mp4
