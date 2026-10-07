"""ProofTrace — exploitability-first security review agent (100% local, no API key).

Pipeline: PR diff -> tree-sitter source->sink graph -> reachability ->
LangGraph investigation (local LLM) -> live Docker exploit validation -> proof.
"""

__version__ = "0.1.0"
