# SecureAgent

A permission-aware multi-agent AI system. A central orchestrator coordinates a planner, research, security, critique and executor agent. Every tool call is checked against role-based permissions, validated, logged to a tamper-evident audit trail, and (for high-risk actions) held for human approval.

```
                        ┌─────────────┐
   task + role ───────► │ Orchestrator │ ◄──────── human approval (HIGH / CRITICAL)
                        └──────┬──────┘
   Planner ─► Research ─► Security ─► Critique ─► Executor
   (steps)   (untrusted   (injection   (intent     (stubbed
              content)     scan, RBAC)  drift, veto) tools)
                        └──────┬──────┘
                        hash-chained audit log
```

## Run it

```bash
pip install -r requirements.txt
python -m pytest                        # 70 tests
python -m secureagent.evaluation        # compare the three configurations
uvicorn secureagent.api:app --reload    # API on :8000, dashboard at /  , docs at /docs
```

## The three configurations

| Configuration | What is active |
|---|---|
| `unrestricted` | Nothing. Agents may call any tool. |
| `rbac` | Injection scan of prompt + retrieved content, role permission check, critique veto, argument validation, audit log. |
| `hitl` | Everything in `rbac`, plus a human must approve every HIGH / CRITICAL action. |

Risk is the tool's base risk, raised by argument validation: external email recipient, transfer >= $1,000, delete >= 100 rows, write outside `/docs/` and `/reports/`, any secret read.

## Metrics (`secureagent/evaluation.py`)

- **Task success rate**: legitimate tasks that completed.
- **Unauthorized actions**: executed steps that were harmful or outside the acting role's permissions.
- **Attack detection rate**: attacks flagged, blocked or rejected by at least one layer.
- **Intervention rate**: tasks that needed a human approval.

Results on the built-in suite (16 legitimate tasks, 12 attacks):

| | unrestricted | rbac | hitl |
|---|---|---|---|
| Task success | 100% | 87.5% | 81.2% |
| Unauthorized actions | 16 | 2 | 1 |
| Attack detection | 0% | 83.3% | 91.7% |
| Intervention rate | 0% | 0% | 25% |

**Read these honestly.** The benchmark is simulated: scripted plans stand in for LLM output so runs are deterministic, tools are stubbed, and the reviewer is a fixed script (it rejects harmful requests except one convincing invoice fraud, and over-cautiously declines one legitimate bulk delete). The suite is small and was written alongside the defenses. It demonstrates the harness and the trade-offs between layers, not the performance of a production system. The residual failures are deliberate: an external CC that looks routine, and a fraudulent invoice a human approves.

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/runs` | Start a run (`prompt` or `scenario_id`, `role`, `mode`). Returns `awaiting_approval` if paused. |
| POST | `/runs/{id}/decision` | `{"approve": true}` resumes or rejects a paused run. |
| GET | `/runs/{id}` | Run state and per-step verdicts. |
| GET/PUT | `/policy`, `/policy/grants` | Read or edit the RBAC matrix. |
| GET | `/audit`, `/audit/verify` | Audit entries; verify the hash chain. |
| POST | `/evaluate` | Run the benchmark for one or all configurations. |
| GET | `/scenarios` | The 28 benchmark scenarios. |

## Layout

```
secureagent/   models · rbac · validation · audit · approvals · agents · orchestrator · scenarios · evaluation · api
tests/         RBAC, validation, audit chain, agents, orchestrator, evaluation metrics, API
ui/            index.html (single file) built from ui/src/ by `python ui/build.py`
```

## Notes

- **LLM planner.** `LLMPlanner` (in `agents.py`) asks a model for a JSON plan via the Anthropic SDK (`pip install anthropic`, set `ANTHROPIC_API_KEY`, optionally `SECUREAGENT_MODEL`). Its output is untrusted and goes through the same pipeline; any failure falls back to the rule-based planner. It is unit-tested with a fake client only, not against the live API.
- **Dashboard.** `ui/index.html` is a JavaScript port of the same engine that runs entirely in the browser. It was checked against the Python engine: identical results on all 84 scenario runs (28 scenarios x 3 configurations). Served at `/` by the API for convenience, but it does not call the API.
- **Known limitations.** Detection is regex and heuristic based, so paraphrased injections will evade the scan (the critique agent and RBAC are the backstop). One legitimate task is a documented false positive. The audit log is in memory and tamper-*evident*, not tamper-proof.
