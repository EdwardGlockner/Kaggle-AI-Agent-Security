# AI Agent Security: Multi-Step Tool Attacks

Final research implementation for Kaggle's [AI Agent Security: Multi-Step Tool Attacks](https://www.kaggle.com/competitions/ai-agent-security-multi-step-tool-attacks) competition.

## Result

- Final placement: **473 / 4251**
- Percentile: **top 11.1%**
- Final representative submission: **SUB-019 v68 Dual-Heavy**
- Final SUB-019 scores: **67.675 public / 2.415 private**
- Best public development score: **69.755** (SUB-007)
- Final evaluated on **September 2, 2026**

This was my first Kaggle competition. The project focused on red-teaming tool-using agents by generating replayable prompt chains that trigger security findings under a constrained evaluator.

## What This Repo Does

The submission runs `AttackAlgorithm.run(env, config)` from `kaggle_submission.py`. The algorithm explores a sandboxed tool-using agent and returns replayable `AttackCandidate` prompt sequences whose traces trigger a scoring predicate.

The project concentrates on the final selected submission and a deterministic validation harness. The full time-ordered notebook and submission archive is retained locally but intentionally excluded from the public repository.

## Project Highlights

- Built a reproducible experiment loop across local tests and Kaggle-hosted notebooks
- Investigated scoring behavior, replay limits, latency bottlenecks, and candidate diversity
- Compared multiple attack families, including direct exfiltration, mixed-surface prompts, multi-event prompts, and minimal-discovery emitters
- Summarized the key findings and limitations in [the research summary](docs/research-summary.md)

## Repo Structure

- [kaggle_submission.py](kaggle_submission.py): the final SUB-019 v68 Dual-Heavy implementation
- [scripts/scoring_oracle.py](scripts/scoring_oracle.py): deterministic evaluator smoke check
- [scripts/local_dryrun.py](scripts/local_dryrun.py): end-to-end dry run with a compliant stand-in agent
- [docs/research-summary.md](docs/research-summary.md): methods, findings, and final outcome
- [tests/](tests): contract and integration tests

## Why `kaggle_submission.py`?

This is the one implementation that represents the final leaderboard result. SUB-019 was the only selected final submission with a nonzero private score; Kaggle required its source to be named `attack.py`, so the notebook copied this file to `/kaggle/working/attack.py` before starting the evaluator.

## Competition Contract

- Target models: GPT-OSS 20B and Gemma 4 26B-A4B-it
- Environment methods: `reset`, `interact`, `export_trace_dict`, `snapshot`, `restore`
- Limits: 2,000 candidates, 32 messages per candidate, 10,000 characters per message, and 8 tool hops per interaction
- Score: predicate severity plus tool-call-signature diversity, normalized to `0-1000`
- Submission format: Kaggle notebook that writes `/kaggle/working/attack.py` and starts `JEDAttackInferenceServer`

## Setup

Accept the competition rules, install the Kaggle CLI, and download the SDK-backed competition data:

```bash
python -m pip install kaggle
kaggle competitions download -c ai-agent-security-multi-step-tool-attacks -p data
unzip data/ai-agent-security-multi-step-tool-attacks.zip -d data/competition
```

The SDK is distributed with the competition data rather than as a standard dependency. Add the extracted dataset root to `PYTHONPATH` for local experiments:

```bash
export PYTHONPATH="$PWD/data/competition:$PYTHONPATH"
```

Run the lightweight contract tests:

```bash
python -m unittest discover -s tests
```

## Validation

Run the deterministic end-to-end smoke test:

```bash
PYTHONPATH=data/competition:$PYTHONPATH .venv/bin/python scripts/local_dryrun.py --budget 60
```

## Submission Context

In a competition notebook, attach the competition data, write the contents of `kaggle_submission.py` to `/kaggle/working/attack.py`, then start the inference server:

```python
import kaggle_evaluation.jed_attack_134815.jed_attack_inference_server

server = kaggle_evaluation.jed_attack_134815.jed_attack_inference_server
server.JEDAttackInferenceServer().serve()
```

Notebook startup only validates packaging. The real scoring happens during Kaggle's rerun.

## Responsible Use

This repository documents controlled research performed within a Kaggle competition sandbox. It is intended for evaluation, defensive research, and improving tool-using agent safeguards. Do not apply these techniques to systems, data, or services without explicit authorization.
