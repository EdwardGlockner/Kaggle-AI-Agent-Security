# AI Agent Security: Multi-Step Tool Attacks

My first Kaggle competition: [AI Agent Security: Multi-Step Tool Attacks](https://www.kaggle.com/competitions/ai-agent-security-multi-step-tool-attacks).

**Result:** 473rd out of 4,251 teams, top 11.1%.

## Overview

Kaggle gives the program a language model with access to tools such as web requests and email. The goal is to find short messages that make the model use one of those tools in a security-relevant way. Kaggle then replays the successful messages against hidden evaluation rows.

The submission works like an attack generator. It sends a candidate message, watches the tool call the model actually makes, and keeps the message only when that call triggers one of the competition's scoring rules. It then repeats the process with different prompt forms and different fake destinations.

In practice, a useful candidate had to satisfy three conditions at once:

- The model has to follow it and make a tool call.
- The tool call has to trigger a scored security predicate.
- It has to be cheap enough to replay many times before the time budget expires.

The evaluator rewarded both severity and diversity. Finding one strong behavior was not enough; repeating an identical tool-call pattern stopped adding value. At the same time, a prompt that produced more actions could be worse overall if it made the model spend too long generating them.

## How My Solution Works

The final implementation is [kaggle_submission.py](kaggle_submission.py). Each candidate follows this path:

```text
prompt template -> model tool call -> execution trace -> predicate check -> deduplication -> replayable candidate
```

1. The submission first looks for model metadata in the environment. If that information is unavailable, it runs a small timing probe to distinguish the GPT-OSS and Gemma backends.
2. It generates a repeating four-prompt bundle. Three prompts ask for a compact `http.post` call; the fourth combines a notification request with the same post action. The destination URL changes on every candidate so the replayed actions are not all the same scoring cell.
3. Before each candidate, it resets the environment. It allows only one tool hop, because the score was recorded on the tool action and waiting for the model's follow-up response was usually wasted time.
4. After each message, it reads the trace and evaluates the competition predicates. When a predicate fires, it keeps only the shortest prefix that caused it.
5. It hashes the observed tool-call cell and drops duplicates. It stops at the candidate cap, maximum-step limit, or a deadline that reserves 60 seconds for the evaluator.

The result is deliberately conservative: every returned candidate was verified in the environment before being handed back to Kaggle for replay.

## What I Learned

- Short, direct tool-call prompts were more reliable than long multi-step instructions on CPU-bound evaluation.
- Latency mattered as much as raw severity. A multi-event prompt could look impressive in a small probe and still lose over a full submission run because it was slow.
- Varying the URL and mixing a second prompt family helped reach more scoring cells, but it did not compensate for unreliable model behavior.
- Local tests were excellent for ruling out weak ideas. They were not a perfect predictor of the hidden evaluation distribution, so each major change still had to be tested through a real Kaggle submission.

## Repository Guide

- [kaggle_submission.py](kaggle_submission.py): final competition submission.
- [scripts/local_dryrun.py](scripts/local_dryrun.py): end-to-end local run with a deterministic stand-in agent.
- [scripts/scoring_oracle.py](scripts/scoring_oracle.py): smaller check that the candidate stream reaches the scorer.
- [tests/](tests): contract tests for candidate generation, limits, deduplication, and predicate handling.
- [docs/research-summary.md](docs/research-summary.md): experiment conclusions and limitations.

## Run Locally

Kaggle distributed the SDK with the competition data rather than as a normal Python package. After accepting the competition rules and downloading the data:

```bash
python -m pip install kaggle
kaggle competitions download -c ai-agent-security-multi-step-tool-attacks -p data
unzip data/ai-agent-security-multi-step-tool-attacks.zip -d data/competition

export PYTHONPATH="$PWD/data/competition:$PYTHONPATH"
.venv/bin/python -m unittest discover -s tests
.venv/bin/python scripts/local_dryrun.py --budget 60
```

The local dry run checks the integration and scoring path with a deterministic agent. It does not reproduce the hidden Kaggle leaderboard.

For Kaggle packaging, this file was written to `/kaggle/working/attack.py`, which is the filename expected by the competition evaluator.

## Responsible Use

This project documents work performed in a controlled competition sandbox. It is for authorized evaluation and defensive research on tool-using AI systems. Do not apply these techniques to systems, data, or services without permission.
