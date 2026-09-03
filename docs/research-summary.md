# Research Summary

## Goal

The competition evaluated red-team algorithms that generate replayable prompt chains against sandboxed, tool-using language models. The score combined security predicate severity with diversity across observed tool-call behavior.

## Approach

The final work centered on a constrained attack-generation loop:

- generate compact, replayable candidate prompts rather than relying on a long interactive trace
- route prompt forms to the target model family where possible
- measure replay latency alongside predicate severity, since slow candidates reduce effective coverage
- vary destination identifiers to preserve scoring-cell diversity
- validate the contract locally with deterministic agents before launching a Kaggle submission

## Findings

- Direct exfiltration-style tool calls were the most stable high-severity behavior under the public evaluator.
- Tool-call format and continuation tokens had a larger latency effect than broad prompt rewrites.
- Multi-event candidates could increase raw severity but often lost to simple candidates once replay time was included.
- Candidate throughput and scoring-cell diversity were more predictive of submission quality than discovery-time complexity.
- Local probes were useful for rejecting weak ideas, but did not perfectly predict the hidden Kaggle evaluation distribution.

## Outcome

The project placed **473rd of 4,251 teams** (top **11.1%**) in my first Kaggle competition. The final representative implementation is SUB-019 v68 Dual-Heavy, which recorded `67.675` publicly and `2.415` privately. An earlier development submission reached the highest public score, `69.755`, but it was not the final selected implementation.

## Reproducibility

The competition SDK is distributed through Kaggle rather than as a normal package. After downloading the competition data and setting `PYTHONPATH`, run:

```bash
.venv/bin/python -m unittest discover -s tests
PYTHONPATH=data/competition:$PYTHONPATH .venv/bin/python scripts/local_dryrun.py --budget 60
```

The local dry run verifies the attack contract and scoring pipeline with a deterministic stand-in. It is not a substitute for a hidden Kaggle leaderboard score.
