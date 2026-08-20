"""E2 cross-model transfer diagnostic runner (see RESEARCH_PLAN.md).

Reads validated finding sets produced by E1 (``experiments/e1_characterize.py``)
and replays each source model's ``user_messages`` against every requested
target model through the same authoritative replay path used by the evaluator.
Records per-predicate-class transfer rates.

Input: one or more ``artifacts/EXP-004-*/`` directories, each containing
``report.json`` (used for source-model identity) and ``findings.jsonl``.

Output under ``--artifacts-dir``:
- ``transfer_matrix.json`` — aggregated per-pair, per-predicate rates
- ``<source_id>__vs__<target_agent>/replayed.jsonl`` — per-finding replay log

Read-only w.r.t. the SDK; no candidate generation.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from aicomp_sdk.agents import AgentSelection, build_agent_factory  # noqa: E402
from aicomp_sdk.core.env.sandbox import SandboxEnv  # noqa: E402
from aicomp_sdk.core.predicates import eval_predicates  # noqa: E402
from aicomp_sdk.guardrails.optimal import Guardrail as OptimalGuardrail  # noqa: E402

DEFAULT_FIXTURES = Path("data/competition/aicomp_sdk/fixtures")

_AGENT_ALIASES: dict[str, AgentSelection] = {
    "deterministic": AgentSelection.DETERMINISTIC,
    "gpt_oss": AgentSelection.GPT_OSS,
    "gpt-oss": AgentSelection.GPT_OSS,
    "gemma": AgentSelection.GEMMA,
    "gemma_4": AgentSelection.GEMMA_4,
    "gemma-4": AgentSelection.GEMMA_4,
}


def _resolve_agent(name: str) -> AgentSelection:
    try:
        return _AGENT_ALIASES[name.lower()]
    except KeyError as exc:
        allowed = ", ".join(sorted(set(_AGENT_ALIASES)))
        raise SystemExit(f"unknown agent {name!r}; expected one of: {allowed}") from exc


def _predicate_name(predicate: Mapping[str, Any]) -> str:
    for key in ("name", "id", "predicate", "type"):
        val = predicate.get(key)
        if isinstance(val, str) and val:
            return val
    return "UNKNOWN"


def _load_findings(path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            findings.append(json.loads(line))
    return findings


def _identify_source(source_dir: Path) -> dict[str, Any]:
    report_path = source_dir / "report.json"
    if not report_path.exists():
        raise SystemExit(f"missing report.json under {source_dir}")
    report = json.loads(report_path.read_text())
    return {
        "source_dir": str(source_dir),
        "source_id": source_dir.name,
        "source_agent": report.get("agent"),
        "source_seed": report.get("attack_env_seed"),
    }


def _replay_one(
    *,
    seed: int,
    user_messages: Sequence[str],
    agent_factory,
    fixtures_dir: Path,
) -> dict[str, Any]:
    env = SandboxEnv(
        seed=seed,
        fixtures_dir=fixtures_dir,
        agent=agent_factory(),
        guardrail=OptimalGuardrail(),
    )
    env.reset()
    for msg in user_messages:
        env.interact(msg)
    return env.export_trace_dict()


def _transfer_status(
    source_predicates: Iterable[Mapping[str, Any]],
    replayed_predicates: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    source_names = {_predicate_name(p) for p in source_predicates}
    replayed_names = {_predicate_name(p) for p in replayed_predicates}
    return {
        "source_predicates": sorted(source_names),
        "replayed_predicates": sorted(replayed_names),
        "any_transfer": bool(replayed_names),
        "same_predicate_transfer": bool(source_names & replayed_names),
        "overlap": sorted(source_names & replayed_names),
    }


def _empty_pair_stats() -> dict[str, Any]:
    return {
        "n_source_findings": 0,
        "n_replayed": 0,
        "n_any_transfer": 0,
        "n_same_predicate_transfer": 0,
        "per_source_predicate": defaultdict(
            lambda: {
                "n_source_findings": 0,
                "n_same_predicate_transfer": 0,
                "n_any_transfer": 0,
            }
        ),
    }


def _finalize_pair_stats(stats: dict[str, Any]) -> dict[str, Any]:
    per_pred = stats["per_source_predicate"]
    finalized_pred: dict[str, dict[str, Any]] = {}
    for name, agg in per_pred.items():
        n = agg["n_source_findings"] or 1
        finalized_pred[name] = {
            **agg,
            "rate_same_predicate": agg["n_same_predicate_transfer"] / n,
            "rate_any_transfer": agg["n_any_transfer"] / n,
        }
    n = stats["n_source_findings"] or 1
    return {
        "n_source_findings": stats["n_source_findings"],
        "n_replayed": stats["n_replayed"],
        "n_any_transfer": stats["n_any_transfer"],
        "n_same_predicate_transfer": stats["n_same_predicate_transfer"],
        "rate_any_transfer": stats["n_any_transfer"] / n,
        "rate_same_predicate_transfer": stats["n_same_predicate_transfer"] / n,
        "per_source_predicate": finalized_pred,
    }


def run(args: argparse.Namespace) -> int:
    artifacts_dir = Path(args.artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    fixtures_dir = Path(args.fixtures_dir)

    sources = [Path(s) for s in args.source]
    for src in sources:
        if not src.is_dir():
            raise SystemExit(f"source is not a directory: {src}")

    target_selections = [(name, _resolve_agent(name)) for name in args.target]

    transfer_matrix: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    started = time.monotonic()

    for source_dir in sources:
        source_meta = _identify_source(source_dir)
        source_findings = _load_findings(source_dir / "findings.jsonl")
        if args.max_findings_per_source is not None:
            source_findings = source_findings[: args.max_findings_per_source]

        for target_name, target_selection in target_selections:
            pair_dir = artifacts_dir / f"{source_meta['source_id']}__vs__{target_name}"
            pair_dir.mkdir(parents=True, exist_ok=True)
            agent_factory = build_agent_factory(target_selection)

            stats = _empty_pair_stats()
            stats["n_source_findings"] = len(source_findings)

            with (pair_dir / "replayed.jsonl").open("w") as out_fh:
                for idx, finding in enumerate(source_findings):
                    user_messages = list(finding.get("user_messages", []))
                    seed = int(finding.get("seed", source_meta["source_seed"] or 123))
                    replay_trace = _replay_one(
                        seed=seed,
                        user_messages=user_messages,
                        agent_factory=agent_factory,
                        fixtures_dir=fixtures_dir,
                    )
                    replayed_predicates = eval_predicates(replay_trace)
                    status = _transfer_status(
                        finding.get("predicates", []), replayed_predicates
                    )
                    stats["n_replayed"] += 1
                    if status["any_transfer"]:
                        stats["n_any_transfer"] += 1
                    if status["same_predicate_transfer"]:
                        stats["n_same_predicate_transfer"] += 1
                    for pred_name in status["source_predicates"]:
                        agg = stats["per_source_predicate"][pred_name]
                        agg["n_source_findings"] += 1
                        if pred_name in status["overlap"]:
                            agg["n_same_predicate_transfer"] += 1
                        if status["any_transfer"]:
                            agg["n_any_transfer"] += 1

                    out_fh.write(
                        json.dumps(
                            {
                                "index": idx,
                                "seed": seed,
                                "user_messages": user_messages,
                                "source_predicates": status["source_predicates"],
                                "replayed_predicates": status["replayed_predicates"],
                                "same_predicate_transfer": status["same_predicate_transfer"],
                                "any_transfer": status["any_transfer"],
                            },
                            default=str,
                        )
                        + "\n"
                    )

            transfer_matrix[source_meta["source_id"]][target_name] = {
                "source_agent": source_meta["source_agent"],
                "target_agent": target_name,
                **_finalize_pair_stats(stats),
            }

    payload = {
        "fixtures_dir": str(fixtures_dir),
        "guardrail": "optimal_public",
        "sources": [_identify_source(Path(s)) for s in args.source],
        "targets": [name for name, _ in target_selections],
        "wall_time_s": time.monotonic() - started,
        "transfer_matrix": transfer_matrix,
    }
    (artifacts_dir / "transfer_matrix.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str)
    )

    summary = {
        source_id: {
            target: {
                k: v
                for k, v in cell.items()
                if k
                in {
                    "rate_any_transfer",
                    "rate_same_predicate_transfer",
                    "n_source_findings",
                }
            }
            for target, cell in row.items()
        }
        for source_id, row in transfer_matrix.items()
    }
    print(json.dumps({"transfer_summary": summary}, indent=2, sort_keys=True))
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="E2 cross-model transfer diagnostic")
    parser.add_argument(
        "--source",
        nargs="+",
        required=True,
        help="One or more EXP-004 artifact directories (each contains findings.jsonl and report.json).",
    )
    parser.add_argument(
        "--target",
        nargs="+",
        required=True,
        help=f"Target agent names to replay against; from: {sorted(set(_AGENT_ALIASES))}",
    )
    parser.add_argument("--fixtures-dir", default=str(DEFAULT_FIXTURES))
    parser.add_argument("--artifacts-dir", required=True)
    parser.add_argument(
        "--max-findings-per-source",
        type=int,
        default=None,
        help="Cap replays per source (default: all findings).",
    )
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(run(_parse_args()))
