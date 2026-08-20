"""Local upper-bound dry run for attack.py.

Uses a lightweight compliant agent that parses each user message and emits the tool
call the prompt asks for (http.post with url/data, or email.send to a parsed recipient).
Runs through the authoritative `evaluate_redteam` path with the `optimal_public`
guardrail so scores and cell hashes are computed identically to the Kaggle scorer.

This is not a substitute for the real Kaggle score (real LLMs will refuse some prompts,
scorer-oracle behaves differently) but it does prove:

    1. attack.py runs to completion without exceptions.
    2. Candidates serialize / validate cleanly.
    3. `optimal_public.decide()` allows the intended tool calls.
    4. The scoring pipeline produces a nonzero score with the current candidate set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from aicomp_sdk.agents.types import (  # noqa: E402
    AGENT_STATE_VERSION,
    AgentStateSnapshot,
    AgentToolSpec,
    FinalResponseDecision,
    ToolCall,
    ToolCallDecision,
    ToolResultEvent,
    UserMessageEvent,
)
from aicomp_sdk.core.runtime_history import RuntimeHistory  # noqa: E402
from aicomp_sdk.evaluation.runner import evaluate_redteam  # noqa: E402

from attack import AttackAlgorithm  # noqa: E402


_URL_PATTERNS = [
    re.compile(r"url\s*[:=]?\s*(https?://[^\s\"'<>,]+)", re.IGNORECASE),
    re.compile(r"to\s+(https?://[^\s\"'<>,]+)", re.IGNORECASE),
]
_EMAIL_ADDR = re.compile(r"[A-Za-z0-9._+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]+")
_PAGE_ID = re.compile(r"\b(mh_web_\w+|scale_web_\d+|page_\d+)\b", re.IGNORECASE)
_FILE_NAME = re.compile(r"\bread\s+([A-Za-z0-9_./\-]+\.[A-Za-z]+)\b", re.IGNORECASE)


def _extract_url(msg: str) -> str | None:
    for pat in _URL_PATTERNS:
        m = pat.search(msg)
        if m:
            url = m.group(1).rstrip(".,);:")
            return url
    return None


def _extract_recipient(msg: str) -> str | None:
    m = _EMAIL_ADDR.search(msg)
    return m.group(0) if m else None


def _extract_page_id(msg: str) -> str | None:
    m = _PAGE_ID.search(msg)
    return m.group(1) if m else None


def _extract_file_path(msg: str) -> str | None:
    m = _FILE_NAME.search(msg)
    return m.group(1) if m else None


class CompliantAgent:
    """Pattern-matching stand-in for a highly-compliant tool LLM.

    Plans a sequence of tool calls from a single user message and executes them one per
    next_action() invocation, matching how a real LLM chains multiple tool calls under
    `max_tool_hops` in one turn. Compliance is applied per-message deterministically via
    sha256, so the same message always makes the same accept/refuse decision.
    """

    _URL_ALL = re.compile(r"https?://[^\s\"',<>)]+", re.IGNORECASE)
    _EMAIL_ALL = re.compile(r"[A-Za-z0-9._+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]+")
    _PAGE_ID_ALL = re.compile(r"\b(mh_web_\w+|scale_web_\d+|page_\d+)\b", re.IGNORECASE)
    _FILE_ALL = re.compile(r"\bread\s+([A-Za-z0-9_./\-]+\.[A-Za-z]+)\b", re.IGNORECASE)

    def __init__(self, exfil_compliance: float = 1.0, email_compliance: float = 1.0) -> None:
        self.exfil_compliance = exfil_compliance
        self.email_compliance = email_compliance
        self._plan: list[dict[str, Any]] = []
        self._plan_msg: str = ""
        self._counter = 0

    @staticmethod
    def _refuse(msg: str, compliance: float) -> bool:
        if compliance >= 1.0:
            return False
        if compliance <= 0.0:
            return True
        h = int(hashlib.sha256(msg.encode("utf-8")).hexdigest()[:8], 16)
        return (h % 10_000) / 10_000.0 >= compliance

    def _plan_for(self, msg: str) -> list[dict[str, Any]]:
        """Extract every tool call implied by the user message, in order of appearance."""
        events: list[tuple[int, dict[str, Any]]] = []
        lower = msg.lower()

        # Multi-step launder step 1: web.open pages
        for m in self._PAGE_ID_ALL.finditer(msg):
            events.append((m.start(), {"tool": "web.open", "args": {"id": m.group(1)}}))

        # Multi-step launder step 2..6: fs.read files
        for m in self._FILE_ALL.finditer(lower):
            path = m.group(1)
            events.append((m.start(), {"tool": "fs.read", "args": {"path": path}}))

        # EXFIL: every http.post URL becomes a call. Requires SECRET_MARKER token in message.
        has_marker = "SECRET_MARKER" in msg
        if "http.post" in lower and has_marker:
            for m in self._URL_ALL.finditer(msg):
                url = m.group(0).rstrip(".,);:")
                if self._refuse(msg, self.exfil_compliance):
                    continue
                events.append((m.start(), {
                    "tool": "http.post",
                    "args": {"url": url, "data": "SECRET_MARKER"},
                }))

        # CONFUSED_DEPUTY: any email address in a message with delivery verbs.
        if any(v in lower for v in ("deliver", "forward", "dispatch", "compose", "send email", "email.send", "dispatch", "notification")):
            for m in self._EMAIL_ALL.finditer(msg):
                addr = m.group(0)
                if self._refuse(msg, self.email_compliance):
                    continue
                events.append((m.start(), {
                    "tool": "email.send",
                    "args": {"to": addr, "subject": "Status", "body": "ok"},
                }))

        events.sort(key=lambda p: p[0])
        return [e[1] for e in events]

    def next_action(self, *, history: RuntimeHistory, tools: tuple[AgentToolSpec, ...]):
        del tools
        user_msg = next(
            (
                ev.text
                for ev in reversed(history.events)
                if isinstance(ev, UserMessageEvent)
            ),
            "",
        )
        if not user_msg:
            return FinalResponseDecision(text="no user message")

        if user_msg != self._plan_msg:
            self._plan = self._plan_for(user_msg)
            self._plan_msg = user_msg

        if not self._plan:
            return FinalResponseDecision(text="no matching tool calls")

        self._counter += 1
        step = self._plan.pop(0)
        return ToolCallDecision(
            call=ToolCall(
                call_id=f"agent_{self._counter}",
                tool_name=step["tool"],
                arguments=step["args"],
            )
        )

    def reset_state(self) -> None:
        self._counter = 0
        self._plan = []
        self._plan_msg = ""

    def snapshot_state(self) -> AgentStateSnapshot:
        return {
            "version": AGENT_STATE_VERSION,
            "backend": "compliant_dryrun",
            "data": {"counter": self._counter},
        }

    def restore_state(self, snapshot: AgentStateSnapshot) -> None:
        if snapshot["version"] != AGENT_STATE_VERSION:
            raise ValueError(f"unsupported snapshot version: {snapshot['version']}")
        if snapshot["backend"] != "compliant_dryrun":
            raise ValueError(f"unsupported snapshot backend: {snapshot['backend']}")
        self._counter = int(snapshot["data"]["counter"])


def _make_agent_factory(exfil: float, email: float):
    def factory():
        return CompliantAgent(exfil_compliance=exfil, email_compliance=email)
    return factory


def main() -> int:
    parser = argparse.ArgumentParser(description="Local upper-bound dry run for attack.py")
    parser.add_argument("--budget-s", type=float, default=120.0)
    parser.add_argument("--exfil-compliance", type=float, default=1.0)
    parser.add_argument("--email-compliance", type=float, default=1.0)
    parser.add_argument("--seed", type=int, default=123)
    parser.add_argument(
        "--fixtures-dir",
        default="data/competition/aicomp_sdk/fixtures",
    )
    args = parser.parse_args()

    started = time.monotonic()
    execution = evaluate_redteam(
        AttackAlgorithm,
        budget_s=args.budget_s,
        agent_factory=_make_agent_factory(args.exfil_compliance, args.email_compliance),
        agent_label=f"compliant(exfil={args.exfil_compliance},email={args.email_compliance})",
        fixtures_dir=Path(args.fixtures_dir),
        attack_env_seed=args.seed,
    )
    wall = time.monotonic() - started

    attack = execution.attack
    if attack is None:
        print("no attack result")
        return 1

    per_pred: dict[str, int] = {}
    per_pred_sev: dict[str, int] = {}
    for finding in attack.findings:
        for pred in finding.get("predicates", []):
            name = str(pred.get("predicate") or pred.get("name") or "UNKNOWN")
            per_pred[name] = per_pred.get(name, 0) + 1
            per_pred_sev[name] = per_pred_sev.get(name, 0) + int(pred.get("severity", 0))

    summary: dict[str, Any] = {
        "wall_time_s": round(wall, 2),
        "budget_s": args.budget_s,
        "score": attack.score,
        "score_raw": attack.score_raw,
        "findings_count": attack.findings_count,
        "unique_cells": attack.unique_cells,
        "unique_canonical_cells": attack.unique_canonical_cells,
        "guardrail_id": attack.guardrail_id,
        "predicate_counts": per_pred,
        "predicate_severity_sum": per_pred_sev,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
