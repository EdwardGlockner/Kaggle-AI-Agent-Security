import importlib
import sys
import types
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch


@dataclass
class AttackCandidate:
    user_messages: tuple[str, ...]


class AttackAlgorithmBase:
    pass


@dataclass
class AttackRunConfig:
    time_budget_s: float
    max_steps: int = 10**9
    max_tool_hops: int = 8


def load_attack_module():
    attacks = types.ModuleType("aicomp_sdk.attacks")
    attacks.AttackAlgorithmBase = AttackAlgorithmBase
    attacks.AttackCandidate = AttackCandidate
    attacks.AttackRunConfig = AttackRunConfig

    predicates = types.ModuleType("aicomp_sdk.core.predicates")
    predicates.eval_predicates = lambda trace: trace["triggered"]

    cells = types.ModuleType("aicomp_sdk.core.cells")
    _counter = {"n": 0}

    def _fake_cell_signature(_tool_events):
        _counter["n"] += 1
        return {"hash": f"cell-{_counter['n']}"}

    cells.cell_signature = _fake_cell_signature

    sys.modules["aicomp_sdk"] = types.ModuleType("aicomp_sdk")
    sys.modules["aicomp_sdk.attacks"] = attacks
    sys.modules["aicomp_sdk.core"] = types.ModuleType("aicomp_sdk.core")
    sys.modules["aicomp_sdk.core.predicates"] = predicates
    sys.modules["aicomp_sdk.core.cells"] = cells
    sys.modules.pop("kaggle_submission", None)
    return importlib.import_module("kaggle_submission")


def _patch_stream(attack, chains):
    def _stream():
        yield from chains
    return patch.object(attack, "_candidate_stream", _stream)


class FakeEnvironment:
    """First candidate triggers; the rest don't. Used to check first-hit semantics."""

    def __init__(self):
        self.attempt = -1
        self.messages: list[str] = []
        self.max_tool_hops: list[int | None] = []

    def reset(self):
        self.attempt += 1
        self.messages = []

    def interact(self, message, max_tool_hops=None):
        self.messages.append(message)
        self.max_tool_hops.append(max_tool_hops)

    def export_trace_dict(self):
        return {"triggered": self.attempt == 0, "tool_events": []}


class TriggeringEnvironment:
    def __init__(self):
        self.interactions: list[str] = []

    def reset(self):
        pass

    def interact(self, message, max_tool_hops=None):
        self.interactions.append(message)

    def export_trace_dict(self):
        return {"triggered": True, "tool_events": []}


class NonTriggeringEnvironment:
    def __init__(self):
        self.interactions: list[str] = []

    def reset(self):
        pass

    def interact(self, message, max_tool_hops=None):
        self.interactions.append(message)

    def export_trace_dict(self):
        return {"triggered": False, "tool_events": []}


class SelectiveEnvironment:
    def __init__(self, is_triggering):
        self.interactions: list[str] = []
        self._is_triggering = is_triggering

    def reset(self):
        pass  # keep cumulative interaction log for test assertions

    def interact(self, message, max_tool_hops=None):
        self.interactions.append(message)

    def export_trace_dict(self):
        triggered = bool(self.interactions) and self._is_triggering(self.interactions[-1])
        return {"triggered": triggered, "tool_events": []}


class AttackAlgorithmTest(unittest.TestCase):
    def test_repeated_chains_do_not_consume_extra_attempts(self):
        attack = load_attack_module()
        env = SelectiveEnvironment(lambda msg: msg in {"repeat", "unique"})

        with _patch_stream(attack, [("repeat",), ("repeat",), ("unique",)]):
            findings = attack.AttackAlgorithm().run(
                env, AttackRunConfig(time_budget_s=60, max_steps=2)
            )

        self.assertEqual(
            [f.user_messages for f in findings],
            [("repeat",), ("unique",)],
        )
        self.assertEqual(env.interactions.count("repeat"), 1)

    def test_returns_shortest_prefix_for_multi_message_candidate(self):
        attack = load_attack_module()
        env = SelectiveEnvironment(lambda msg: msg == "first")

        with _patch_stream(attack, [("first", "second", "third")]):
            findings = attack.AttackAlgorithm().run(
                env, AttackRunConfig(time_budget_s=60, max_steps=1)
            )

        self.assertEqual(
            [f.user_messages for f in findings], [("first",)]
        )
        self.assertEqual(env.interactions, ["first"])

    def test_budget_expiry_during_replay_stops_before_next_message(self):
        attack = load_attack_module()
        env = NonTriggeringEnvironment()

        with (
            _patch_stream(attack, [("first", "second"), ("later",)]),
            patch.object(attack, "DEADLINE_MARGIN_S", 0.0),
            patch.object(attack, "INTERNAL_BUDGET_S_CAP", 1e9),
            patch.object(attack.time, "monotonic", side_effect=(0, 1, 2, 6, 7, 8, 9)),
        ):
            findings = attack.AttackAlgorithm().run(
                env, AttackRunConfig(time_budget_s=5, max_steps=2)
            )

        self.assertEqual(findings, [])
        self.assertEqual(env.interactions, ["first"])

    def test_runtime_max_findings_stops_before_next_candidate(self):
        attack = load_attack_module()
        env = TriggeringEnvironment()

        with (
            _patch_stream(attack, [("one",), ("two",), ("three",)]),
            patch.object(attack, "TARGET_FINDINGS", 2),
        ):
            findings = attack.AttackAlgorithm().run(
                env, AttackRunConfig(time_budget_s=60, max_steps=3)
            )

        self.assertEqual(
            [f.user_messages for f in findings], [("one",), ("two",)]
        )
        self.assertEqual(env.interactions, ["one", "two"])

    def test_returns_only_replayable_triggering_candidates(self):
        attack = load_attack_module()
        env = FakeEnvironment()

        findings = attack.AttackAlgorithm().run(
            env, AttackRunConfig(time_budget_s=60, max_steps=3)
        )

        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].user_messages)

    def test_honors_step_and_tool_hop_limits(self):
        attack = load_attack_module()
        env = FakeEnvironment()

        attack.AttackAlgorithm().run(
            env,
            AttackRunConfig(time_budget_s=60, max_steps=1, max_tool_hops=3),
        )

        self.assertEqual(env.attempt, 0)
        # v7: intentionally caps hops to MAX_TOOL_HOPS_OVERRIDE (1) regardless
        # of gateway config; see the submission documentation / EXP-011.
        self.assertEqual(env.max_tool_hops, [min(3, attack.MAX_TOOL_HOPS_OVERRIDE)])

    def test_zero_steps_performs_no_interactions(self):
        attack = load_attack_module()
        env = FakeEnvironment()

        findings = attack.AttackAlgorithm().run(
            env, AttackRunConfig(time_budget_s=60, max_steps=0)
        )

        self.assertEqual(findings, [])
        self.assertEqual(env.attempt, -1)
        self.assertEqual(env.max_tool_hops, [])

    def test_dedup_on_cell_hash_skips_scoring_duplicates(self):
        attack = load_attack_module()
        env = TriggeringEnvironment()

        with (
            _patch_stream(attack, [("a",), ("b",), ("c",)]),
            patch.object(attack, "cell_signature", lambda _events: {"hash": "constant"}),
        ):
            findings = attack.AttackAlgorithm().run(
                env, AttackRunConfig(time_budget_s=60, max_steps=3)
            )

        self.assertEqual([f.user_messages for f in findings], [("a",)])
        self.assertEqual(env.interactions, ["a", "b", "c"])

    def test_probes_and_legacy_corpus_respect_message_limits(self):
        attack = load_attack_module()

        chains = tuple(attack._DIRECT_HEAD_PROBES)
        self.assertGreater(len(chains), 0)
        for messages in chains:
            self.assertGreater(len(messages), 0)
            self.assertLessEqual(len(messages), 32)
            self.assertTrue(all(len(m) <= 2_000 for m in messages))


class ScorerOracleIntegrationTest(unittest.TestCase):
    def test_oracle_baseline_scores_under_public_guardrail(self):
        sys.modules.pop("kaggle_submission", None)
        for module_name in tuple(sys.modules):
            if module_name == "aicomp_sdk" or module_name.startswith("aicomp_sdk."):
                sys.modules.pop(module_name, None)

        try:
            from aicomp_sdk.evaluation.runner import evaluate_redteam
        except ModuleNotFoundError:
            self.skipTest("vendored aicomp_sdk is not on PYTHONPATH")

        from kaggle_submission import AttackAlgorithm
        from scripts.scoring_oracle import ScorerOracleAgent

        execution = evaluate_redteam(
            AttackAlgorithm,
            budget_s=20,
            agent_factory=ScorerOracleAgent,
            agent_label="scorer-oracle",
            fixtures_dir=Path("data/competition/aicomp_sdk/fixtures"),
        )

        self.assertIsNotNone(execution.attack)
        assert execution.attack is not None
        self.assertGreaterEqual(execution.attack.findings_count, 2)
        self.assertGreater(execution.attack.score_raw, 0)
        self.assertEqual(execution.attack.guardrail_id, "optimal_public")


if __name__ == "__main__":
    unittest.main()
