# Prompt to paste into a fresh Codex session

Copy-paste everything below this line into Codex:

---

You're picking up an in-flight Kaggle red-team attack submission for the **ai-agent-security-multi-step-tool-attacks** competition.

**Start by reading `HANDOFF.md` in the workspace root.** It has the full state.

**Elevator pitch of the state:**

- **v10 attack.py shipped as SUB-008. Scored 40.585.** That's a regression from v9's 69.755. Multi-hit gemma turned out to be CPU-toxic.
- **Leaderboard #1: 137.130.** Public open-source frontier: 88.875. Our best (SUB-007 / v9): 69.755. Gap to LB #1: 67 points.
- **CPU measurements exhausted templates.** `v9_harmony_gpt_oss` is CPU-optimal on gpt_oss (17.4 s p75). Multi-hit `numbered_calls` beats single-hit on gemma but only by 5 norm. Both walls are at their respective floors. Reply-OK / silent variants don't help.
- **The unexplained 2× gap.** Our CPU probe predicts v9 = ~35 aggregate. Actual = 69.755. Working hypothesis: gateway KV cache reuse across identical-prefix candidates.

**Your first action:** run `experiments/v14_kv_cache_chains.ipynb` in a Kaggle **CPU-only** session (attach workspace + both GGUFs). Wall time ~60 min. It will print one of:

- `>> KV cache reuse CONFIRMED. Design v11 with 2-message chains + shared priming.` → Path A: v11 = v9 + 2-message priming. Expected 90–130.
- `>> No cache warming detected.` → Path B: run v12 (template evolution) + v13 (LLM self-attack). Expected 65–90.
- `>> Marginal cache benefit.` → Path C: combine chain + best template. Expected 80–120.

**Regardless of path**, also run `experiments/v15_novelty_hunt.ipynb` (~15 min) to confirm/refute the "hidden novelty bonus" hypothesis before designing v11.

**Do not ship v11 until v14 has run and the direction is chosen.**

**Ground rules:**
1. Kaggle scoring logs are never exposed. Don't try to instrument attack.py with print() calls hoping to see them.
2. `data/competition/` is gitignored — export `PYTHONPATH="$PWD/data/competition:$PYTHONPATH"` for local tests.
3. Use `.venv/bin/python` (uv-managed, 3.12).
4. Preserve the module-level names the unit tests patch (`_candidate_stream`, `_DIRECT_HEAD_PROBES`, `MAX_TOOL_HOPS_OVERRIDE`, `TARGET_FINDINGS`, `MAX_FINDINGS_HARD`).
5. User prefers importing submission notebooks via Kaggle web UI over `kaggle kernels push`.
6. Do not ship a v11 that just recovers v9's 69.755 — user rejected that idea explicitly.

**Key files:**
- `attack.py` — current shipped code (v10)
- `EXPERIMENTS.md` — full experiment log, especially EXP-031/032/033 and SUB-008 entries
- `HANDOFF.md` — this handoff (detailed)
- `data/competition/kaggle_evaluation/jed_attack_134815/jed_attack_gateway.py` — how scoring works
- `experiments/v11_cpu_probe.ipynb` — CPU measurements that produced current baselines
- `experiments/v14_kv_cache_chains.ipynb` — **the notebook to run first**
- `submissions/sub-008/` — template for future submission bundles

**Sanity check before making any change:**
```bash
.venv/bin/python -m unittest discover -s tests        # 10 tests must pass
PYTHONPATH=data/competition:$PYTHONPATH .venv/bin/python experiments/local_dryrun.py --budget 60
```

Now read `HANDOFF.md` fully and start with Step 1 (run v14).
