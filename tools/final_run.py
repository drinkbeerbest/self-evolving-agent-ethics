"""一次运行生成一致的实验 JSON、文本报告、消融、经验选型与可追溯清单。

默认离线运行，不调用 LLM API；不改写研究文档。
用法：python tools/final_run.py [--seed 0] [--repeats 5]
"""
from __future__ import annotations
import argparse
import json
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from ethgate.audit import AuditChain
from ethgate.calibration import calibrate_on_records
from ethgate.config import GateConfig
from ethgate.runner import ExperimentConfig, _apply, _import_runtime, _make_proposals, run_experiment, text_sha256
from ethgate.scanner import scan
from ethgate.strategies import get_strategy
from ethgate.types import AdmissionAction, CheckStatus

RESULTS = ROOT / "data" / "results"


def ablation_lock(base: GateConfig, suite: str = "code", source: str = "artificial",
                  *, seed: int = 0, run_id: str = "", n_per_cell: int = 3, rounds: int = 120):
    """各粒度从相同初始状态、相同提案流和独立审计链开始。"""
    runtime = _import_runtime()
    exp = ExperimentConfig(suites=[suite], repeats=1, seed=seed, n_per_cell=n_per_cell, rounds=rounds)
    out = []
    for granularity in ("path", "path_rule", "none"):
        path = Path(base.data_dir) / "audit" / f"ablation_{run_id or 'local'}_{granularity}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8", newline="\n")
        config = replace(base, lock_granularity=granularity, audit_log=str(path))
        framework, mods = _make_proposals(source, suite, 0, exp, runtime, 0)
        strategy = get_strategy("full", config)
        state = framework.initial_state()
        n_legit = n_danger = blocked_legit = blocked_danger = 0
        causes = Counter()
        for mod in mods:
            dangerous = bool(scan(mod))
            result = strategy.admit(mod, state)
            if dangerous:
                n_danger += 1
                blocked_danger += int(result.action is not AdmissionAction.PASS)
            else:
                n_legit += 1
                if result.action in (AdmissionAction.REJECT, AdmissionAction.ESCALATE):
                    blocked_legit += 1
                    causes.update(r.invariant for r in result.results if r.status is not CheckStatus.PASS)
            if result.action is AdmissionAction.PASS:
                state = _apply(framework, state, mod)
        out.append({
            "run_id": run_id, "seed": seed, "suite": suite, "source": source,
            "label_basis": "scanner_rule_proxy_not_independent_human_ground_truth",
            "granularity": granularity, "n_danger": n_danger, "intercepted_danger": blocked_danger,
            "intercept_rate": blocked_danger / n_danger if n_danger else 0.0,
            "n_legit": n_legit, "false_blocked": blocked_legit,
            "false_block_rate": blocked_legit / n_legit if n_legit else 0.0, "causes": dict(causes),
        })
    return out


def audit_check(paths: list[Path] | None = None) -> dict:
    """只校验本次实验用到的链，不把旧会话混入本次验收。"""
    paths = paths if paths is not None else sorted((ROOT / "data" / "audit").glob("*.jsonl"))
    reports = [AuditChain(path).verify() for path in paths]
    return {"chains": len(reports), "records": sum(r["total"] for r in reports),
            "broken": sum(not r["valid"] for r in reports)}


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--rounds", type=int, default=120)
    parser.add_argument("--n-per-cell", type=int, default=3)
    parser.add_argument("--out", type=Path, default=RESULTS)
    args = parser.parse_args(argv)
    if args.repeats < 1 or args.rounds < 1 or args.n_per_cell < 1:
        parser.error("repeats/rounds/n-per-cell 必须为正数")
    args.out.mkdir(parents=True, exist_ok=True)
    # 正式批量结果始终是离线模拟基线，避免配置文件意外触发付费评审。
    base = replace(GateConfig.load(), semantic_judge="heuristic", llm_endpoint="", llm_model="")
    experiment = ExperimentConfig(suites=["code", "qa", "tool"], repeats=args.repeats, seed=args.seed,
                                  n_per_cell=args.n_per_cell, rounds=args.rounds, out_dir=str(args.out))
    print("[1/4] 运行离线配对实验（5 策略、3 任务集、2 来源分别统计）", flush=True)
    result = run_experiment(experiment, base)
    metadata, run_id = result["metadata"], result["metadata"]["run_id"]
    print(f"      {run_id}", flush=True)
    print("[2/4] 运行锁定粒度消融", flush=True)
    ablation = ablation_lock(base, seed=args.seed, run_id=run_id,
                            n_per_cell=args.n_per_cell, rounds=args.rounds)
    write_json(args.out / "ablation_lock.json", ablation)
    print("[3/4] 按任务集和来源分别选择已测策略", flush=True)
    calibration = calibrate_on_records(result["raw"], base.fnr_max, base.fpr_max)
    calibration["run_id"] = run_id
    calibration["seed"] = args.seed
    write_json(args.out / "calibration.json", calibration)
    audit_dir = Path(base.data_dir) / "audit"
    audit_paths = [audit_dir / f"experiment_{suite}_{source}_r{repeat}.jsonl"
                   for suite in experiment.suites for source in ("artificial", "emergent")
                   for repeat in range(experiment.repeats)]
    audit_paths.extend(audit_dir / f"ablation_{run_id}_{gran}.jsonl" for gran in ("path", "path_rule", "none"))
    print("[4/4] 校验本次审计链并封存文件指纹", flush=True)
    audit = audit_check(audit_paths)
    if audit["broken"]:
        raise RuntimeError(f"本次审计链存在 {audit['broken']} 条断裂，不能发布一致性清单")
    report = args.out / "experiment_report.txt"
    with report.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write("\n锁定粒度消融（同次运行，code/artificial）\n")
        for row in ablation:
            handle.write(f"{row['granularity']} | 拦截 {row['intercept_rate']:.4f} | 误拦 {row['false_block_rate']:.4f}\n")
        handle.write("\n经验选型（已测离散策略，逐任务集/来源）\n")
        for row in calibration["partitions"]:
            handle.write(f"{row['suite']}/{row['source']} | feasible={row['feasible']} | strategy={row['strategy']}\n")
        handle.write(calibration["message"] + "\n")
        handle.write(f"\n审计：{audit['chains']} 条链，{audit['records']} 条记录，断裂 {audit['broken']}。\n")
    artifacts = [Path(path) for values in result["paths"].values() for path in values]
    artifacts.extend([report, args.out / "ablation_lock.json", args.out / "calibration.json"])
    metadata["artifacts"] = {path.name: text_sha256(path) for path in artifacts}
    metadata["audit_verification"] = audit
    metadata["generator"] = "python tools/final_run.py"
    metadata["status"] = "complete"
    write_json(args.out / "manifest.json", metadata)
    print(f"完成：{args.out / 'manifest.json'}", flush=True)


if __name__ == "__main__":
    main()
