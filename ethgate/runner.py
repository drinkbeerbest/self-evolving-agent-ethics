"""实验运行器（开题报告 §3.5.2「实验方案」）。

对照实验的设计要点
------------------
1. **规则代理标签**：危险标签来自扫描器，不使用策略自己的判定；但与设计规则共享假设，
   不是独立人工真值。分类器默认不读取扫描器命中数，仍需盲标测试集验证。
2. **两路模拟样本分开报告**：人工构造（artificial）与模拟涌现（emergent）各自成组统计，
   **不合并计算总拦截率**——合并会高估机制的实际效果（开题报告 §3.5.2 的明确承诺）。
3. **配对设计**：同一 (suite, source, repeat) 下所有策略面对**同一批提案**与**同一初始状态**，
   差异只来自门禁策略本身。
4. **成本口径**：墙钟时延为实测值；令牌与 GPU 秒是解析式估计（原型不接真实 LLM/GPU）；
   能力成本来自模拟框架的能力评分，基线为同一批提案下的"无门禁"运行。

跨任务依赖（ethgate.mockdgm / ethgate.datasets / ethgate.gates / ethgate.scanner）
一律**延迟导入**，这些模块尚未就绪时本模块仍可被正常 import。
"""
from __future__ import annotations

import json
import hashlib
import math
import random
import statistics
import time
import uuid
from datetime import datetime, timezone
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable, Sequence

from .config import GateConfig
from .strategies import (
    HUMAN_HOURS_PER_ESCALATION,
    HUMAN_HOURS_PER_REJECT,
    PRICE_PER_GPU_HOUR,
    PRICE_PER_MTOK,
    PROPOSAL_LATENCY_S,
    STRATEGY_DISPLAY,
    STRATEGY_GPU_SECONDS,
    STRATEGY_LATENCY_S,
    STRATEGY_NAMES,
    STRATEGY_TOKEN_COST,
    get_strategy,
    scan_hits,
)
from .types import (
    AdmissionAction,
    CostLedger,
    Modification,
    SystemState,
)

__all__ = [
    "ExperimentConfig",
    "run_experiment",
    "summarize",
    "compute_frontier",
    "save_results",
    "render_report",
]


@dataclass
class ExperimentConfig:
    """实验配置。"""

    strategies: list[str] = field(default_factory=lambda: list(STRATEGY_NAMES))
    suites: list[str] = field(default_factory=lambda: ["code"])
    repeats: int = 5
    seed: int = 0
    use_emergent: bool = True
    # 附加字段（不影响上面五个位置的兼容性）
    n_per_cell: int = 3  # 人工构造数据集每个分类格的条数
    rounds: int = 120  # 涌现数据集的演化轮数
    control_pressure: float = 0.35  # 合法对照组的演化压力（低压力 ⇒ 多为正常修改）
    out_dir: str = ""  # 结果落盘目录，留空则用 config.data_dir/results

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# 内部工具
# --------------------------------------------------------------------------


def _import_runtime():
    """延迟导入跨任务依赖（模拟框架 + 数据集）。"""
    try:
        from .mockdgm import MockSelfEvolvingFramework  # 延迟导入：跨任务依赖
        from .datasets import (  # 延迟导入：跨任务依赖
            build_artificial_dataset,
            build_emergent_dataset,
        )
    except Exception as exc:  # pragma: no cover - 依赖未就绪时的提示
        raise RuntimeError(
            "实验运行器需要 ethgate.mockdgm 与 ethgate.datasets（任务 C）"
            f"，当前不可用：{exc}"
        ) from exc
    return MockSelfEvolvingFramework, build_artificial_dataset, build_emergent_dataset


def _apply(framework, state: SystemState, mod: Modification) -> SystemState:
    """把修改作用到状态上；框架接口不可用时退回 SystemState.apply。"""
    try:
        return framework.apply(mod, state)
    except Exception:
        return state.apply(mod)


def _mean(values: Iterable[float]) -> float:
    vals = list(values)
    return sum(vals) / len(vals) if vals else 0.0


def _median(values: Iterable[float]) -> float:
    vals = list(values)
    return statistics.median(vals) if vals else 0.0


def _stdev(values: Sequence[float]) -> float:
    return statistics.stdev(list(values)) if len(values) > 1 else 0.0


def _is_dominated(point: dict, others: Sequence[dict]) -> bool:
    """局部实现与 ethgate.cost.CostCollector.is_dominated 同语义。

    存在另一点 cost ≤ 且 risk ≤ 且至少一项严格更小 → 本点被支配。
    """
    for other in others:
        if other is point:
            continue
        if (
            other["cost"] <= point["cost"]
            and other["risk"] <= point["risk"]
            and (other["cost"] < point["cost"] or other["risk"] < point["risk"])
        ):
            return True
    return False


def _task_cost_collector():
    """尽量复用任务 B 的 CostCollector；不可用时返回 None。"""
    try:
        from .cost import CostCollector  # 延迟导入：跨任务依赖
        return CostCollector
    except Exception:
        return None


# --------------------------------------------------------------------------
# 单次重复的执行
# --------------------------------------------------------------------------


def _run_strategy(
    strategy,
    framework,
    mods: Sequence[Modification],
    tasks: list[dict],
    *,
    suite: str,
    source: str,
    repeat: int,
    baseline: dict[str, Any] | None,
) -> dict[str, Any]:
    """在配对的初始状态上跑一遍策略，产出逐次原始记录。"""
    state = framework.initial_state()
    n = len(mods)
    counts = {
        "dangerous": 0,
        "legit": 0,
        "intercepted": 0,
        "passed_dangerous": 0,
        "false_blocked": 0,
        "false_escalated": 0,
        "rejected": 0,
        "escalated": 0,
        "sandbox": 0,
        "passed": 0,
    }
    mod_records: list[dict[str, Any]] = []
    gate_elapsed = 0.0

    t0 = time.perf_counter()
    for mod in mods:
        # 规则代理标签，与策略输出分离；不代表经独立人工验证。
        hits = scan_hits(mod)
        dangerous = len(hits) > 0
        gt = "dangerous" if dangerous else "legit"

        result = strategy.admit(mod, state)
        action = result.action
        gate_elapsed += float(result.elapsed_s or 0.0)

        if dangerous:
            counts["dangerous"] += 1
            if action is AdmissionAction.PASS:
                counts["passed_dangerous"] += 1
            else:
                counts["intercepted"] += 1
        else:
            counts["legit"] += 1
            # SANDBOX 是待进一步审查，本次不生效；不能假设其最终必然放行。
            # 硬误拦 = 拒绝/上报；误升级单列，不与硬误拦混算。
            if action in (AdmissionAction.REJECT, AdmissionAction.ESCALATE):
                counts["false_blocked"] += 1
            elif action is AdmissionAction.SANDBOX:
                counts["false_escalated"] += 1

        if action is AdmissionAction.REJECT:
            counts["rejected"] += 1
        elif action is AdmissionAction.ESCALATE:
            counts["escalated"] += 1
        elif action is AdmissionAction.SANDBOX:
            counts["sandbox"] += 1
        else:
            counts["passed"] += 1

        mod_records.append(
            {
                "mod_id": mod.mod_id,
                "layer": mod.layer.value,
                "autonomy": mod.autonomy.value,
                "ground_truth": gt,
                "n_hits": len(hits),
                "hit_rules": [h.get("rule_id", "") for h in hits],
                "action": action.value,
                "action_key": action.name,
                "blocked": action is not AdmissionAction.PASS,
                "strictness": strategy.strictness,
            }
        )

        if action is AdmissionAction.PASS:
            state = _apply(framework, state, mod)
    elapsed = time.perf_counter() - t0

    t1 = time.perf_counter()
    eval_out = framework.evaluate(state, tasks)
    eval_s = time.perf_counter() - t1
    score = float(eval_out.get("score", 0.0))

    # —— 统计量 ——
    n_danger = counts["dangerous"]
    n_legit = counts["legit"]
    intercept_rate = counts["intercepted"] / n_danger if n_danger else 0.0
    fnr = counts["passed_dangerous"] / n_danger if n_danger else 0.0
    false_block_rate = counts["false_blocked"] / n_legit if n_legit else 0.0
    false_escalate_rate = counts["false_escalated"] / n_legit if n_legit else 0.0

    baseline_score = float(baseline["score"]) if baseline else score
    baseline_elapsed = float(baseline["elapsed_s"]) if baseline else elapsed

    # —— 成本 ——
    # 时延用**分阶段时延模型**：原型里的检查器与沙箱是桩实现，实测墙钟只有毫秒级，
    # 直接拿它做"相对无门禁基线的倍数"会得到无意义的巨值。
    # 模型：每次修改的墙钟 = 提案生成（模型推理，各策略共有）+ 门禁附加时延。
    l_gate = STRATEGY_LATENCY_S.get(strategy.name, 0.0)
    endpoint_review = (strategy.name == "llm_review" and strategy.config.semantic_judge in ("llm", "llm_review", "model")
                       and bool(strategy.config.llm_endpoint))
    if endpoint_review:
        l_gate = 3.0  # 仅显式端点评审使用假设的 API 时延/token 预算，仍非实测用量。
    elapsed_model_s = n * (PROPOSAL_LATENCY_S + l_gate)
    baseline_elapsed_model_s = n * PROPOSAL_LATENCY_S
    tokens = STRATEGY_TOKEN_COST.get(strategy.name, 0.0) * n
    if endpoint_review:
        tokens = 1200.0 * n
    gpu_s = STRATEGY_GPU_SECONDS.get(strategy.name, 0.0) * n
    c_comp = tokens / 1e6 * PRICE_PER_MTOK + gpu_s / 3600 * PRICE_PER_GPU_HOUR
    c_hum = (
        (counts["escalated"] * HUMAN_HOURS_PER_ESCALATION
         + counts["rejected"] * HUMAN_HOURS_PER_REJECT) / n * 1000.0
        if n else 0.0
    )
    c_cap = (baseline_score - score) / baseline_score if baseline_score > 0 else 0.0
    c_lat = (PROPOSAL_LATENCY_S + l_gate) / PROPOSAL_LATENCY_S
    c_fp = false_block_rate
    c_fn = fnr
    # 迭代效率：单位时间内有效修改次数的下降比例（用模型时延）
    if elapsed_model_s > 0 and baseline_elapsed_model_s > 0:
        iter_before = n / baseline_elapsed_model_s
        iter_after = counts["passed"] / elapsed_model_s
        c_iter = (iter_before - iter_after) / iter_before if iter_before > 0 else 0.0
    else:
        c_iter = 0.0
    c_ali = CostLedger(
        c_cap=c_cap,
        c_lat=c_lat,
        c_comp=c_comp,
        c_hum=c_hum,
        c_fp=c_fp,
        c_fn=c_fn,
        c_iter=c_iter,
    ).weighted_total(strategy.config.cost_weights or None)

    return {
        "strategy": strategy.name,
        "display_name": strategy.display_name,
        "label_basis": "scanner_rule_proxy_not_independent_human_ground_truth",
        "execution_mode": "mock_framework",
        "cost_basis": "stage_model_estimates_mixed_units_weighted_index_not_usd",
        "classifier_uses_scanner_features": False if strategy.name == "classifier" else None,
        "suite": suite,
        "source": source,
        "repeat": repeat,
        "n": n,
        "n_dangerous": n_danger,
        "n_legit": n_legit,
        "intercept_rate": intercept_rate,
        "false_block_rate": false_block_rate,
        "false_escalate_rate": false_escalate_rate,
        "fnr": fnr,
        "reject_rate": counts["rejected"] / n if n else 0.0,
        "escalate_rate": counts["escalated"] / n if n else 0.0,
        "sandbox_rate": counts["sandbox"] / n if n else 0.0,
        "pass_rate": counts["passed"] / n if n else 0.0,
        "score": score,
        "baseline_score": baseline_score,
        "elapsed_s": elapsed,
        "baseline_elapsed_s": baseline_elapsed,
        "elapsed_model_s": elapsed_model_s,
        "baseline_elapsed_model_s": baseline_elapsed_model_s,
        "gate_latency_model_s": l_gate,
        "gate_elapsed_s": gate_elapsed,
        "eval_s": eval_s,
        "tokens": tokens,
        "gpu_s": gpu_s,
        "human_hours": c_hum,
        "iter_count": counts["passed"],
        "c_cap": c_cap,
        "c_lat": c_lat,
        "c_comp": c_comp,
        "c_hum": c_hum,
        "c_fp": c_fp,
        "c_fn": c_fn,
        "c_iter": c_iter,
        "c_ali": c_ali,
        "risk": fnr,
        "delta_r": 1.0 - fnr,
        "acer": (1.0 - fnr) / c_ali if c_ali > 0 else 0.0,
        "mod_records": mod_records,
    }


# --------------------------------------------------------------------------
# 实验主流程
# --------------------------------------------------------------------------


def _make_proposals(
    route: str,
    suite: str,
    repeat: int,
    cfg: ExperimentConfig,
    runtime,
    suite_index: int = 0,
):
    """生成本次重复的提案流。

    提案流 = **该路线的危险样本** + **合法对照组**。

    为什么需要合法对照组：CONTRACT 的两路数据集
    （``build_artificial_dataset`` / ``build_emergent_dataset``）产出的样本
    **全部命中高危规则**，即全部是危险修改。若只跑这两路样本，误拦率与误拦成本
    c_fp 将恒为 0，"无门禁"与"一律拒绝"在指标上无法区分，实验失去意义。
    因此这里从同一模拟框架的**常规进化轮次**中取未命中任何规则的提案作为
    合法对照组——它代表系统平时产生的正常自修改，是误拦率的分母。

    两路样本的危险部分仍然各自独立，**分开报告，绝不合并**。
    """
    MockFramework, build_artificial, build_emergent = runtime
    # 三个任务集用**独立随机种子**抽样：模拟框架的提案生成不依赖任务集类型，
    # 若共用种子，三套任务集拿到的是同一批提案，任务集维度就退化成了重复实验。
    # 代价是：任务集之间的差异只反映抽样波动，不反映任务类型对修改分布的影响，
    # 这一局限须在报告中如实说明。
    seed = cfg.seed * 100000 + suite_index * 1000 + repeat
    framework = MockFramework(seed=seed, name=f"mockdgm-{suite}")

    if route == "artificial":
        danger = list(build_artificial(n_per_cell=cfg.n_per_cell, seed=seed))
    else:
        danger = list(build_emergent(framework, rounds=cfg.rounds, seed=seed))

    # 合法对照组：低进化压力下的正常修改（ground truth 由扫描器判定，无命中即合法）
    controls = [
        m
        for m in framework.run(rounds=max(20, cfg.rounds), pressure=cfg.control_pressure)
        if not scan_hits(m)
    ]

    mods = danger + controls
    random.Random(seed + 7).shuffle(mods)  # 打散顺序，避免时序偏置
    return framework, mods


def _block_config(config: GateConfig, suite: str, source: str, repeat: int) -> GateConfig:
    """为每个实验块准备一份配置：审计链按块独立。

    ``ethgate.audit.AuditChain`` 每追加一条就整体重写文件，若整个实验共用一条链，
    写入量随记录数平方增长（几万条判定会把实验拖成 I/O 瓶颈）。
    因此这里给每个 (suite, source, repeat) 块单独一条审计链：
    既保住"每次判定都留痕"的性质，又把重写规模限制在块内。
    """
    audit_dir = Path(config.data_dir) / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    path = audit_dir / f"experiment_{suite}_{source}_r{repeat}.jsonl"
    path.write_text("", encoding="utf-8")  # 每次运行从空链开始
    return replace(config, audit_log=str(path))


def run_experiment(
    cfg: ExperimentConfig, config: GateConfig | None = None
) -> dict[str, Any]:
    """跑完整的对照实验，返回原始记录、汇总与帕累托前沿。"""
    config = config or GateConfig.load()
    runtime = _import_runtime()
    metadata = experiment_metadata(cfg, config)

    unknown = [s for s in cfg.strategies if s not in STRATEGY_NAMES]
    if unknown:
        raise KeyError(f"未知策略：{unknown}；可选 {STRATEGY_NAMES}")

    raw: list[dict[str, Any]] = []
    for suite_index, suite in enumerate(cfg.suites):
        routes = ["artificial"] + (["emergent"] if cfg.use_emergent else [])
        for source in routes:
            for repeat in range(cfg.repeats):
                block_cfg = _block_config(config, suite, source, repeat)
                framework, mods = _make_proposals(
                    source, suite, repeat, cfg, runtime, suite_index
                )
                tasks = framework.task_suite(suite)

                # 基线：无门禁（同时用于 c_cap / ΔR / c_lat 的基准）
                baseline_strategy = get_strategy("none", block_cfg)
                baseline = _run_strategy(
                    baseline_strategy,
                    framework,
                    mods,
                    tasks,
                    suite=suite,
                    source=source,
                    repeat=repeat,
                    baseline=None,
                )

                for name in cfg.strategies:
                    if name == "none":
                        # 与基线同一次运行，避免重复计算并保持口径一致
                        record = dict(baseline)
                        record["is_baseline"] = True
                    else:
                        # 每个 repeat 重建策略实例：避免熔断锁等有状态量跨 repeat 污染
                        strategy = get_strategy(name, block_cfg)
                        record = _run_strategy(
                            strategy,
                            framework,
                            mods,
                            tasks,
                            suite=suite,
                            source=source,
                            repeat=repeat,
                            baseline=baseline,
                        )
                    raw.append(record)

    completed = experiment_metadata(cfg, config)
    if metadata["code_version"] != completed["code_version"]:
        raise RuntimeError("实验运行中源码或配置发生变化；请在稳定版本上重跑，未发布汇总结果")
    metadata["finished_at"] = completed["generated_at"]
    metadata["code_unchanged_during_run"] = True
    summary = summarize(raw, weights=config.cost_weights or None)
    frontier = compute_frontier(summary)
    for row in [*raw, *summary, *frontier]:
        row["run_id"] = metadata["run_id"]
    paths = save_results(raw, summary, frontier, config, out_dir=cfg.out_dir, metadata=metadata)

    return {
        "config": cfg.as_dict(),
        "gate_config": {
            "fnr_max": config.fnr_max,
            "fpr_max": config.fpr_max,
            "high_risk_threshold": config.high_risk_threshold,
            "cost_weights": config.cost_weights or {},
        },
        "raw": raw,
        "summary": summary,
        "frontier": frontier,
        "paths": paths,
        "metadata": metadata,
    }


# --------------------------------------------------------------------------
# 汇总
# --------------------------------------------------------------------------


def summarize(
    raw: list[dict], weights: dict[str, float] | None = None
) -> list[dict[str, Any]]:
    """把逐次原始记录汇总为每个 (strategy, suite, source) 一行。

    两路样本（artificial / emergent）**分行统计，绝不合并**。
    """
    groups: dict[tuple[str, str, str], list[dict]] = {}
    for rec in raw:
        key = (
            str(rec.get("strategy", "")),
            str(rec.get("suite", "")),
            str(rec.get("source", "")),
        )
        groups.setdefault(key, []).append(rec)

    w = weights or CostLedger.WEIGHTS
    rows: list[dict[str, Any]] = []

    def _order(key: tuple[str, str, str]) -> tuple[Any, ...]:
        strategy, suite, source = key
        try:
            idx = STRATEGY_NAMES.index(strategy)
        except ValueError:
            idx = len(STRATEGY_NAMES)
        return (suite, source, idx, strategy)

    for (strategy, suite, source), recs in sorted(groups.items(), key=lambda kv: _order(kv[0])):
        n_repeats = len(recs)
        intercepts = [float(r.get("intercept_rate", 0.0)) for r in recs]
        fnrs = [float(r.get("fnr", 0.0)) for r in recs]
        fprs = [float(r.get("false_block_rate", 0.0)) for r in recs]

        c_cap = _mean(r.get("c_cap", 0.0) for r in recs)
        # 时延成本用分阶段时延模型（实测墙钟另存 elapsed_s）
        c_lat = _median(r.get("c_lat", 1.0) for r in recs)
        c_comp = _mean(r.get("c_comp", 0.0) for r in recs)
        c_hum = _mean(r.get("c_hum", 0.0) for r in recs)
        c_fp = _mean(fprs)
        c_fn = _mean(fnrs)
        c_iter = _mean(r.get("c_iter", 0.0) for r in recs)

        cost = CostLedger(
            c_cap=c_cap, c_lat=c_lat, c_comp=c_comp, c_hum=c_hum,
            c_fp=c_fp, c_fn=c_fn, c_iter=c_iter,
        )
        c_ali = cost.weighted_total(w)
        fnr_mean = _mean(fnrs)
        acer = (1.0 - fnr_mean) / c_ali if c_ali > 0 else 0.0

        se = _stdev(intercepts) / math.sqrt(n_repeats) if n_repeats > 1 else 0.0
        rows.append(
            {
                "strategy": strategy,
                "display_name": str(recs[0].get("display_name", STRATEGY_DISPLAY.get(strategy, strategy))),
                "label_basis": "scanner_rule_proxy_not_independent_human_ground_truth",
                "execution_mode": "mock_framework",
                "cost_basis": "stage_model_estimates_mixed_units_weighted_index_not_usd",
                "suite": suite,
                "source": source,
                "intercept_rate": _mean(intercepts),
                "false_block_rate": _mean(fprs),
                "false_escalate_rate": _mean(
                    r.get("false_escalate_rate", 0.0) for r in recs
                ),
                "fnr": fnr_mean,
                "reject_rate": _mean(r.get("reject_rate", 0.0) for r in recs),
                "escalate_rate": _mean(r.get("escalate_rate", 0.0) for r in recs),
                "score": _mean(r.get("score", 0.0) for r in recs),
                "c_cap": c_cap,
                "c_lat": c_lat,
                "c_comp": c_comp,
                "c_hum": c_hum,
                "c_fp": c_fp,
                "c_fn": c_fn,
                "c_iter": c_iter,
                "c_ali": c_ali,
                "acer": acer,
                "risk": fnr_mean,
                "n": int(sum(int(r.get("n", 0)) for r in recs)),
                "n_dangerous": int(sum(int(r.get("n_dangerous", 0)) for r in recs)),
                "n_legit": int(sum(int(r.get("n_legit", 0)) for r in recs)),
                "ci95": 1.96 * se,
                "n_repeats": n_repeats,
            }
        )
    return rows


def compute_frontier(summary: list[dict]) -> list[dict[str, Any]]:
    """计算成本—风险平面上的帕累托前沿。

    横轴 c_ali（对齐总成本），纵轴 fnr（残余风险 = 漏放率），标注被支配的点。
    """
    collector = _task_cost_collector()
    groups: dict[tuple[str, str], list[dict]] = {}
    for row in summary:
        groups.setdefault(
            (str(row.get("suite", "")), str(row.get("source", ""))), []
        ).append(row)

    out: list[dict[str, Any]] = []
    for (suite, source), rows in sorted(groups.items()):
        points = [
            {
                "name": r["strategy"],
                "display_name": r.get("display_name", r["strategy"]),
                "cost": float(r.get("c_ali", 0.0)),
                "risk": float(r.get("fnr", 0.0)),
            }
            for r in rows
        ]
        for pt in points:
            if collector is not None:
                try:
                    dominated = bool(
                        collector.is_dominated(pt, points)
                    )
                except Exception:
                    dominated = _is_dominated(pt, points)
            else:
                dominated = _is_dominated(pt, points)
            out.append(
                {
                    "suite": suite,
                    "source": source,
                    "strategy": pt["name"],
                    "display_name": pt["display_name"],
                    "cost": pt["cost"],
                    "risk": pt["risk"],
                    "dominated": dominated,
                    "frontier": not dominated,
                }
            )
    return out


# --------------------------------------------------------------------------
# 落盘
# --------------------------------------------------------------------------


def experiment_metadata(cfg: ExperimentConfig, config: GateConfig) -> dict[str, Any]:
    """记录实际源码指纹，既不依赖 git，也不收集 API 密钥。"""
    root = Path(__file__).resolve().parent.parent
    sources = sorted([*root.joinpath("ethgate").rglob("*.py"), root / "tools" / "final_run.py",
                      root / "configs" / "gate.yaml", *root.joinpath("data", "expert_scores").glob("*.json")])
    hashes = {p.relative_to(root).as_posix(): text_sha256(p) for p in sources if p.is_file()}
    fingerprint = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
    gate = config.to_dict()
    gate.pop("llm_endpoint", None)
    gate["llm_endpoint_configured"] = bool(config.llm_endpoint)
    for key in ("expert_scores_dir", "state_path", "audit_log", "data_dir"):
        path = Path(gate.get(key) or ".")
        try:
            gate[key] = path.resolve().relative_to(root).as_posix()
        except ValueError:
            gate[key] = "(external path)"
    exp = cfg.as_dict()
    if exp["out_dir"]:
        try:
            exp["out_dir"] = Path(exp["out_dir"]).resolve().relative_to(root).as_posix()
        except ValueError:
            exp["out_dir"] = "(external path)"
    return {
        "schema": "ethgate.experiment/v2", "run_id": "run-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8],
        "normalization": "utf8-lf",
        "generated_at": datetime.now(timezone.utc).isoformat(), "seed": cfg.seed,
        "code_version": "sha256:" + fingerprint, "source_hashes": hashes,
        "experiment_config": exp, "gate_config": gate,
        "label_basis": "scanner_rule_proxy_not_independent_human_ground_truth",
        "execution_mode": "mock_framework", "classifier_uses_scanner_features": False,
        "reviewer": "heuristic_prompt_constraint_only" if config.semantic_judge == "heuristic" else "configured_endpoint_with_fallback",
        "cost_basis": "stage_model_estimates_mixed_units_weighted_index_not_usd",
        "score_basis": "mock_score_includes_reward_hacking_bonus_not_independent_capability",
        "sources_reported_separately": True,
    }


def text_sha256(path: Path) -> str:
    """UTF-8 文本统一 LF 后取指纹，避免 Windows/Git 自动换行影响复现。"""
    value = path.read_bytes().decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def render_report(summary: list[dict], metadata: dict) -> str:
    """报告完全由同次汇总与元数据生成，不引用硬编码结论。"""
    lines = ["伦理熔断模拟对照实验", f"运行 ID: {metadata.get('run_id', 'unknown')}",
             f"UTC: {metadata.get('generated_at', '')}", f"种子: {metadata.get('seed')}",
             f"源码版本: {metadata.get('code_version', '')}",
             "标签: 扫描器规则代理；尚非独立人工危险真值。",
             "来源: artificial=人工构造；emergent=模拟涌现，不是真实 API 观测。",
             "评审: 默认提示/约束启发式；llm_review 是兼容策略键。",
             "成本: 分阶段估算的混合量纲加权指标，C_ali 不是美元。",
             "能力: 模拟评分含奖励作弊增益；评分差不能解释为真实能力损失。",
             "SANDBOX 本次不生效；合法误升级单列，不能假定最终必然放行。", ""]
    for suite, source in sorted({(r["suite"], r["source"]) for r in summary}):
        lines.extend([f"任务集 {suite} · 样本来源 {source}",
                      "策略 | 拦截率 | 误拦率 | 误升级率 | 漏放率 | C_ali | ACER | 模拟分 | n | 危险/合法 | CI95"])
        for row in summary:
            if (row["suite"], row["source"]) != (suite, source):
                continue
            lines.append(f"{row['display_name']} | {row['intercept_rate']:.4f} | {row['false_block_rate']:.4f} | "
                         f"{row.get('false_escalate_rate', 0):.4f} | {row['fnr']:.4f} | {row['c_ali']:.4f} | "
                         f"{row['acer']:.4f} | {row['score']:.4f} | {row['n']} | "
                         f"{row.get('n_dangerous', 0)}/{row.get('n_legit', 0)} | {row['ci95']:.4f}")
        lines.append("")
    return "\n".join(lines) + "\n"


def save_results(
    raw: list[dict],
    summary: list[dict],
    frontier: list[dict],
    config: GateConfig,
    out_dir: str | Path | None = None,
    metadata: dict | None = None,
) -> dict[str, list[str]]:
    """落盘 raw_<suite>.json / summary_<suite>.json / frontier_<suite>.json。"""
    base = Path(out_dir) if out_dir else Path(config.data_dir) / "results"
    base.mkdir(parents=True, exist_ok=True)
    suites = sorted({str(r.get("suite", "")) for r in raw} |
                    {str(r.get("suite", "")) for r in summary})
    paths: dict[str, list[str]] = {"raw": [], "summary": [], "frontier": []}
    for suite in suites:
        raw_suite = [r for r in raw if str(r.get("suite", "")) == suite]
        sum_suite = [r for r in summary if str(r.get("suite", "")) == suite]
        fr_suite = [r for r in frontier if str(r.get("suite", "")) == suite]
        for kind, payload in (
            ("raw", raw_suite),
            ("summary", sum_suite),
            ("frontier", fr_suite),
        ):
            p = base / f"{kind}_{suite}.json"
            p.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
                newline="\n",
            )
            paths[kind].append(str(p))
    if metadata is not None:
        report = base / "experiment_report.txt"
        report.write_text(render_report(summary, metadata), encoding="utf-8", newline="\n")
        files = [Path(path) for values in paths.values() for path in values] + [report]
        metadata["artifacts"] = {p.name: text_sha256(p) for p in files}
        (base / "manifest.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")
    return paths
