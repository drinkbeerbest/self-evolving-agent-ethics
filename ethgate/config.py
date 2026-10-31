"""门禁配置：约束集、阈值、预算、门禁策略开关。

配置来源优先级：显式路径 > 环境变量 ETHGATE_CONFIG > 默认 configs/gate.yaml
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = REPO_ROOT / "configs" / "gate.yaml"


@dataclass
class GateConfig:
    """全局门禁配置。"""

    # 运行时
    strictness: str = "formality"  # formality | full
    max_gate_level: int = 4

    # 不变量开关
    enable_i1: bool = True
    enable_i2: bool = True
    enable_i3: bool = True
    enable_i4: bool = True

    # I4 语义侧评审器：heuristic（本地启发式，无外部依赖） | llm（需接入大模型）
    semantic_judge: str = "heuristic"
    llm_endpoint: str = ""
    llm_model: str = ""

    # 阈值与预算（开题报告 §3.4）
    fnr_max: float = 0.05  # ε 漏放率上限
    fpr_max: float = 0.10  # δ 误拦率上限
    cost_budget_per_mod: float = 1.0  # 单次修改的成本预算（相对基线倍数）
    shadow_drift_threshold: float = 0.15  # 影子期行为偏移阈值

    # 熔断
    lock_duration_s: float = 24 * 3600  # 路径锁定时长
    # 锁定粒度：path（整类修改一并锁死，连带误拦极强）
    #          path_rule（锁定到"修改层×自主度×触发不变量"，同一类合法修改不受牵连）
    #          none（只记录事件不锁定，用于消融对照）
    lock_granularity: str = "path_rule"
    auto_escalate_on_infeasible: bool = True  # 标定约束不可行时自动升级门禁并报警

    # 分类学
    high_risk_threshold: float = 4.0
    expert_scores_dir: str = ""

    # 成本权重（可按场景重加权，开题报告 §3.3.2）
    cost_weights: dict[str, float] = field(default_factory=dict)

    # 运行时路径
    state_path: str = ""
    audit_log: str = ""
    data_dir: str = ""

    @classmethod
    def load(cls, path: str | Path | None = None) -> "GateConfig":
        p = Path(path) if path else Path(
            os.environ.get("ETHGATE_CONFIG", DEFAULT_CONFIG_PATH)
        )
        raw: dict[str, Any] = {}
        if p.exists():
            raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        cfg = cls()
        for k, v in raw.items():
            if hasattr(cfg, k) and v is not None:
                setattr(cfg, k, v)
        if not cfg.expert_scores_dir:
            cfg.expert_scores_dir = str(REPO_ROOT / "data" / "expert_scores")
        if not cfg.data_dir:
            cfg.data_dir = str(REPO_ROOT / "data")
        if not cfg.audit_log:
            cfg.audit_log = str(REPO_ROOT / "data" / "audit" / "audit_chain.jsonl")
        if not cfg.state_path:
            cfg.state_path = str(REPO_ROOT / "data" / "state" / "current_state.json")
        return cfg

    def to_dict(self) -> dict[str, Any]:
        return {
            k: getattr(self, k)
            for k in self.__dataclass_fields__  # type: ignore[attr-defined]
        }
