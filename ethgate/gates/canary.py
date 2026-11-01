"""四级门禁：灰度放量（开题报告 §3.2.3 四级）。

按比例逐步放开，每一级设观察窗与回滚条件；任何一级观察到异常即回滚，
并把事件记入该修改路径的历史（开题报告 §3.2.3 四级）。

本模块只负责**记录灰度计划**（放量比例、观察窗、回滚点、回滚条件）并返回 PASS，
真正的放量执行由运行时负责；这里要保证的是「计划可审计、可回滚」。
"""
from __future__ import annotations

from typing import Any, Sequence

from ..types import Modification, SystemState, path_key

__all__ = [
    "DEFAULT_CANARY_STAGES",
    "DEFAULT_OBSERVATION_WINDOW_S",
    "build_canary_plan",
]

# 默认分级放量比例：先 5%，再 20%、50%，最后全量
DEFAULT_CANARY_STAGES: tuple[float, ...] = (0.05, 0.20, 0.50, 1.0)

# 默认观察窗：1 小时
DEFAULT_OBSERVATION_WINDOW_S: float = 3600.0


def build_canary_plan(
    mod: Modification,
    state: SystemState,
    *,
    stages: Sequence[float] | None = None,
    observation_window_s: float | None = None,
    rollback_point: str | None = None,
    drift_threshold: float | None = None,
) -> dict[str, Any]:
    """生成灰度放量计划。

    返回的字典包含：
      traffic_ratio        首批放量比例
      canary_stages        分级放量比例序列
      observation_window_s 每级的观察窗长度（秒）
      rollback_point       回滚点（最近一次通过审查的版本）
      rollback_conditions  回滚条件
      path_key             该修改所属的路径键（熔断锁定与标定的单位）
    """
    stage_list = [float(s) for s in (stages or DEFAULT_CANARY_STAGES)]
    if not stage_list:
        stage_list = [float(DEFAULT_CANARY_STAGES[0])]
    window = float(
        observation_window_s
        if observation_window_s is not None
        else DEFAULT_OBSERVATION_WINDOW_S
    )
    point = (
        rollback_point
        or getattr(state, "code_version", "")
        or getattr(mod, "base_commit", "")
        or mod.mod_id
    )
    conditions = [
        "观察窗内出现任一不变量告警即回滚",
        "观察窗内出现熔断事件即回滚",
        "观察窗内人工否决即回滚",
    ]
    if drift_threshold is not None:
        conditions.insert(
            1,
            f"观察窗内行为偏移超过影子期阈值 {float(drift_threshold):.4f} 即回滚",
        )
    return {
        "traffic_ratio": stage_list[0],
        "canary_stages": stage_list,
        "observation_window_s": window,
        "rollback_point": point,
        "rollback_conditions": conditions,
        "path_key": path_key(mod.layer, mod.autonomy),
    }
