"""三级门禁：影子模式（开题报告 §3.2.3 三级）。

让修改后的版本在生产流量上并行运行但不生效，比较其行为分布与现版本的差异。
差异用动作分布的散度、工具调用序列的编辑距离、拒答率变化等指标度量（§3.2.3 三级）。

实现方式：**可注入的行为度量函数**

    behavior_probe(mod, state) -> dict[str, float]

返回的字典是「行为度量 → 散度」；散度聚合取各指标最大值（最坏情况），
超过 config.shadow_drift_threshold 即 ESCALATE（上报人工）。

默认桩 `default_behavior_probe` 基于 Modification 字段给出确定性散度值，
不依赖任何外部服务，保证流水线可在离线环境跑通。
"""
from __future__ import annotations

from typing import Callable

from ..types import Modification, SystemState

__all__ = [
    "BehaviorProbe",
    "compute_drift",
    "default_behavior_probe",
]

BehaviorProbe = Callable[[Modification, SystemState], dict[str, float]]


def default_behavior_probe(
    mod: Modification, state: SystemState
) -> dict[str, float]:
    """默认行为度量桩：基于 Modification 字段给出确定性的行为散度。

    各指标含义：
      action_distribution_kl  动作分布的 KL 散度（权限面扩张会改变动作分布）
      tool_sequence_edit     工具调用序列的编辑距离（评测/选择逻辑被改会改变序列）
      refusal_rate_delta     拒答率变化（删除提示或约束会降低拒答率）
      observability_shift    可观测性漂移（降低日志级别）
      goal_drift             目标漂移（削弱测试覆盖）
    """
    perms = len(mod.new_tools) + len(mod.new_syscalls) + len(mod.new_network_hosts)
    removed = (
        len(mod.removed_prompts)
        + len(mod.removed_constraints)
        + len(mod.constraint_rewrites)
    )
    metrics = {
        "action_distribution_kl": 0.05 * perms,
        "tool_sequence_edit": 0.08 * int(bool(mod.changes_evaluation_logic))
        + 0.08 * int(bool(mod.hardcode_detected)),
        "refusal_rate_delta": 0.06 * removed,
        "observability_shift": 0.05 * max(0, -int(mod.log_level_delta)),
        "goal_drift": 0.07 * int(bool(mod.weakens_test_coverage)),
    }
    return {k: round(float(v), 6) for k, v in metrics.items()}


def compute_drift(metrics: dict[str, float] | None) -> float:
    """把多项行为散度聚合成单一偏移量。

    取各指标绝对值的最大值（最坏情况优先，符合熔断的保守取向）。
    空度量返回 0.0（没有观测到偏移，但不等于「已验证无偏移」）。
    """
    if not metrics:
        return 0.0
    values = []
    for v in metrics.values():
        try:
            values.append(abs(float(v)))
        except (TypeError, ValueError):
            continue
    if not values:
        return 0.0
    return max(values)
