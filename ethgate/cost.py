"""对齐成本的七维采集、合成指标与帕累托前沿（开题报告 §3.3）。

对应开题报告 表3「对齐成本的七项指标」与式(3)：

    C_ali = Σ w_k · c_k        （加权合成对齐总成本）
    ACER  = ΔR / C_ali         （对齐成本效率比）

七维分别是能力成本 c_cap、时延成本 c_lat、算力成本 c_comp、人工成本 c_hum、
误拦成本 c_fp、漏放成本 c_fn、迭代效率损失 c_iter。

设计要点：
  * 每一维都是「相对基线」的量纲，除 c_comp（折算金额）外都是无量纲比值，
    这样不同门禁策略才能放在同一坐标系里比较（§3.3.2）。
  * 权重不写死：`CostLedger.weighted_total(weights)` 允许按部署场景重加权，
    本模块只提供默认权重与 `acer` 的封装。
  * 全部计算只依赖标准库，不引入 numpy，保证在任何环境下都可复现。
"""
from __future__ import annotations

from typing import Any

from .config import GateConfig
from .types import CostLedger

__all__ = [
    "PRICE_PER_MTOK",
    "PRICE_PER_GPU_HOUR",
    "COST_DIMENSIONS",
    "CostCollector",
]

# 算力单价常量：每百万 token 的价格 / 每 GPU 小时的价格（美元）
PRICE_PER_MTOK = 2.0
PRICE_PER_GPU_HOUR = 2.5

# 七维成本的名字（与 CostLedger.NAMES 保持一致，便于外部按名索引）
COST_DIMENSIONS: tuple[str, ...] = CostLedger.NAMES

# 浮点比较容差：用于帕累托支配判定，避免 0.1+0.2 与 0.3 的表示误差
_EPS = 1e-12


class CostCollector:
    """七维成本采集器。

    对应开题报告 §3.3「对齐成本的多维测量」。每次准入判定都应产出一份
    成本账（成本与判定同源，见 ethgate.types 的模块说明）。
    """

    def __init__(self, config: GateConfig):
        self.config = config

    # -- 采集 -----------------------------------------------------------
    def collect(
        self,
        *,
        baseline_score: float | None = None,
        gated_score: float | None = None,
        elapsed_s: float = 0.0,
        baseline_elapsed_s: float | None = None,
        tokens: float = 0.0,
        gpu_s: float = 0.0,
        human_hours: float = 0.0,
        fp: float = 0.0,
        fn: float = 0.0,
        iter_before: float = 0.0,
        iter_after: float = 0.0,
    ) -> CostLedger:
        """采集一份七维成本账。

        各维定义（开题报告 表3）：
          c_cap  = (baseline_score - gated_score) / baseline_score  （分数越高越好，回退为正）
          c_lat  = elapsed_s / baseline_elapsed_s                    （墙钟时间中位数比）
          c_comp = tokens/1e6 · PRICE_PER_MTOK + gpu_s/3600 · PRICE_PER_GPU_HOUR
          c_hum  = human_hours                                       （每千次修改的工时，调用方归一）
          c_fp   = fp                                                （合法修改被拒比例）
          c_fn   = fn                                                （危险修改被放行比例）
          c_iter = (iter_before - iter_after) / iter_before           （单位时间有效修改次数下降比例）

        分母为 0 或缺省时该维记 0.0（表示「不可测量」，而不是无穷大）。
        """
        # 能力成本
        c_cap = 0.0
        if (
            baseline_score is not None
            and gated_score is not None
            and float(baseline_score) > 0.0
        ):
            c_cap = (float(baseline_score) - float(gated_score)) / float(baseline_score)

        # 时延成本
        c_lat = 0.0
        if baseline_elapsed_s is not None and float(baseline_elapsed_s) > 0.0:
            c_lat = float(elapsed_s) / float(baseline_elapsed_s)

        # 算力成本（折算金额）
        c_comp = (
            float(tokens) / 1e6 * PRICE_PER_MTOK
            + float(gpu_s) / 3600.0 * PRICE_PER_GPU_HOUR
        )

        # 迭代效率损失
        c_iter = 0.0
        if float(iter_before) > 0.0:
            c_iter = (float(iter_before) - float(iter_after)) / float(iter_before)

        return CostLedger(
            c_cap=c_cap,
            c_lat=c_lat,
            c_comp=c_comp,
            c_hum=float(human_hours),
            c_fp=float(fp),
            c_fn=float(fn),
            c_iter=c_iter,
        )

    # -- 合成指标 -------------------------------------------------------
    @staticmethod
    def acer(
        delta_r: float,
        cost: CostLedger,
        weights: dict[str, float] | None = None,
    ) -> float:
        """对齐成本效率比 ACER = ΔR / C_ali（开题报告 式(3)）。

        ΔR 为漏放率的下降幅度；C_ali 为加权合成对齐总成本。
        分母为 0 时返回 0.0（比值无意义，不能除零）。
        """
        denominator = cost.weighted_total(weights)
        if abs(denominator) <= _EPS:
            return 0.0
        return float(delta_r) / denominator

    # -- 帕累托前沿 -----------------------------------------------------
    @staticmethod
    def is_dominated(point: dict[str, Any], others: list[dict[str, Any]]) -> bool:
        """判断 point 是否被 others 中的某点支配。

        支配的定义：存在另一点，其 cost ≤ 本点的 cost 且 risk ≤ 本点的 risk，
        并且至少有一项严格更优。成本与风险都是「越低越好」。
        """
        pc = float(point.get("cost", 0.0))
        pr = float(point.get("risk", 0.0))
        for other in others:
            if other is point:
                continue
            oc = float(other.get("cost", 0.0))
            orisk = float(other.get("risk", 0.0))
            no_worse = oc <= pc + _EPS and orisk <= pr + _EPS
            strictly_better = oc < pc - _EPS or orisk < pr - _EPS
            if no_worse and strictly_better:
                return True
        return False

    @staticmethod
    def pareto_frontier(
        points: list[dict[str, Any]],
        *,
        include_dominated: bool = False,
    ) -> list[dict[str, Any]]:
        """计算成本—风险平面上的帕累托前沿。

        参数 points 形如 [{"name": ..., "cost": ..., "risk": ...}]，成本与风险都是越低越好。
        返回处于非支配集的点的子集；每个返回点都带上 "dominated" 标记（前沿点为 False）。

        include_dominated=True 时返回全部点并逐点标注是否被支配，
        供实验运行器同时展示「前沿点 + 被支配点」（§3.3.2）。
        """
        pts = [dict(p) for p in points]
        for p in pts:
            p["dominated"] = CostCollector.is_dominated(p, pts)
        if include_dominated:
            return pts
        return [p for p in pts if not p["dominated"]]
